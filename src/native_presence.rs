use hbb_common::{bail, rendezvous_proto::OnlineRequest, ResultType};
use sodiumoxide::crypto::sign;
use std::collections::HashSet;

pub(crate) const REQUEST_PREFIX: &str = "bk-presence-v1:";
pub(crate) const RESPONSE_MAGIC: &[u8; 5] = b"BKRP1";
pub(crate) const SIGNATURE_DOMAIN: &[u8] = b"BK Remote native registration v1\n";
pub(crate) const MAX_PEERS: usize = 200;
pub(crate) const MAX_ID_BYTES: usize = 253;
pub(crate) const MAX_TOTAL_ID_BYTES: usize = 16 * 1024;
pub(crate) const MAX_REQUEST_BYTES: usize = 24 * 1024;

pub(crate) struct NativePresenceQuery<'a> {
    pub peers: &'a [String],
    nonce: [u8; 32],
}

impl<'a> NativePresenceQuery<'a> {
    pub fn parse(request: &'a OnlineRequest) -> ResultType<Self> {
        let hex = request.id.strip_prefix(REQUEST_PREFIX)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("Unsupported native registration query"))?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            bail!("Invalid native registration challenge");
        }
        validate_peers(&request.peers)?;
        let mut nonce = [0u8; 32];
        for (index, value) in nonce.iter_mut().enumerate() {
            *value = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Self { peers: &request.peers, nonce })
    }

    pub fn signed_response(&self, states: &[u8], key: &sign::SecretKey) -> ResultType<Vec<u8>> {
        validate_bitmap(states, self.peers.len())?;
        let count = (self.peers.len() as u16).to_be_bytes();
        let signature = sign::sign_detached(&self.transcript(states), key);
        let mut response = Vec::with_capacity(5 + 32 + 2 + states.len() + 64);
        response.extend_from_slice(RESPONSE_MAGIC);
        response.extend_from_slice(&self.nonce);
        response.extend_from_slice(&count);
        response.extend_from_slice(states);
        response.extend_from_slice(&signature.to_bytes());
        Ok(response)
    }

    fn transcript(&self, states: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 34 + self.peers.iter().map(|id| id.len() + 2).sum::<usize>() + states.len());
        payload.extend_from_slice(SIGNATURE_DOMAIN);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&(self.peers.len() as u16).to_be_bytes());
        for id in self.peers {
            payload.extend_from_slice(&(id.len() as u16).to_be_bytes());
            payload.extend_from_slice(id.as_bytes());
        }
        payload.extend_from_slice(states);
        payload
    }
}

fn validate_peers(peers: &[String]) -> ResultType<()> {
    if peers.is_empty() || peers.len() > MAX_PEERS {
        bail!("Invalid native registration query size");
    }
    let mut total = 0usize;
    let mut seen = HashSet::with_capacity(peers.len());
    for id in peers {
        if id.is_empty() || id.len() > MAX_ID_BYTES
            || !id.as_bytes()[0].is_ascii_alphanumeric()
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
            || !seen.insert(id.as_str())
        {
            bail!("Invalid or duplicate native device identifier");
        }
        total = total.saturating_add(id.len());
        if total > MAX_TOTAL_ID_BYTES {
            bail!("Native registration identifiers exceed the byte limit");
        }
    }
    Ok(())
}

fn validate_bitmap(states: &[u8], count: usize) -> ResultType<()> {
    if states.len() != count.div_ceil(8) {
        bail!("Invalid native registration bitmap length");
    }
    let used = count % 8;
    if used != 0 && states.last().is_some_and(|last| last & ((1u8 << (8 - used)) - 1) != 0) {
        bail!("Invalid native registration bitmap padding");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(peers: Vec<String>) -> OnlineRequest {
        OnlineRequest { id: format!("{REQUEST_PREFIX}{}", "00".repeat(32)), peers, ..Default::default() }
    }

    #[test]
    fn rejects_unbounded_ambiguous_or_malformed_queries() {
        let mut invalid = vec![vec![], vec!["101".into(), "101".into()], vec!["bad\nidentifier".into()], vec!["../id".into()], vec!["x".repeat(254)], (0..201).map(|n| n.to_string()).collect()];
        invalid.push((0..70).map(|n| format!("{n:03}{}", "x".repeat(250))).collect());
        for peers in invalid {
            assert!(NativePresenceQuery::parse(&request(peers)).is_err());
        }
        let valid = request((0..200).map(|n| n.to_string()).collect());
        assert!(NativePresenceQuery::parse(&valid).is_ok());
        for challenge in ["00".repeat(31), "AA".repeat(32), "gg".repeat(32)] {
            let mut invalid = request(vec!["101".into()]);
            invalid.id = format!("{REQUEST_PREFIX}{challenge}");
            assert!(NativePresenceQuery::parse(&invalid).is_err());
        }
    }

    #[test]
    fn response_signature_binds_challenge_order_count_and_original_bit_order() {
        sodiumoxide::init().unwrap();
        let (public, secret) = sign::keypair_from_seed(&sign::Seed([7; 32]));
        let mut request = request(vec!["101".into(), "202".into(), "303".into()]);
        request.id = format!("{REQUEST_PREFIX}{}", (0..32).map(|v| format!("{v:02x}")).collect::<String>());
        let query = NativePresenceQuery::parse(&request).unwrap();
        let response = query.signed_response(&[0xa0], &secret).unwrap();
        assert_eq!(&response[..5], b"BKRP1");
        assert_eq!(&response[5..37], &(0u8..32).collect::<Vec<_>>());
        assert_eq!(&response[37..40], &[0, 3, 0xa0]);
        assert_eq!(response.len(), 104);
        let signature = sign::Signature::from_bytes(&response[40..]).unwrap();
        assert!(sign::verify_detached(&signature, &query.transcript(&[0xa0]), &public));
        assert!(!sign::verify_detached(&signature, &query.transcript(&[0x80]), &public));
        assert!(query.signed_response(&[0xa1], &secret).is_err());
        assert!(query.signed_response(&[0xa0, 0], &secret).is_err());
        request.peers.swap(0, 1);
        assert!(!sign::verify_detached(&signature, &NativePresenceQuery::parse(&request).unwrap().transcript(&[0xa0]), &public));
    }
}
