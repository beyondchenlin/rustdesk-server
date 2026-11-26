//! Explicit, bounded relay protocol checks for the local administrator.
//! This checks relay admission and data forwarding, not cryptographic server identity.

use hbb_common::{
    anyhow::Context,
    bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config::RELAY_PORT,
    futures::future::try_join_all,
    protobuf::Message as _,
    rendezvous_proto::{RendezvousMessage, RequestRelay},
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{lookup_host, TcpStream},
        time::{timeout, Duration},
    },
    tokio_util::codec::Encoder,
    ResultType,
};
use std::{
    collections::BTreeSet,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::Path,
};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayTarget(String);

impl RelayTarget {
    pub fn parse(input: &str) -> ResultType<Self> {
        if input.is_empty() || input.len() > 260 || !input.is_ascii() {
            bail!("Invalid relay address");
        }
        if let Ok(addr) = input.parse::<SocketAddr>() {
            if let SocketAddr::V6(v6) = addr {
                if v6.scope_id() != 0 || v6.flowinfo() != 0 {
                    bail!("Scoped IPv6 relay addresses are not supported");
                }
            }
            return Self::from_ip(addr.ip(), addr.port());
        }
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Self::from_ip(ip, RELAY_PORT as u16);
        }
        let (host, port) = match input.split_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().context("Invalid relay port")?),
            None => (input, RELAY_PORT as u16),
        };
        if port == 0
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        {
            bail!("Invalid relay host or port");
        }
        Ok(Self(format!("{}:{port}", host.to_ascii_lowercase())))
    }

    fn from_ip(ip: IpAddr, port: u16) -> ResultType<Self> {
        if port == 0 || ip.is_unspecified() || ip.is_multicast() {
            bail!("Invalid relay IP or port");
        }
        Ok(Self(SocketAddr::new(ip, port).to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Only a canonical 32-byte public key is accepted. Never accept a private key file.
pub struct RelayPublicKey(String);

impl RelayPublicKey {
    pub fn parse(input: &str) -> ResultType<Self> {
        let key = input.trim();
        if key.len() != 44 {
            bail!("Expected a base64-encoded 32-byte relay public key");
        }
        let bytes = base64::decode(key)
            .map_err(|_| hbb_common::anyhow::anyhow!("Invalid relay public key"))?;
        if bytes.len() != 32 || base64::encode(&bytes) != key {
            bail!("Expected a canonical relay public key");
        }
        Ok(Self(key.to_owned()))
    }

    pub fn from_file(path: &Path) -> ResultType<Self> {
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() > 256 {
            bail!("Expected a small regular relay public key file");
        }
        let mut contents = String::new();
        std::fs::File::open(path)?
            .take(257)
            .read_to_string(&mut contents)?;
        if contents.len() > 256 {
            bail!("Relay public key file is too large");
        }
        Self::parse(&contents)
    }

    fn different_key(&self) -> ResultType<String> {
        let mut bytes = base64::decode(&self.0)?;
        let first = bytes.first_mut().context("Empty relay public key")?;
        *first ^= 1;
        Ok(base64::encode(bytes))
    }
}

async fn send_request(stream: &mut TcpStream, pair_id: &str, key: &str) -> ResultType<()> {
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        uuid: pair_id.to_owned(),
        licence_key: key.to_owned(),
        ..Default::default()
    });
    let mut frame = BytesMut::new();
    BytesCodec::new().encode(Bytes::from(msg.write_to_bytes()?), &mut frame)?;
    stream.write_all(&frame).await?;
    Ok(())
}

async fn verify_forwarding(target: SocketAddr, key: &RelayPublicKey) -> ResultType<()> {
    let pair_id = Uuid::new_v4().simple().to_string();
    let mut first = TcpStream::connect(target).await?;
    let mut second = TcpStream::connect(target).await?;
    send_request(&mut first, &pair_id, &key.0).await?;
    send_request(&mut second, &pair_id, &key.0).await?;

    let marker = Uuid::new_v4();
    let mut received = [0u8; 16];
    first.write_all(marker.as_bytes()).await?;
    second.read_exact(&mut received).await?;
    if &received != marker.as_bytes() {
        bail!("Relay forward probe returned unexpected data");
    }
    let marker = Uuid::new_v4();
    second.write_all(marker.as_bytes()).await?;
    first.read_exact(&mut received).await?;
    if &received != marker.as_bytes() {
        bail!("Relay reverse probe returned unexpected data");
    }
    Ok(())
}

async fn verify_key_rejection(target: SocketAddr, key: &RelayPublicKey) -> ResultType<()> {
    let mut stream = TcpStream::connect(target).await?;
    let pair_id = Uuid::new_v4().simple().to_string();
    send_request(&mut stream, &pair_id, &key.different_key()?).await?;
    // The native relay closes a connection when the admission key is wrong.
    // A silent or unkeyed relay is not considered healthy.
    if stream.read(&mut [0u8; 1]).await? != 0 {
        bail!("Relay did not reject an incorrect admission key");
    }
    Ok(())
}

const MAX_RESOLVED_ENDPOINTS: usize = 8;

fn validated_endpoints(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> ResultType<Vec<SocketAddr>> {
    let mut endpoints = BTreeSet::new();
    for address in addresses {
        if address.ip().is_unspecified() || address.ip().is_multicast() || address.port() == 0 {
            bail!("Relay hostname resolved to an invalid endpoint");
        }
        endpoints.insert(address);
        if endpoints.len() > MAX_RESOLVED_ENDPOINTS {
            bail!("Relay hostname resolved to too many endpoints");
        }
    }
    if endpoints.is_empty() {
        bail!("Relay hostname resolved to no endpoints");
    }
    Ok(endpoints.into_iter().collect())
}

/// A successful probe requires exact bidirectional forwarding and explicit wrong-key rejection.
/// Resolve once and use the same concrete endpoint for all three legs; otherwise
/// DNS rotation can accidentally verify key rejection on a different relay.
/// A multi-address node is healthy only if every bounded, resolved endpoint passes.
/// All connect, DNS, send and receive operations share one total deadline.
pub async fn probe(target: &RelayTarget, key: &RelayPublicKey) -> ResultType<Vec<SocketAddr>> {
    timeout(Duration::from_secs(6), async {
        let endpoints = validated_endpoints(lookup_host(target.as_str()).await?)?;
        try_join_all(endpoints.iter().copied().map(|address| async move {
            verify_forwarding(address, key)
                .await
                .with_context(|| format!("Relay forwarding failed at {address}"))?;
            verify_key_rejection(address, key)
                .await
                .with_context(|| format!("Relay admission-key rejection failed at {address}"))
        }))
        .await?;
        Ok(endpoints)
    })
    .await
    .context("Relay protocol probe timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parser_accepts_only_well_formed_addresses() {
        assert_eq!(
            RelayTarget::parse("RELAY.example").unwrap().as_str(),
            format!("relay.example:{RELAY_PORT}")
        );
        assert_eq!(
            RelayTarget::parse("192.0.2.1:21117").unwrap().as_str(),
            "192.0.2.1:21117"
        );
        assert_eq!(
            RelayTarget::parse("[2001:db8::1]:21117").unwrap().as_str(),
            "[2001:db8::1]:21117"
        );
        for bad in [
            "",
            " relay.example",
            "relay.example\nrs x",
            "a,b",
            "https://relay.example",
            "host:0",
            "host:65536",
            "host:",
            "bad..example",
            "-bad.example",
            "0.0.0.0",
            "[::]:21117",
            "224.0.0.1",
            "999.999.999.999",
            "[fe80::1%2]:21117",
        ] {
            assert!(RelayTarget::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn resolved_endpoints_are_deduplicated_and_bounded() {
        let first: SocketAddr = "192.0.2.1:21117".parse().unwrap();
        let second: SocketAddr = "[2001:db8::1]:21117".parse().unwrap();
        assert_eq!(
            validated_endpoints([first, second, first]).unwrap(),
            vec![first, second]
        );
        assert!(validated_endpoints([]).is_err());
        assert!(validated_endpoints(["0.0.0.0:21117".parse().unwrap()]).is_err());
        let excessive = (1..=9).map(|n| format!("192.0.2.{n}:21117").parse().unwrap());
        assert!(validated_endpoints(excessive).is_err());
    }
    #[test]
    fn public_key_parser_refuses_private_keys_and_malformed_values() {
        assert!(RelayPublicKey::parse(&base64::encode([7u8; 32])).is_ok());
        assert!(RelayPublicKey::parse(&base64::encode([7u8; 64])).is_err());
        assert!(RelayPublicKey::parse("not-a-public-key").is_err());
    }

    #[test]
    fn public_key_file_is_regular_and_bounded() {
        let root = tempfile::tempdir().unwrap();
        assert!(RelayPublicKey::from_file(root.path()).is_err());
        let key = root.path().join("relay.pub");
        std::fs::write(&key, vec![b'x'; 257]).unwrap();
        assert!(RelayPublicKey::from_file(&key).is_err());
        std::fs::write(&key, format!("{}\n", base64::encode([3u8; 32]))).unwrap();
        assert!(RelayPublicKey::from_file(&key).is_ok());
    }
}
