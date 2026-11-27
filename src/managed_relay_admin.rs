//! Managed relay administration over the existing local console only.
//! The token file is an administrator credential, never a relay admission key.

use crate::{
    managed_relay_probe::RelayPublicKey,
    managed_relay_runtime::ManagedRelayRuntime,
    managed_relay_store::{validate_actor, RelayPoolStore},
};
use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::Mutex,
        time::{timeout, Duration},
    },
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
};

pub const PREFIX: &[u8] = b"BKREL1 ";
const MAX_REQUEST: usize = 8192;
const MAX_REPLY: usize = 256 * 1024;

use sodiumoxide::crypto::auth::hmacsha256::{authenticate, verify, Key, Tag};

pub struct AdminToken(Key);

impl AdminToken {
    pub fn create(path: &Path) -> ResultType<()> {
        sodiumoxide::init().map_err(|_| anyhow!("Secure random initialization failed"))?;
        let mut bytes = [0u8; 32];
        sodiumoxide::randombytes::randombytes_into(&mut bytes);
        let token = base64::encode(bytes);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(token.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    pub fn read(path: &Path) -> ResultType<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() > 128 {
            bail!("Expected a small regular administrator token file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 {
                bail!("Administrator token file must not be accessible to group or others");
            }
        }
        let mut value = String::new();
        std::fs::File::open(path)?
            .take(129)
            .read_to_string(&mut value)?;
        let key = value.trim();
        if key.len() != 44 {
            bail!("Invalid administrator token file");
        }
        let decoded =
            base64::decode(key).map_err(|_| anyhow!("Invalid administrator token file"))?;
        if decoded.len() != 32 || base64::encode(&decoded) != key {
            bail!("Invalid administrator token file");
        }
        sodiumoxide::init().map_err(|_| anyhow!("Secure crypto initialization failed"))?;
        let key = Key::from_slice(&decoded).context("Invalid administrator token file")?;
        Ok(Self(key))
    }

    fn mac_input(domain: &[u8], challenge: &[u8; 32], body: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(domain.len() + 1 + challenge.len() + body.len());
        input.extend_from_slice(domain);
        input.push(0);
        input.extend_from_slice(challenge);
        input.extend_from_slice(body);
        input
    }

    fn sign(&self, domain: &[u8], challenge: &[u8; 32], body: &[u8]) -> String {
        base64::encode(authenticate(&Self::mac_input(domain, challenge, body), &self.0).0)
    }

    fn verify(&self, domain: &[u8], challenge: &[u8; 32], body: &[u8], proof: &str) -> bool {
        if proof.len() != 44 {
            return false;
        }
        base64::decode(proof)
            .ok()
            .and_then(|bytes| Tag::from_slice(&bytes))
            .is_some_and(|tag| verify(&tag, &Self::mac_input(domain, challenge, body), &self.0))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminCommand {
    Status,
    Publish { expected: i64, nodes: Vec<String> },
    Rollback { expected: i64 },
    Recover,
    Refresh,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    actor: String,
    command: AdminCommand,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    challenge: String,
    proof: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBody {
    body: String,
    proof: String,
}

const CHALLENGE_DOMAIN: &[u8] = b"BKREL1-server";
const REQUEST_DOMAIN: &[u8] = b"BKREL1-request";
const REPLY_DOMAIN: &[u8] = b"BKREL1-reply";

pub struct ManagedRelayAdmin {
    pub runtime: ManagedRelayRuntime,
    token: AdminToken,
    request: Mutex<()>,
}

impl ManagedRelayAdmin {
    pub async fn open(pool: &Path, token: &Path, key: RelayPublicKey) -> ResultType<Self> {
        let token = AdminToken::read(token)?;
        if key.equals_key_bytes(&token.0 .0) {
            bail!("Administrator token must differ from the public relay admission key");
        }
        let store = RelayPoolStore::open(pool).await?;
        let runtime = ManagedRelayRuntime::open(store, key).await?;
        Ok(Self {
            runtime,
            token,
            request: Mutex::new(()),
        })
    }

    async fn execute(&self, payload: &[u8]) -> ResultType<Value> {
        let request: Request = serde_json::from_slice(payload)
            .map_err(|_| anyhow!("Invalid managed relay request"))?;
        validate_actor(&request.actor)?;
        let _guard = self
            .request
            .try_lock()
            .map_err(|_| anyhow!("Relay administrator busy"))?;
        match request.command {
            AdminCommand::Status => {}
            AdminCommand::Publish { expected, nodes } => {
                self.runtime
                    .publish(expected, &nodes, &request.actor)
                    .await?;
            }
            AdminCommand::Rollback { expected } => {
                self.runtime.rollback(expected, &request.actor).await?;
            }
            AdminCommand::Recover => self.runtime.recover(&request.actor).await?,
            AdminCommand::Refresh => self.runtime.refresh().await?,
        }
        let (journal, runtime) = self.runtime.status().await?;
        Ok(json!({"journal": journal, "runtime": runtime}))
    }

    /// The native console reads the first bytes. A partial prefix must not
    /// accidentally become a legacy command. Only one newline-terminated,
    /// bounded managed frame is accepted per connection.
    pub fn is_managed_prefix(bytes: &[u8]) -> bool {
        !bytes.is_empty() && (bytes.starts_with(PREFIX) || PREFIX.starts_with(bytes))
    }

    pub async fn serve(&self, mut stream: TcpStream, first: &[u8]) -> ResultType<()> {
        let peer = stream.peer_addr()?;
        if !hbb_common::try_into_v4(peer).ip().is_loopback() {
            bail!("Managed relay console is local only");
        }
        let hello = timeout(Duration::from_secs(2), read_frame(&mut stream, first)).await??;
        if hello != b"challenge" {
            bail!("Managed relay challenge required");
        }
        let mut challenge = [0u8; 32];
        sodiumoxide::randombytes::randombytes_into(&mut challenge);
        let hello = Challenge {
            challenge: base64::encode(challenge),
            proof: self.token.sign(CHALLENGE_DOMAIN, &challenge, b""),
        };
        write_frame(&mut stream, &serde_json::to_vec(&hello)?, MAX_REQUEST).await?;
        let result = async {
            let bytes = timeout(Duration::from_secs(2), read_frame(&mut stream, &[])).await??;
            let signed: SignedBody = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow!("Invalid signed administrator request"))?;
            if !self.token.verify(
                REQUEST_DOMAIN,
                &challenge,
                signed.body.as_bytes(),
                &signed.proof,
            ) {
                bail!("Administrator authentication failed");
            }
            self.execute(signed.body.as_bytes()).await
        }
        .await;
        let reply = match result {
            Ok(data) => json!({"ok": true, "data": data}),
            Err(error) => json!({"ok": false, "error": format!("{error:#}")}),
        };
        let body = serde_json::to_string(&reply)?;
        let signed = SignedBody {
            proof: self.token.sign(REPLY_DOMAIN, &challenge, body.as_bytes()),
            body,
        };
        write_frame(&mut stream, &serde_json::to_vec(&signed)?, MAX_REPLY).await?;
        Ok(())
    }
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8], max: usize) -> ResultType<()> {
    if PREFIX.len() + payload.len() + 1 > max || payload.contains(&b'\n') {
        bail!("Managed relay frame exceeded bound or contains a delimiter");
    }
    let mut frame = Vec::with_capacity(PREFIX.len() + payload.len() + 1);
    frame.extend_from_slice(PREFIX);
    frame.extend_from_slice(payload);
    frame.push(b'\n');
    timeout(Duration::from_secs(2), stream.write_all(&frame)).await??;
    Ok(())
}

async fn read_bounded_frame(
    stream: &mut TcpStream,
    first: &[u8],
    max: usize,
) -> ResultType<Vec<u8>> {
    let mut bytes = first.to_vec();
    loop {
        if bytes.len() > max {
            bail!("Managed relay request exceeded bound");
        }
        if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
            if end + 1 != bytes.len() || !bytes.starts_with(PREFIX) {
                bail!("Invalid managed relay framing");
            }
            return Ok(bytes[PREFIX.len()..end].to_vec());
        }
        let mut buffer = [0u8; 1024];
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            bail!("Incomplete managed relay request");
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

async fn read_frame(stream: &mut TcpStream, first: &[u8]) -> ResultType<Vec<u8>> {
    read_bounded_frame(stream, first, MAX_REQUEST).await
}

pub async fn request_local(
    port: u16,
    token: &AdminToken,
    actor: &str,
    command: AdminCommand,
) -> ResultType<Value> {
    if port == 0 {
        bail!("Invalid local console port");
    }
    validate_actor(actor)?;
    let body = serde_json::to_string(&Request {
        actor: actor.to_owned(),
        command,
    })?;
    let reply = timeout(Duration::from_secs(120), async {
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        let mut stream = TcpStream::connect(address).await?;
        write_frame(&mut stream, b"challenge", MAX_REQUEST).await?;
        let bytes = timeout(Duration::from_secs(2), read_frame(&mut stream, &[])).await??;
        let hello: Challenge = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("Invalid local relay server challenge"))?;
        let challenge: [u8; 32] = base64::decode(&hello.challenge)
            .map_err(|_| anyhow!("Invalid local relay server challenge"))?
            .try_into()
            .map_err(|_| anyhow!("Invalid local relay server challenge"))?;
        if !token.verify(CHALLENGE_DOMAIN, &challenge, b"", &hello.proof) {
            bail!("Local relay server authentication failed");
        }
        let signed = SignedBody {
            proof: token.sign(REQUEST_DOMAIN, &challenge, body.as_bytes()),
            body,
        };
        write_frame(&mut stream, &serde_json::to_vec(&signed)?, MAX_REQUEST).await?;
        let bytes = read_bounded_frame(&mut stream, &[], MAX_REPLY).await?;
        let signed: SignedBody = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("Invalid signed administrator reply"))?;
        if !token.verify(
            REPLY_DOMAIN,
            &challenge,
            signed.body.as_bytes(),
            &signed.proof,
        ) {
            bail!("Local relay administrator reply authentication failed");
        }
        serde_json::from_str::<Value>(&signed.body)
            .context("Invalid local relay administrator reply")
    })
    .await
    .context("Local relay administrator request timed out; inspect status before retrying")??;
    if reply["ok"] != true && reply["ok"] != false {
        bail!("Invalid local relay administrator status");
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    #[test]
    fn token_file_is_created_once_and_authenticated() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("admin.token");
        AdminToken::create(&path).unwrap();
        let first = AdminToken::read(&path).unwrap();
        let challenge = [7u8; 32];
        let proof = first.sign(REQUEST_DOMAIN, &challenge, b"status");
        assert!(first.verify(REQUEST_DOMAIN, &challenge, b"status", &proof));
        assert!(!first.verify(REQUEST_DOMAIN, &[8u8; 32], b"status", &proof));
        assert!(!first.verify(REQUEST_DOMAIN, &challenge, b"publish", &proof));
        assert!(!first.verify(REPLY_DOMAIN, &challenge, b"status", &proof));
        assert!(AdminToken::create(&path).is_err());
        assert!(AdminToken::read(&path).unwrap().verify(
            REQUEST_DOMAIN,
            &challenge,
            b"status",
            &proof
        ));
    }

    #[hbb_common::tokio::test]
    async fn public_relay_key_cannot_be_reused_as_admin_token() {
        let tmp = tempfile::tempdir().unwrap();
        let token = tmp.path().join("admin.token");
        AdminToken::create(&token).unwrap();
        let key = RelayPublicKey::from_file(&token).unwrap();
        let result = ManagedRelayAdmin::open(&tmp.path().join("pool.sqlite3"), &token, key).await;
        match result {
            Err(error) => assert!(error.to_string().contains("must differ")),
            Ok(_) => panic!("public relay key was accepted as administrator token"),
        }
    }

    #[test]
    fn managed_prefix_does_not_reinterpret_legacy_commands() {
        assert!(ManagedRelayAdmin::is_managed_prefix(b"BK"));
        assert!(ManagedRelayAdmin::is_managed_prefix(PREFIX));
        assert!(ManagedRelayAdmin::is_managed_prefix(b"BKREL1 {}"));
        assert!(!ManagedRelayAdmin::is_managed_prefix(b"rs node.example"));
        assert!(!ManagedRelayAdmin::is_managed_prefix(b""));
    }
}
