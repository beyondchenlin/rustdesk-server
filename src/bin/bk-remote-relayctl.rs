use hbb_common::{
    anyhow::{anyhow, Context},
    tokio, ResultType,
};
use hbbs::{
    managed_relay_admin::{request_local, AdminCommand, AdminToken},
    managed_relay_probe::{probe, RelayPublicKey, RelayTarget},
    managed_relay_store::RelayPoolStore,
};
use std::{ffi::OsString, path::Path, process::ExitCode, time::Instant};

const USAGE: &str = "Usage:
  bk-remote-relayctl probe <relay-address> <public-key-file>
  bk-remote-relayctl init-config <new-journal-file> <comma-separated-nodes>
  bk-remote-relayctl init-token <new-admin-token-file>
  bk-remote-relayctl config-status <journal-file>
  bk-remote-relayctl admin <local-console-port> <token-file> status
  bk-remote-relayctl admin <local-console-port> <token-file> publish <expected-revision> <comma-separated-nodes>
  bk-remote-relayctl admin <local-console-port> <token-file> rollback <expected-revision>
  bk-remote-relayctl admin <local-console-port> <token-file> recover
  bk-remote-relayctl admin <local-console-port> <token-file> refresh";

fn as_text(value: &OsString) -> ResultType<&str> {
    value.to_str().context("Invalid command argument encoding")
}

fn nodes(value: &OsString) -> ResultType<Vec<String>> {
    Ok(as_text(value)?.split(',').map(str::to_owned).collect())
}

async fn run(args: &[OsString]) -> ResultType<ExitCode> {
    match args {
        [command, target, key_file] if command == "probe" => {
            let target = RelayTarget::parse(as_text(target)?)?;
            let key = RelayPublicKey::from_file(Path::new(key_file))?;
            let started = Instant::now();
            let result = probe(&target, &key).await;
            println!(
                "{}",
                serde_json::json!({
                    "endpoint": target.as_str(),
                    "checked_at": chrono::Utc::now().to_rfc3339(),
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                    "status": if result.is_ok() { "healthy" } else { "unhealthy" },
                    "resolved_endpoints": result.as_ref().ok().map(|addresses| addresses.iter().map(ToString::to_string).collect::<Vec<_>>()),
                    "check": "relay_forwarding_and_admission_key_rejection",
                    "reason": result.as_ref().err().map(|err| format!("{err:#}"))
                })
            );
            Ok(if result.is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        [command, path, configured] if command == "init-config" => {
            let store = RelayPoolStore::initialize(
                Path::new(path),
                &nodes(configured)?,
                &whoami::username(),
            )
            .await?;
            println!(
                "{}",
                serde_json::json!({
                    "journal": store.snapshot().await?,
                    "runtime": "not_checked"
                })
            );
            Ok(ExitCode::SUCCESS)
        }
        [command, path] if command == "init-token" => {
            AdminToken::create(Path::new(path))?;
            println!("Administrator token file created; protect its filesystem permissions.");
            Ok(ExitCode::SUCCESS)
        }
        [command, path] if command == "config-status" => {
            let store = RelayPoolStore::open(Path::new(path)).await?;
            println!(
                "{}",
                serde_json::json!({
                    "journal": store.snapshot().await?,
                    "runtime": "not_checked",
                    "recent_probes": store.recent_probes(10).await?
                })
            );
            Ok(ExitCode::SUCCESS)
        }
        [command, port, token_file, rest @ ..] if command == "admin" => {
            let port: u16 = as_text(port)?
                .parse()
                .context("Invalid local console port")?;
            let token = AdminToken::read(Path::new(token_file))?;
            let command = match rest {
                [op] if op == "status" => AdminCommand::Status,
                [op, revision, configured] if op == "publish" => AdminCommand::Publish {
                    expected: as_text(revision)?
                        .parse()
                        .context("Invalid expected revision")?,
                    nodes: nodes(configured)?,
                },
                [op, revision] if op == "rollback" => AdminCommand::Rollback {
                    expected: as_text(revision)?
                        .parse()
                        .context("Invalid expected revision")?,
                },
                [op] if op == "recover" => AdminCommand::Recover,
                [op] if op == "refresh" => AdminCommand::Refresh,
                _ => return Err(anyhow!(USAGE)),
            };
            let result = match request_local(port, &token, &whoami::username(), command).await {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("{error:#}");
                    return Ok(ExitCode::from(1));
                }
            };
            println!("{result}");
            Ok(if result["ok"] == true {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        _ => Err(anyhow!(USAGE)),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match run(&args).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::from(2)
        }
    }
}
