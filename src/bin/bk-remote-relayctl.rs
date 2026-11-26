use hbb_common::tokio;
use hbbs::managed_relay_probe::{probe, RelayPublicKey, RelayTarget};
use std::{path::Path, process::ExitCode, time::Instant};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [command, target, key_file] = args.as_slice() else {
        eprintln!("Usage: bk-remote-relayctl probe <relay-address> <public-key-file>");
        return ExitCode::from(2);
    };
    if command != "probe" {
        eprintln!("Only the read-only probe command is implemented");
        return ExitCode::from(2);
    }
    let Some(target) = target.to_str() else {
        eprintln!("Invalid relay address encoding");
        return ExitCode::from(2);
    };
    let (target, key) = match (
        RelayTarget::parse(target),
        RelayPublicKey::from_file(Path::new(key_file)),
    ) {
        (Ok(target), Ok(key)) => (target, key),
        _ => {
            eprintln!("Invalid relay address or public-key file");
            return ExitCode::from(2);
        }
    };
    let started = Instant::now();
    let result = probe(&target, &key).await;
    // The status is a point-in-time observation, not an authenticated server identity.
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
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}
