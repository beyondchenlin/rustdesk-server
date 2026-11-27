#!/usr/bin/env bash
set -Eeuo pipefail
TOOLS=/mnt/d/demo2/bk-remote-toolchains
REPO=/mnt/d/demo2/rustdesk-server
EVIDENCE="$TOOLS/logs/relay-g4-review-20261127"
mkdir -p "$EVIDENCE"
export RUSTUP_HOME="$TOOLS/rustup-home"
export CARGO_HOME="$TOOLS/cargo-home"
export RUSTUP_TOOLCHAIN=1.98.1
export PATH="$TOOLS/wsl-build-env/bin:$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR=/home/ai/bk-remote-build/server-g4-target
export CARGO_BUILD_JOBS=4
export CC=x86_64-conda-linux-gnu-cc
export CXX=x86_64-conda-linux-gnu-c++
export AR=x86_64-conda-linux-gnu-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-conda-linux-gnu-cc
export PKG_CONFIG_PATH="$TOOLS/wsl-build-env/lib/pkgconfig"
export LD_LIBRARY_PATH="$TOOLS/wsl-build-env/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CARGO_HTTP_MULTIPLEXING=false
export CARGO_NET_RETRY=3
export CARGO_HTTP_TIMEOUT=90
cd "$REPO"
phase="${1:?phase required}"
case "$phase" in
red)
 set +e
 cargo test --locked --lib client_rejects_replayed_server_challenge_and_reply -- --nocapture > "$EVIDENCE/admin-replay-red.log" 2>&1
 result=$?
 printf '%s\n' "$result" > "$EVIDENCE/admin-replay-red.exit"
 tail -40 "$EVIDENCE/admin-replay-red.log"
 exit "$result"
 ;;
green)
 trap 'result=$?; printf "%s\n" "$result" > "$EVIDENCE/green.exit"' EXIT
 export XDG_CONFIG_HOME=/home/ai/bk-remote-build/server-g4-test-config
 export RUST_TEST_THREADS=4
 sha256sum Cargo.lock db_v2.sqlite3 > "$EVIDENCE/preserved-inputs.sha256"
 cargo test --locked --workspace > "$EVIDENCE/regression.log" 2>&1
 cargo build --locked --bins > "$EVIDENCE/build.log" 2>&1
 sha256sum -c "$EVIDENCE/preserved-inputs.sha256" > "$EVIDENCE/preserved-inputs-verified.log"
 tail -35 "$EVIDENCE/regression.log"
 ;;
e2e)
 trap 'result=$?; printf "%s\n" "$result" > "$EVIDENCE/e2e.exit"' EXIT
 run_path="/home/ai/bk-remote-build/relay-g4-e2e-$(date +%Y%m%d-%H%M%S)"
 printf '%s\n' "$run_path" > "$EVIDENCE/e2e-path.txt"
 python3 scripts/bk-remote/test-managed-relay-linux.py --bin-root "$CARGO_TARGET_DIR/debug" --evidence-root "$run_path" --repo-root "$REPO" > "$EVIDENCE/e2e.log" 2>&1
 cp "$run_path/result.json" "$EVIDENCE/e2e-result.json"
 cat "$EVIDENCE/e2e.log"
 ;;
*) exit 2;;
esac
