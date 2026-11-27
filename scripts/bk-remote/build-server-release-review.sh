#!/usr/bin/env bash
# Build the reviewed server sources and exercise the exact copied release candidates.
set -Eeuo pipefail
TOOLS=/mnt/d/demo2/bk-remote-toolchains
REPO=/mnt/d/demo2/rustdesk-server
TAG="$(date +%Y%m%d-%H%M%S)"
EVIDENCE="$TOOLS/logs/relay-g4-release-$TAG"
OUTPUT="$EVIDENCE/bin-linux-x86_64"
mkdir "$EVIDENCE"
mkdir "$OUTPUT"
printf '%s\n' "$EVIDENCE" > "$TOOLS/logs/relay-g4-review-20261127/release-path.txt"
exec > "$EVIDENCE/driver.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$EVIDENCE/exit-code.txt"; date --iso-8601=seconds > "$EVIDENCE/finished-at.txt"' EXIT
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
date --iso-8601=seconds > "$EVIDENCE/started-at.txt"
git rev-parse HEAD > "$EVIDENCE/source-head.txt"
git status --porcelain=v1 > "$EVIDENCE/source-status.txt"
git diff --binary -- src Cargo.toml Cargo.lock build.rs > "$EVIDENCE/reviewed-source.patch"
git diff --check > "$EVIDENCE/diff-check.txt"
rustc --version --verbose > "$EVIDENCE/rustc-version.txt"
cargo --version > "$EVIDENCE/cargo-version.txt"
sha256sum Cargo.lock db_v2.sqlite3 > "$EVIDENCE/preserved-inputs.sha256"
python3 - "$REPO" "$EVIDENCE" "$TOOLS/logs/relay-g4-review-20261127/review-manifest.json" <<'PY'
import hashlib, json, pathlib, subprocess, sys
repo, evidence, reviewed = map(pathlib.Path, sys.argv[1:])
review = json.loads(reviewed.read_text(encoding='utf-8-sig'))
for entry in review['files']:
    path = repo / entry['path'].replace('\\', '/')
    if path.suffix == '.rs' or path.name in ('Cargo.lock', 'db_v2.sqlite3'):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'].lower(), str(path)
files = subprocess.check_output(['git', 'ls-files', '--recurse-submodules', '-z'], cwd=repo).split(b'\0')
files += subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z'], cwd=repo).split(b'\0')
lines = []
for raw in sorted(set(files)):
    if not raw: continue
    relative = raw.decode('utf-8')
    path = repo / relative
    if path.is_file():
        lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}')
(evidence / 'source-before.sha256').write_text('\n'.join(lines) + '\n', encoding='utf-8')
(evidence / 'source-count.txt').write_text(str(len(lines)) + '\n', encoding='utf-8')
print('REVIEWED_SOURCE_HASHES_MATCH')
PY
printf 'PHASE=release-build JOBS=4 LOCKED=true\n'
set +e
cargo build --locked --release --bins > "$EVIDENCE/build.log" 2>&1
build_result=$?
set -e
printf '%s\n' "$build_result" > "$EVIDENCE/build-exit-code.txt"
if ((build_result != 0)); then exit "$build_result"; fi
sha256sum -c "$EVIDENCE/source-before.sha256" > "$EVIDENCE/source-after-verified.log"
sha256sum -c "$EVIDENCE/preserved-inputs.sha256" > "$EVIDENCE/preserved-inputs-verified.log"
cp src/version.rs "$EVIDENCE/generated-version.rs"
for binary in hbbs hbbr rustdesk-utils bk-remote-relayctl; do
    test -x "$CARGO_TARGET_DIR/release/$binary"
    cp "$CARGO_TARGET_DIR/release/$binary" "$OUTPUT/$binary"
    chmod 755 "$OUTPUT/$binary"
done
(cd "$OUTPUT" && sha256sum hbbs hbbr rustdesk-utils bk-remote-relayctl) > "$EVIDENCE/binaries.sha256"
file "$OUTPUT"/* > "$EVIDENCE/binaries-file.txt"
for binary in hbbs hbbr rustdesk-utils bk-remote-relayctl; do
    printf '\nBINARY=%s\n' "$binary"
    readelf -h "$OUTPUT/$binary"
    env -u LD_LIBRARY_PATH ldd "$OUTPUT/$binary"
done > "$EVIDENCE/binaries-elf-and-runtime.txt"
if grep -q 'not found' "$EVIDENCE/binaries-elf-and-runtime.txt"; then
    printf 'Release candidate has an unresolved runtime dependency\n'
    exit 1
fi
printf 'PHASE=release-native-protocol-check\n'
run_path="/home/ai/bk-remote-build/relay-g4-release-e2e-$TAG"
printf '%s\n' "$run_path" > "$EVIDENCE/e2e-path.txt"
set +e
python3 scripts/bk-remote/test-managed-relay-linux.py --bin-root "$OUTPUT" --evidence-root "$run_path" --repo-root "$REPO" > "$EVIDENCE/e2e.log" 2>&1
e2e_result=$?
set -e
printf '%s\n' "$e2e_result" > "$EVIDENCE/e2e-exit-code.txt"
if [[ -f "$run_path/result.json" ]]; then cp "$run_path/result.json" "$EVIDENCE/e2e-result.json"; fi
(cd "$OUTPUT" && sha256sum -c "$EVIDENCE/binaries.sha256") > "$EVIDENCE/tested-binaries-verified.log"
sha256sum -c "$EVIDENCE/preserved-inputs.sha256" > "$EVIDENCE/final-preserved-inputs-verified.log"
cat "$EVIDENCE/e2e.log"
exit "$e2e_result"
