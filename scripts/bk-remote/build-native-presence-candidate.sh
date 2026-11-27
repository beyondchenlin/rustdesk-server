#!/usr/bin/env bash
set -Eeuo pipefail
TOOLS=/mnt/d/demo2/bk-remote-toolchains
REPO=/mnt/d/demo2/rustdesk-server
TAG="$(date +%Y%m%d-%H%M%S)"
EVIDENCE="$TOOLS/logs/native-presence-release-$TAG"
OUTPUT="$EVIDENCE/bin-linux-x86_64"
mkdir "$EVIDENCE"
mkdir "$OUTPUT"
printf '%s\n' "$EVIDENCE" > "$TOOLS/current-server-presence-release.txt"
exec > "$EVIDENCE/driver.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$EVIDENCE/exit-code.txt"; date --iso-8601=seconds > "$EVIDENCE/finished-at.txt"' EXIT
export RUSTUP_HOME="$TOOLS/rustup-home"
export CARGO_HOME="$TOOLS/cargo-home"
export RUSTUP_TOOLCHAIN=1.98.1
export PATH="$TOOLS/wsl-build-env/bin:$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR=/home/ai/bk-remote-build/server-g4-target
export CARGO_BUILD_JOBS=4
export PYTHONDONTWRITEBYTECODE=1
export CC=x86_64-conda-linux-gnu-cc
export CXX=x86_64-conda-linux-gnu-c++
export AR=x86_64-conda-linux-gnu-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-conda-linux-gnu-cc
export PKG_CONFIG_PATH="$TOOLS/wsl-build-env/lib/pkgconfig"
export LD_LIBRARY_PATH="$TOOLS/wsl-build-env/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$REPO"
date --iso-8601=seconds > "$EVIDENCE/started-at.txt"
git rev-parse HEAD > "$EVIDENCE/source-head.txt"
git status --porcelain=v1 > "$EVIDENCE/source-status.txt"
git diff --binary -- src Cargo.toml Cargo.lock build.rs > "$EVIDENCE/source.patch"
git diff --check > "$EVIDENCE/diff-check.txt"
sha256sum Cargo.lock db_v2.sqlite3 > "$EVIDENCE/preserved-inputs.sha256"
python3 - "$REPO" "$EVIDENCE" <<'PY'
import hashlib, pathlib, subprocess, sys
repo, out = map(pathlib.Path, sys.argv[1:])
files = subprocess.check_output(['git', 'ls-files', '--recurse-submodules', '-z'], cwd=repo).split(b'\0')
files += subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z'], cwd=repo).split(b'\0')
lines = []
for raw in sorted(set(files)):
    if not raw: continue
    path = repo / raw.decode()
    if path.is_file():
        lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {raw.decode()}')
(out / 'source-before.sha256').write_text('\n'.join(lines) + '\n')
(out / 'source-count.txt').write_text(str(len(lines)) + '\n')
PY
printf 'PHASE=locked-release-build JOBS=4\n'
set +e
cargo build --locked --release --bins > "$EVIDENCE/build.log" 2>&1
build_code=$?
set -e
printf '%s\n' "$build_code" > "$EVIDENCE/build-exit-code.txt"
if ((build_code != 0)); then exit "$build_code"; fi
sha256sum -c "$EVIDENCE/source-before.sha256" > "$EVIDENCE/source-after-build.log"
sha256sum -c "$EVIDENCE/preserved-inputs.sha256" > "$EVIDENCE/preserved-after-build.log"
for binary in hbbs hbbr rustdesk-utils bk-remote-relayctl; do
    cp "$CARGO_TARGET_DIR/release/$binary" "$OUTPUT/$binary"
    chmod 755 "$OUTPUT/$binary"
done
(cd "$OUTPUT" && sha256sum hbbs hbbr rustdesk-utils bk-remote-relayctl) > "$EVIDENCE/binaries.sha256"
python3 - "$OUTPUT" "$EVIDENCE" <<'PY'
import json, os, pathlib, re, subprocess, sys
output, evidence = map(pathlib.Path, sys.argv[1:])
runtime = {}
environment = dict(os.environ)
environment.pop('LD_LIBRARY_PATH', None)
for name in ('hbbs', 'hbbr', 'rustdesk-utils', 'bk-remote-relayctl'):
    binary = output / name
    header = subprocess.check_output(['readelf', '-h', str(binary)], text=True)
    dynamic = subprocess.check_output(['readelf', '-d', str(binary)], text=True)
    versions = subprocess.check_output(['readelf', '--version-info', str(binary)], text=True)
    libraries = subprocess.check_output(['ldd', str(binary)], text=True, env=environment)
    assert 'not found' not in libraries
    system = subprocess.check_output(['/lib64/ld-linux-x86-64.so.2', '--library-path',
                                      '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu',
                                      '--list', str(binary)], text=True, env=environment)
    required = sorted(set(re.findall(r'Name: (GLIBC_[0-9.]+)', versions)),
                      key=lambda x: tuple(map(int, x[6:].split('.'))))
    runtime[name] = {
        'minimum_glibc': required[-1] if required else None,
        'architecture': 'ELF64 x86-64',
        'needed': re.findall(r'\(NEEDED\).*\[(.*?)\]', dynamic),
        'runpath': re.findall(r'\(RUNPATH\).*\[(.*?)\]', dynamic),
        'runtime_resolution': libraries, 'system_resolution': system,
        'production_compatibility_verified': False,
    }
    (evidence / (name + '-runtime.txt')).write_text(header + dynamic + versions + libraries + system)
(evidence / 'runtime-requirements.json').write_text(json.dumps(runtime, indent=2) + '\n')
PY
printf 'PHASE=original-relay-protocol-checks\n'
relay_run="/home/ai/bk-remote-build/native-presence-relay-e2e-$TAG"
set +e
python3 scripts/bk-remote/test-managed-relay-linux.py --bin-root "$OUTPUT" --evidence-root "$relay_run" --repo-root "$REPO" > "$EVIDENCE/relay-e2e.log" 2>&1
relay_code=$?
set -e
printf '%s\n' "$relay_code" > "$EVIDENCE/relay-e2e-exit-code.txt"
if [[ -f "$relay_run/result.json" ]]; then cp "$relay_run/result.json" "$EVIDENCE/relay-e2e-result.json"; fi
printf 'PHASE=signed-native-presence-protocol-checks\n'
presence_run="/home/ai/bk-remote-build/native-presence-e2e-$TAG"
set +e
python3 scripts/bk-remote/test-native-presence-linux.py --hbbs "$OUTPUT/hbbs" --old-hbbs "$TOOLS/logs/relay-g4-release-20261127-205254/bin-linux-x86_64/hbbs" --evidence-root "$presence_run" --repo-root "$REPO" > "$EVIDENCE/presence-e2e.log" 2>&1
presence_code=$?
set -e
printf '%s\n' "$presence_code" > "$EVIDENCE/presence-e2e-exit-code.txt"
if [[ -f "$presence_run/result.json" ]]; then cp "$presence_run/result.json" "$EVIDENCE/presence-e2e-result.json"; fi
if [[ -f "$presence_run/interop-vector.json" ]]; then cp "$presence_run/interop-vector.json" "$EVIDENCE/interop-vector.json"; fi
printf '%s\n%s\n' "$relay_run" "$presence_run" > "$EVIDENCE/protocol-evidence-paths.txt"
(cd "$OUTPUT" && sha256sum -c "$EVIDENCE/binaries.sha256") > "$EVIDENCE/tested-binaries-verified.log"
sha256sum -c "$EVIDENCE/source-before.sha256" > "$EVIDENCE/source-after-protocol.log"
sha256sum -c "$EVIDENCE/preserved-inputs.sha256" > "$EVIDENCE/final-preserved-inputs.log"
cat "$EVIDENCE/relay-e2e.log"
cat "$EVIDENCE/presence-e2e.log"
if ((relay_code != 0)); then exit "$relay_code"; fi
exit "$presence_code"
