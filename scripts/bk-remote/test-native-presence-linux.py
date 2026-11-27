#!/usr/bin/env python3
"""Owned local processes only: signed native registration interoperability and failure checks."""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import time
import uuid

helper_path = Path(__file__).with_name('test-managed-relay-linux.py')
spec = importlib.util.spec_from_file_location('relay_native_helpers', helper_path)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
field, fields, frame, receive = helpers.field, helpers.fields, helpers.frame, helpers.receive
DOMAIN = b'BK Remote native registration v1\n'
PREFIX = 'bk-presence-v1:'
SPKI = bytes.fromhex('302a300506032b6570032100')


def transcript(ids, nonce, bitmap):
    return (DOMAIN + nonce + len(ids).to_bytes(2, 'big') +
            b''.join(len(value.encode('ascii')).to_bytes(2, 'big') + value.encode('ascii') for value in ids) +
            bitmap)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hbbs', type=Path, required=True)
    parser.add_argument('--old-hbbs', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--repo-root', type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for path in [args.hbbs, args.old_hbbs]:
        assert path.is_file()
    openssl = shutil.which('openssl')
    assert openssl, 'Use the existing OpenSSL; do not install another toolchain'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(('192.0.2.1', 9))  # Local route selection; UDP connect sends no packet.
        ip = route.getsockname()[0]
    assert ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback
    owned, logs, results = [], [], []
    repo_db = args.repo_root / 'db_v2.sqlite3'
    db_before = hashlib.sha256(repo_db.read_bytes()).hexdigest() if repo_db.exists() else None

    def record(name):
        results.append(name)
        print(name, flush=True)

    def port_group():
        for _ in range(100):
            port = 32000 + secrets.randbelow(20000)
            sockets = []
            try:
                for offset in [-1, 0, 2]:
                    for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                        sock = socket.socket(socket.AF_INET, kind)
                        sockets.append(sock)
                        sock.bind((ip, port + offset))
                return port
            except OSError:
                pass
            finally:
                for sock in sockets:
                    sock.close()
        raise AssertionError('No isolated port group available')

    def start(binary, tag, port):
        work = root / tag
        work.mkdir(mode=0o700)
        output = (root / (tag + '.log')).open('wb')
        logs.append(output)
        process = subprocess.Popen([str(binary.resolve()), '-b', ip, '-p', str(port)], cwd=work,
                                   stdout=output, stderr=subprocess.STDOUT)
        owned.append(process)
        for _ in range(100):
            assert process.poll() is None, 'Owned native server exited'
            try:
                with socket.create_connection((ip, port), timeout=0.1):
                    return process, work
            except OSError:
                time.sleep(0.1)
        raise AssertionError('Owned native listener did not become ready')

    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def query(port, ids, nonce, *, challenge=None, extra=b'', auxiliary=False):
        request = field(1, challenge if challenge is not None else PREFIX + nonce.hex())
        request += b''.join(field(2, value) for value in ids) + extra
        try:
            with socket.create_connection((ip, port), timeout=2) as stream:
                stream.settimeout(2)
                stream.sendall(frame(field(23, request)))
                response = receive(stream)
                return fields(response[24])[1]
        except (OSError, AssertionError, KeyError, IndexError):
            return None

    def verify(public, ids, nonce, response):
        count = len(ids)
        size = (count + 7) // 8
        if response is None or len(response) != 5 + 32 + 2 + size + 64:
            return None
        if response[:5] != b'BKRP1' or response[5:37] != nonce or response[37:39] != count.to_bytes(2, 'big'):
            return None
        bitmap = response[39:39 + size]
        if count % 8 and bitmap[-1] & ((1 << (8 - count % 8)) - 1):
            return None
        (root / 'verify-public.der').write_bytes(SPKI + public)
        (root / 'verify-message.bin').write_bytes(transcript(ids, nonce, bitmap))
        (root / 'verify-signature.bin').write_bytes(response[39 + size:])
        check = subprocess.run([openssl, 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
                                '-inkey', str(root / 'verify-public.der'), '-rawin',
                                '-in', str(root / 'verify-message.bin'),
                                '-sigfile', str(root / 'verify-signature.bin')],
                               capture_output=True, timeout=5)
        if check.returncode != 0:
            return None
        return [bool(bitmap[index // 8] & (1 << (7 - index % 8))) for index in range(count)]

    def register(port, peer_id):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind((ip, 0))
            peer.settimeout(3)
            request = field(1, peer_id) + field(2, uuid.uuid4().bytes) + field(3, secrets.token_bytes(32))
            peer.sendto(field(15, request), (ip, port))
            assert fields(fields(peer.recv(65536))[16]).get(1, 0) == 0
            peer.sendto(field(6, field(1, peer_id)), (ip, port))
            assert fields(fields(peer.recv(65536))[7]).get(2, 0) == 0
        # Closing this socket stops native keepalives. No GUI/account heartbeat is started.

    try:
        port = port_group()
        process, work = start(args.hbbs, 'signed-server', port)
        public = base64.b64decode((work / 'id_ed25519.pub').read_bytes().strip(), validate=True)
        assert len(public) == 32
        ids = ['910101', '910202', '910303']
        register(port, ids[0])
        register(port, ids[2])
        stopped_at = time.monotonic()
        nonce = secrets.token_bytes(32)
        reply = query(port, ids, nonce)
        assert verify(public, ids, nonce, reply) == [True, False, True]
        record('PRESENCE_CORRECT_KEY_AND_NATIVE_ONLINE_OFFLINE_PASS')

        assert verify(secrets.token_bytes(32), ids, nonce, reply) is None
        record('PRESENCE_WRONG_TRUSTED_PUBLIC_KEY_UNKNOWN_PASS')
        altered = bytearray(reply)
        altered[39] ^= 0x80
        assert verify(public, ids, nonce, bytes(altered)) is None
        record('PRESENCE_BITMAP_TAMPERING_UNKNOWN_PASS')
        new_nonce = secrets.token_bytes(32)
        assert verify(public, ids, new_nonce, reply) is None
        fresh = query(port, ids, new_nonce)
        assert verify(public, ids, new_nonce, fresh) == [True, False, True]
        record('PRESENCE_REPLAY_AND_WRONG_CHALLENGE_UNKNOWN_PASS')
        assert verify(public, [ids[1], ids[0], ids[2]], nonce, reply) is None
        record('PRESENCE_IDENTIFIER_ORDER_IS_SIGNED_PASS')
        assert verify(public, ids, nonce, reply + b'\0') is None
        assert verify(public, ids, nonce, reply[:-1]) is None
        altered = bytearray(reply)
        altered[39] |= 1
        assert verify(public, ids, nonce, bytes(altered)) is None
        record('PRESENCE_EXACT_LENGTH_AND_ZERO_PADDING_PASS')

        assert query(port, [ids[0], ids[0]], secrets.token_bytes(32)) is None
        record('PRESENCE_SERVER_REJECTS_DUPLICATE_IDS_PASS')
        assert query(port, [str(i) for i in range(201)], secrets.token_bytes(32)) is None
        record('PRESENCE_SERVER_REJECTS_COUNT_OVER_LIMIT_PASS')
        for bad in ['bad\nidentifier', '../910101', 'x' * 254]:
            assert query(port, [bad], secrets.token_bytes(32)) is None
        record('PRESENCE_SERVER_REJECTS_INVALID_OR_OVERSIZED_IDS_PASS')
        assert query(port, [f'{i:03}' + 'x' * 250 for i in range(70)], secrets.token_bytes(32)) is None
        assert query(port, [ids[0]], secrets.token_bytes(32), extra=field(99, b'x' * 25000)) is None
        record('PRESENCE_SERVER_REJECTS_TOTAL_ID_AND_WHOLE_REQUEST_BYTE_LIMITS_PASS')

        maximum = [str(i) for i in range(200)]
        max_nonce = secrets.token_bytes(32)
        assert verify(public, maximum, max_nonce, query(port, maximum, max_nonce)) == [False] * 200
        record('PRESENCE_BOUNDED_200_ID_QUERY_INTEROPERATES_PASS')
        legacy = query(port - 1, ids, nonce, challenge='legacy-native-client', auxiliary=True)
        assert legacy == b'\xa0'
        assert verify(public, ids, nonce, legacy) is None
        record('PRESENCE_LEGACY_AUXILIARY_BEHAVIOR_PRESERVED_BUT_UNTRUSTED_PASS')

        old_port = port_group()
        old_process, old_work = start(args.old_hbbs, 'unsupported-server', old_port)
        old_public = base64.b64decode((old_work / 'id_ed25519.pub').read_bytes().strip(), validate=True)
        assert verify(old_public, ids, nonce, query(old_port, ids, nonce)) is None
        stop(old_process)
        record('PRESENCE_OLD_SERVER_UNSUPPORTED_IS_UNKNOWN_PASS')

        # The original registration lease is 30 seconds. No keepalive has been sent.
        remaining = 31 - (time.monotonic() - stopped_at)
        if remaining > 0:
            print(f'WAIT_NATIVE_REGISTRATION_EXPIRY_SECONDS={remaining:.2f}', flush=True)
            time.sleep(remaining)
        expired_nonce = secrets.token_bytes(32)
        assert verify(public, ids, expired_nonce, query(port, ids, expired_nonce)) == [False] * 3
        record('PRESENCE_STOPPED_NATIVE_REGISTRATION_EXPIRES_OFFLINE_PASS')

        # A new isolated identity verifies service recovery without replacing old credentials.
        recovered = ['910404']
        register(port, recovered[0])
        recovery_nonce = secrets.token_bytes(32)
        assert verify(public, recovered, recovery_nonce, query(port, recovered, recovery_nonce)) == [True]
        record('PRESENCE_NATIVE_REGISTRATION_RECOVERY_PASS')
        stop(process)
        assert query(port, ids, secrets.token_bytes(32)) is None
        record('PRESENCE_SERVER_UNAVAILABLE_IS_UNKNOWN_PASS')

        # Public fixed vector: seed is deliberately published synthetic test material, not a deployment key.
        vector_nonce, vector_ids, bitmap = bytes(range(32)), ['101', '202', '303'], b'\xa0'
        private_fixture = root / 'public-test-seed-only.der'
        private_fixture.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + bytes([7]) * 32)
        private_fixture.chmod(0o600)
        public_der = root / 'interop-public.der'
        subprocess.run([openssl, 'pkey', '-inform', 'DER', '-in', str(private_fixture),
                        '-pubout', '-outform', 'DER', '-out', str(public_der)], check=True, capture_output=True, timeout=5)
        vector_public = public_der.read_bytes()[-32:]
        vector_payload = transcript(vector_ids, vector_nonce, bitmap)
        (root / 'interop-transcript.bin').write_bytes(vector_payload)
        signature_path = root / 'interop-signature.bin'
        subprocess.run([openssl, 'pkeyutl', '-sign', '-inkey', str(private_fixture), '-keyform', 'DER',
                        '-rawin', '-in', str(root / 'interop-transcript.bin'), '-out', str(signature_path)],
                       check=True, capture_output=True, timeout=5)
        envelope = b'BKRP1' + vector_nonce + b'\x00\x03' + bitmap + signature_path.read_bytes()
        assert verify(vector_public, vector_ids, vector_nonce, envelope) == [True, False, True]
        (root / 'interop-vector.json').write_text(json.dumps({
            'purpose': DOMAIN.decode(), 'nonce_hex': vector_nonce.hex(), 'ids': vector_ids,
            'count_big_endian_hex': '0003', 'bitmap_hex': 'a0', 'bitmap_order': 'most-significant-bit-first',
            'public_key_hex': vector_public.hex(), 'transcript_hex': vector_payload.hex(),
            'response_hex': envelope.hex(), 'expected_states': [True, False, True],
            'seed_is_public_synthetic_test_fixture': True,
        }, indent=2) + '\n')
        record('PRESENCE_OPENSSL_ED25519_FIXED_INTEROPERABILITY_VECTOR_PASS')
    finally:
        for process in owned:
            stop(process)
        for output in logs:
            output.close()
        db_after = hashlib.sha256(repo_db.read_bytes()).hexdigest() if repo_db.exists() else None
        result = {
            'tests_passed': results, 'count': len(results),
            'source_head': subprocess.check_output(['git', '-C', str(args.repo_root), 'rev-parse', 'HEAD'], text=True).strip(),
            'hbbs_sha256': hashlib.sha256(args.hbbs.read_bytes()).hexdigest(),
            'old_hbbs_sha256': hashlib.sha256(args.old_hbbs.read_bytes()).hexdigest(),
            'repository_database_unchanged': db_before == db_after,
            'owned_processes_stopped': all(p.poll() is not None for p in owned),
            'scope': 'single-host isolated real native processes and protocol; no GUI acceptance',
            'cross_region_verified': False, 'production_verified': False,
            'native_device_gui_verified': False,
            'transport_encrypted': False,
        }
        (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        assert db_before == db_after
    print(f'PRESENCE_PROTOCOL_CHECKS_PASSED={len(results)}', flush=True)


if __name__ == '__main__':
    main()
