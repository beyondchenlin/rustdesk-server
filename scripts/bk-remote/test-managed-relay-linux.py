#!/usr/bin/env python3
"""Isolated native-process relay checks; never targets deployed services."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import time
import uuid


def varint(value):
    data = bytearray()
    while value > 127:
        data.append((value & 127) | 128)
        value >>= 7
    return bytes(data + bytes([value]))


def field(number, value):
    if isinstance(value, str):
        value = value.encode()
    return varint(number * 8 + 2) + varint(len(value)) + value


def fields(data):
    result, pos = {}, 0
    def integer():
        nonlocal pos
        value, shift = 0, 0
        while True:
            byte = data[pos]
            pos += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7
            assert shift < 70
    while pos < len(data):
        tag = integer()
        if tag % 8 == 0:
            result[tag // 8] = integer()
        elif tag % 8 == 2:
            size = integer()
            result[tag // 8] = data[pos:pos + size]
            pos += size
        else:
            raise AssertionError('Unexpected protobuf wire type')
    return result


def frame(data):
    size = len(data)
    width = next(w for w in range(1, 5) if size < (1 << (w * 8 - 2)))
    return ((size << 2) | (width - 1)).to_bytes(width, 'little') + data


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise AssertionError('Native connection closed unexpectedly')
        data.extend(chunk)
    return bytes(data)


def receive(stream):
    head = exact(stream, 1)
    width = (head[0] & 3) + 1
    head += exact(stream, width - 1)
    size = int.from_bytes(head, 'little') >> 2
    assert size <= 65536
    return fields(exact(stream, size))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin-root', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--repo-root', type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    binaries = args.bin_root.resolve()
    for name in ('hbbs', 'hbbr', 'bk-remote-relayctl'):
        assert (binaries / name).is_file(), name
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(('192.0.2.1', 9))
        ip = route.getsockname()[0]
    address = ipaddress.ip_address(ip)
    assert address.is_private and not address.is_loopback
    owned, files, streams, results = [], [], [], []
    prior_db = args.repo_root / 'db_v2.sqlite3'
    before = hashlib.sha256(prior_db.read_bytes()).hexdigest() if prior_db.exists() else None

    def record(name):
        results.append(name)
        print(name, flush=True)

    def port_group(host, offsets):
        for _ in range(100):
            port = 32000 + secrets.randbelow(20000)
            sockets = []
            try:
                for offset in offsets:
                    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                        s = socket.socket(socket.AF_INET, kind)
                        sockets.append(s)
                        s.bind((host, port + offset))
                return port
            except OSError:
                pass
            finally:
                for s in sockets:
                    s.close()
        raise AssertionError('No isolated port group available')

    def start(name, argv, tag, work=None):
        directory = root / (work or tag)
        directory.mkdir(exist_ok=True)
        out = (root / (tag + '.out.log')).open('wb')
        err = (root / (tag + '.err.log')).open('wb')
        files.extend([out, err])
        process = subprocess.Popen([str(binaries / name), *argv], cwd=directory, stdout=out, stderr=err)
        owned.append(process)
        return process

    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def listener(process, host, port):
        for _ in range(100):
            assert process.poll() is None, 'Isolated native process exited'
            try:
                with socket.create_connection((host, port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError('Isolated listener did not start')

    def ctl(argv, tag, expected=0):
        run = subprocess.run([str(binaries / 'bk-remote-relayctl'), *map(str, argv)], cwd=root,
                             capture_output=True, timeout=125)
        (root / (tag + '.json')).write_bytes(run.stdout)
        (root / (tag + '.err.log')).write_bytes(run.stderr)
        assert run.returncode == expected, f'{tag}: exit {run.returncode}, expected {expected}'
        return json.loads(run.stdout) if run.stdout.strip().startswith(b'{') else None

    def status(data, revision, state, eligible):
        assert data['ok'] is True
        assert data['data']['journal']['current']['revision'] == revision
        assert data['data']['runtime']['state'] == state
        assert data['data']['runtime']['eligible'] == eligible

    def console(command):
        with socket.create_connection(('127.0.0.1', console_port), timeout=5) as stream:
            stream.sendall(command.encode())
            data = bytearray()
            while True:
                part = stream.recv(4096)
                if not part:
                    return bytes(data).decode().strip()
                data.extend(part)
                assert len(data) <= 16384

    def pair(endpoint):
        host, port = endpoint.rsplit(':', 1)
        first = socket.create_connection((host, int(port)), timeout=5)
        second = socket.create_connection((host, int(port)), timeout=5)
        streams.extend([first, second])
        request = frame(field(18, field(2, uuid.uuid4().hex) + field(6, key)))
        first.sendall(request)
        second.sendall(request)
        return first, second

    def roundtrip(pairing):
        first, second = pairing
        for source, destination in ((first, second), (second, first)):
            marker = secrets.token_bytes(262144)
            source.sendall(marker)
            assert exact(destination, len(marker)) == marker

    def reject_native(endpoint, tag):
        with socket.create_connection(('127.0.0.1', server_port), timeout=5) as stream:
            request = field(1, '987654321') + field(2, uuid.uuid4().hex) + field(4, endpoint)
            stream.sendall(frame(field(18, request)))
            response = fields(receive(stream)[19])
            assert response[6] == b'Managed relay unavailable'
        record(tag)

    def direct_without_managed_relay(fallback):
        peer_id = '987654321'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(('127.0.0.1', 0))
            peer.settimeout(5)
            registration = field(1, peer_id) + field(2, uuid.uuid4().bytes) + field(3, secrets.token_bytes(32))
            peer.sendto(field(15, registration), ('127.0.0.1', server_port))
            assert fields(fields(peer.recv(65536))[16]).get(1, 0) == 0
            peer.sendto(field(6, field(1, peer_id)), ('127.0.0.1', server_port))
            assert fields(fields(peer.recv(65536))[7]).get(2, 0) == 0
            with socket.socket() as direct:
                direct.bind(('127.0.0.1', 0))
                direct.listen(1)
                direct.settimeout(5)
                encoded = ((int.from_bytes(socket.inet_aton('127.0.0.1'), 'little') << 49)
                           | direct.getsockname()[1]).to_bytes(16, 'little').rstrip(b'\x00')
                with socket.create_connection(('127.0.0.1', server_port), timeout=5) as controller:
                    controller.sendall(frame(field(8, field(1, peer_id) + field(3, key))))
                    forwarded = fields(fields(peer.recv(65536))[12])
                    assert not forwarded.get(2, b'')
                    response = field(1, forwarded[1]) + field(2, encoded) + field(3, fallback) + field(4, peer_id)
                    with socket.create_connection(('127.0.0.1', server_port), timeout=5) as responder:
                        responder.sendall(frame(field(13, response)))
                    received = fields(receive(controller)[11])
                    assert received[1] == encoded
                    assert not received.get(4, b'')
                with socket.create_connection(direct.getsockname(), timeout=5) as outbound:
                    accepted, _ = direct.accept()
                    with accepted:
                        roundtrip((outbound, accepted))
                record('G4_DIRECT_CANDIDATE_AND_TRANSPORT_PRESERVED_WHEN_POOL_DOWN_PASS')
            with socket.create_connection(('127.0.0.1', server_port), timeout=5) as controller:
                controller.sendall(frame(field(8, field(1, peer_id) + field(3, key))))
                forwarded = fields(fields(peer.recv(65536))[12])
                response = field(1, forwarded[1]) + field(2, uuid.uuid4().hex) + field(3, fallback)
                with socket.create_connection(('127.0.0.1', server_port), timeout=5) as responder:
                    responder.sendall(frame(field(19, response)))
                assert fields(receive(controller)[11])[7] == b'Managed relay unavailable'
            record('G4_FORCED_RELAY_FALLBACK_REFUSED_USING_NATIVE_ERROR_PASS')

    try:
        pa = port_group(ip, (0, 2))
        pb = port_group(ip, (0, 2))
        while abs(pa - pb) <= 2:
            pb = port_group(ip, (0, 2))
        server_port = port_group('127.0.0.1', (-1, 0, 2))
        console_port = server_port - 1
        node_a, node_b = f'{ip}:{pa}', f'{ip}:{pb}'
        key = base64.b64encode(secrets.token_bytes(32)).decode()
        db, token, wrong = root / 'pool.sqlite3', root / 'admin.token', root / 'wrong.token'
        ctl(['init-config', db, node_a], 'init-config')
        ctl(['init-token', token], 'init-token')
        ctl(['init-token', wrong], 'wrong-token')
        relay_a = start('hbbr', ['-b', ip, '-p', str(pa), '-k', key], 'relay-a')
        relay_b = start('hbbr', ['-b', ip, '-p', str(pb), '-k', key], 'relay-b')
        listener(relay_a, ip, pa)
        listener(relay_b, ip, pb)
        server_args = ['-b', '127.0.0.1', '-p', str(server_port), '-k', key,
                       '--bk-relay-pool', str(db), '--bk-relay-admin-token-file', str(token)]
        hbbs = start('hbbs', server_args, 'hbbs')
        listener(hbbs, '127.0.0.1', console_port)
        admin = ['admin', console_port, token]
        status(ctl(admin + ['status'], 'initial-status'), 1, 'healthy', [node_a])
        assert json.loads(console('tg 192.0.2.1 192.0.2.2')) == node_a
        active = pair(node_a)
        roundtrip(active)
        record('G4_INITIAL_NATIVE_SELECTION_AND_BIDIRECTIONAL_FORWARDING_PASS')
        ctl(['admin', console_port, wrong, 'status'], 'wrong-auth', 1)
        assert 'authentication failed' in (root / 'wrong-auth.err.log').read_text()
        assert 'Managed relay mode' in console('rs ' + node_b)
        assert 'Managed relay mode' in console('aur Y')
        record('G4_ADMIN_AUTH_AND_LEGACY_MUTATION_GUARD_PASS')
        status(ctl(admin + ['publish', 1, node_b], 'switch-b'), 2, 'healthy', [node_b])
        assert json.loads(console('tg 192.0.2.1 192.0.2.2')) == node_b
        roundtrip(active)
        roundtrip(pair(node_b))
        record('G4_SWITCH_NEW_NODE_EXISTING_STREAM_UNINTERRUPTED_PASS')
        reject_native(node_a, 'G4_REMOVED_BUT_RUNNING_RELAY_REFUSED_FOR_NEW_CONNECTION_PASS')
        ctl(admin + ['publish', 1, node_a], 'stale-version', 1)
        stop(relay_b)
        status(ctl(admin + ['refresh'], 'all-down'), 2, 'unavailable', [])
        assert json.loads(console('tg 192.0.2.1 192.0.2.2')) == ''
        reject_native(node_b, 'G4_FAILED_NODE_NATIVE_REQUEST_REFUSED_PASS')
        reject_native(node_a, 'G4_IMPLICIT_FALLBACK_OUTSIDE_POOL_REFUSED_PASS')
        ctl(admin + ['publish', 2, node_b], 'reject-down', 1)
        roundtrip(active)
        record('G4_ALL_DOWN_FAIL_CLOSED_EXISTING_STREAM_PRESERVED_PASS')
        direct_without_managed_relay(node_a)
        status(ctl(admin + ['rollback', 2], 'rollback-a'), 3, 'healthy', [node_a])
        assert json.loads(console('tg 192.0.2.1 192.0.2.2')) == node_a
        stop(hbbs)
        assert 'Managed relay unavailable: no healthy nodes' in (root / 'hbbs.out.log').read_text()
        record('G4_ALL_DOWN_TRANSITION_EMITS_SERVER_ALARM_PASS')
        hbbs = start('hbbs', server_args, 'hbbs-restart', work='hbbs')
        listener(hbbs, '127.0.0.1', console_port)
        status(ctl(admin + ['status'], 'restart-status'), 3, 'healthy', [node_a])
        roundtrip(active)
        with sqlite3.connect(db) as connection:
            assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        record('G4_ROLLBACK_RESTART_AND_ATOMIC_JOURNAL_PASS')
        status(ctl(admin + ['publish', 3, node_a + ',' + node_b], 'two-node-degraded'),
               4, 'degraded', [node_a])
        stop(relay_a)
        status(ctl(admin + ['refresh'], 'both-real-nodes-down'), 4, 'unavailable', [])
        assert json.loads(console('tg 192.0.2.1 192.0.2.2')) == ''
        reject_native(node_a, 'G4_BOTH_CONFIGURED_REAL_NODES_DOWN_REFUSED_PASS')
        relay_a = start('hbbr', ['-b', ip, '-p', str(pa), '-k', key],
                        'relay-a-recovered', work='relay-a')
        listener(relay_a, ip, pa)
        status(ctl(admin + ['refresh'], 'node-a-recovered'), 4, 'degraded', [node_a])
        status(ctl(admin + ['rollback', 4], 'rollback-after-total-outage'), 5, 'healthy', [node_a])
        roundtrip(pair(node_a))
        record('G4_PARTIAL_HEALTH_TOTAL_OUTAGE_RECOVERY_PASS')
        stop(hbbs)
        legacy = start('hbbs', ['-b', '127.0.0.1', '-p', str(server_port), '-k', key, '-r', node_a], 'legacy')
        listener(legacy, '127.0.0.1', console_port)
        assert console('rs') == node_a
        record('G4_UNMANAGED_NATIVE_MODE_PRESERVED_PASS')
        if before is not None:
            assert hashlib.sha256(prior_db.read_bytes()).hexdigest() == before
        record('G4_EXISTING_SERVER_DATABASE_UNCHANGED_PASS')
    finally:
        for stream in streams:
            stream.close()
        for process in reversed(owned):
            stop(process)
        for file in files:
            file.close()
        assert all(process.poll() is not None for process in owned)
        (root / 'result.json').write_text(json.dumps({
            'checks': results, 'owned_processes_stopped': True,
            'cross_region_verified': False, 'real_desktop_mobile_session_verified': False,
            'production_changed': False,
        }, indent=2) + '\n')
        print('G4_OWNED_PROCESSES_STOPPED', flush=True)


if __name__ == '__main__':
    main()
