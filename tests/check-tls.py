#!/usr/bin/env python3
"""Pinned TLS transport tests against Python/OpenSSL and optional native Oberon peers.

Usage: check-tls.py C-TEST [--native OBERON-TEST]
Requires Python cryptography. Connections and identity profiles stay local.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import selectors
import socket
import ssl
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier, SignatureAlgorithmOID


tools = []
arguments = iter(sys.argv[1:])
for argument in arguments:
    native = argument == "--native"
    tools.append((Path(next(arguments) if native else argument).resolve(), native))
if not tools:
    raise SystemExit("usage: check-tls.py C-TEST [--native OBERON-TEST]")
seeds = [bytes(range(32)), bytes(range(1, 33))]
now = datetime.now(timezone.utc)


def public(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


with tempfile.TemporaryDirectory(prefix="barev-tls-") as temporary:
    root = Path(temporary)
    profiles = {}

    def profile(seed, mode):
        key = seed.hex(), mode
        if key in profiles:
            return profiles[key]
        path = root/seed.hex()/mode
        path.mkdir(mode=0o700, parents=True)
        keys, accounts = path/"barev/identities", path/"barev/accounts"
        keys.mkdir(mode=0o700, parents=True); accounts.mkdir(mode=0o700)
        (path/"barev").chmod(0o700)
        identifier = public(seed)
        record = keys/(identifier.hex()+".key")
        record.write_bytes(b"BAREVID1"+seed+identifier); record.chmod(0o600)
        account = accounts/(hashlib.sha256(b"Barev account v1\ntls-test").hexdigest()+".identity")
        account.write_bytes(b"BAREVAC1"+identifier); account.chmod(0o600)
        profiles[key] = path
        return path

    def command(tool, seed, pin, fd, server, expected, mode="purple"):
        executable, native = tool
        identity = str(profile(seed, mode)) if native else seed.hex()
        return [str(executable), identity, pin.hex(), str(fd), "server" if server else "client", expected]

    def certificate(process, seed):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(15), "transport did not expose its certificate"
        line = process.stdout.readline().strip()
        assert line.startswith("CERT "), (process.args, line)
        der = bytes.fromhex(line[5:]); cert = x509.load_der_x509_certificate(der)
        assert cert.signature_algorithm_oid == SignatureAlgorithmOID.ED25519
        assert cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == public(seed)
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def fixture(label, usage=None, before=-1, after=1, unknown=False, wrong_signer=False):
        key = Ed25519PrivateKey.from_private_bytes(seeds[1])
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "barev")])
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(1).not_valid_before(now+timedelta(days=before)).not_valid_after(now+timedelta(days=after)))
        if usage is not None:
            builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        if unknown:
            builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.5"), b"\x05\x00"), critical=True)
        cert = builder.sign(Ed25519PrivateKey.generate() if wrong_signer else key, None)
        cert_path, key_path = root/(label+".pem"), root/(label+".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        return cert_path, key_path

    plain = fixture("peer")
    expired = fixture("expired", before=-2, after=-1)
    future = fixture("future", before=1, after=2)
    client_only = fixture("client-only", usage=ExtendedKeyUsageOID.CLIENT_AUTH)
    server_only = fixture("server-only", usage=ExtendedKeyUsageOID.SERVER_AUTH)
    unknown = fixture("critical", unknown=True)
    invalid_signature = fixture("invalid-signature", wrong_signer=True)
    checks = 0
    for tool in tools:
        executable, native = tool
        if not native:
            subprocess.run([str(executable), "selftest"], check=True, timeout=30)
        for server in (False, True):
            cases = [("purple", plain, public(seeds[1]), "X25519", "accept", True, False),
                     ("telepathy/haze", plain, public(seeds[1]), "prime256v1", "accept", True, False),
                     ("purple", plain, bytes(32), "X25519", "reject", True, False),
                     ("purple", plain, public(seeds[1])[:-1], "X25519", "begin-reject", True, False),
                     ("purple", expired, public(seeds[1]), "X25519", "reject", True, False),
                     ("purple", future, public(seeds[1]), "X25519", "reject", True, False),
                     ("purple", unknown, public(seeds[1]), "X25519", "reject", True, False),
                     ("purple", invalid_signature, public(seeds[1]), "X25519", "reject", True, False),
                     ("purple", client_only if not server else server_only, public(seeds[1]), "X25519", "reject", True, False),
                     ("purple", plain, public(seeds[1]), "X25519", "reject", False, False),
                     ("purple", plain, public(seeds[1]), "X25519", "reject", True, True)]
            for mode, peer_identity, pin, curve, expected, mutual, downgrade in cases:
                local, peer = socket.socketpair(); peer.settimeout(20)
                process = subprocess.Popen(command(tool, seeds[0], pin, local.fileno(), server, expected, mode),
                                           pass_fds=(local.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                local.close()
                try:
                    if expected == "begin-reject":
                        stdout, stderr = process.communicate(timeout=20)
                        assert process.returncode == 0, (process.args, stdout, stderr)
                        checks += 1; continue
                    pem = certificate(process, seeds[0])
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if server else ssl.PROTOCOL_TLS_SERVER)
                    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2 if downgrade else ssl.TLSVersion.TLSv1_3
                    context.set_ecdh_curve(curve)
                    if server:
                        context.check_hostname = False; context.load_verify_locations(cadata=pem)
                        if mutual:
                            context.load_cert_chain(*peer_identity)
                    else:
                        context.load_cert_chain(*peer_identity); context.num_tickets = 0
                        if mutual:
                            context.verify_mode = ssl.CERT_REQUIRED; context.load_verify_locations(cadata=pem)
                    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                    stream = context.wrap_bio(incoming, outgoing, server_side=not server,
                                             server_hostname="barev" if server else None)

                    def drain():
                        wire = outgoing.read()
                        for at in range(0, len(wire), 7):
                            peer.sendall(wire[at:at+7])

                    def receive():
                        wire = peer.recv(16384)
                        if not wire:
                            raise EOFError("transport closed")
                        incoming.write(wire)

                    try:
                        while True:
                            try:
                                stream.do_handshake(); drain(); break
                            except ssl.SSLWantReadError:
                                drain(); receive()
                        if server and expected == "accept":
                            stream.write(b"hello"); drain()
                        received = b""
                        while len(received) < 5:
                            try:
                                received += stream.read(5-len(received))
                            except ssl.SSLWantReadError:
                                drain(); receive()
                        assert expected == "accept" and received == (b"world" if server else b"hello"), (expected, received)
                        if not server:
                            stream.write(b"world"); drain()
                    except (ssl.SSLError, OSError, EOFError):
                        if expected == "accept":
                            raise
                        peer.close()
                    stdout, stderr = process.communicate(timeout=20)
                    assert process.returncode == 0, (process.args, peer_identity[0].name, mutual, downgrade, process.returncode, stdout, stderr)
                    checks += 1
                finally:
                    peer.close()
                    if process.poll() is None:
                        process.kill(); process.wait()
        print(executable.name+": peer policy, fragmentation and profile checks passed", flush=True)
        if native:
            flow = executable.with_name("TestTLSFlow")
            if flow.is_file():
                sockets = [*socket.socketpair(), *socket.socketpair()]
                try:
                    sockets[0].setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
                    result = subprocess.run([str(flow), str(profile(seeds[0], "purple")), str(profile(seeds[1], "telepathy/haze")),
                                             *(str(s.fileno()) for s in sockets)], pass_fds=tuple(s.fileno() for s in sockets),
                                            capture_output=True, text=True, timeout=30)
                    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
                    print(result.stdout.strip()); checks += 1
                finally:
                    for s in sockets:
                        s.close()

    for client_tool in tools:
        for server_tool in tools:
            client_fd, server_fd = socket.socketpair()
            processes = []
            try:
                for tool, seed, pin, fd, server in [(client_tool, seeds[0], public(seeds[1]), client_fd, False),
                                                   (server_tool, seeds[1], public(seeds[0]), server_fd, True)]:
                    processes.append(subprocess.Popen(command(tool, seed, pin, fd.fileno(), server, "accept", "telepathy/haze"),
                                                      pass_fds=(fd.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                client_fd.close(); server_fd.close()
                for process, seed in zip(processes, seeds):
                    certificate(process, seed)
                    stdout, stderr = process.communicate(timeout=30)
                    assert process.returncode == 0, (process.args, process.returncode, stdout, stderr)
                checks += 1
            finally:
                client_fd.close(); server_fd.close()
                for process in processes:
                    if process.poll() is None:
                        process.kill(); process.wait()
    for (seed, mode), path in profiles.items():
        raw = bytes.fromhex(seed); identifier = public(raw)
        assert (path/"barev/identities"/(identifier.hex()+".key")).read_bytes() == b"BAREVID1"+raw+identifier
    print(f"TLS transport interoperability: {checks} scenarios passed")
