#!/usr/bin/env python3
"""Exercise pinned STARTTLS and SASL EXTERNAL through live plugin socket paths."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import selectors
import socket
import ssl
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

STREAM = "http://etherx.jabber.org/streams"
TLS = "urn:ietf:params:xml:ns:xmpp-tls"
SASL = "urn:ietf:params:xml:ns:xmpp-sasl"
SEEDS = [bytes(range(32)), bytes(range(1, 33))]


def public(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def prepare(path, peer_key, seed=SEEDS[0], nick="alice", peer="bob@200::2"):
    keys, accounts = path/"barev/identities", path/"barev/accounts"
    keys.mkdir(parents=True, mode=0o700); accounts.mkdir(mode=0o700)
    (path/"barev").chmod(0o700)
    own = public(seed)
    key = keys/(own.hex()+".key"); key.write_bytes(b"BAREVID1"+seed+own); key.chmod(0o600)
    link = accounts/(hashlib.sha256(b"Barev account v1\n"+nick.encode()).hexdigest()+".identity")
    link.write_bytes(b"BAREVAC1"+own); link.chmod(0o600)
    digest = hashlib.sha256(b"Barev peer pin v1\n"+own+peer.encode()).digest()
    pin = path/"barev"/("peer-"+digest.hex()+".pin")
    pin.write_bytes(b"BAREVPN1"+own+digest+peer_key); pin.chmod(0o600)
    return pin


class Host:
    def __init__(self, argv, profile, pass_fds=(), extra_env=None):
        self.errors = tempfile.TemporaryFile(dir=profile)
        env = dict(os.environ, HOME=str(profile), XDG_CONFIG_HOME=str(profile),
                   XDG_CACHE_HOME=str(profile), XDG_DATA_HOME=str(profile), G_DEBUG="fatal-criticals")
        env.pop("DBUS_SESSION_BUS_ADDRESS", None)
        env.update(extra_env or {})
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.errors, env=env, pass_fds=pass_fds, bufsize=0)
        self.selector = selectors.DefaultSelector(); self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = b""; self.events = []
        self.port = int(self.wait("READY ").split()[1])

    def wait(self, prefix):
        while True:
            if b"\n" not in self.buffer:
                assert self.selector.select(30), ("host deadline", prefix, self.events)
                data = os.read(self.process.stdout.fileno(), 65536)
                if not data:
                    self.errors.seek(0)
                    raise AssertionError(("host EOF", self.process.wait(timeout=5), self.events, self.errors.read().decode(errors="replace")))
                self.buffer += data
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                text = line.decode(); self.events.append(text)
                if text.startswith(prefix): return text

    def command(self, text):
        self.process.stdin.write((text+"\n").encode()); self.process.stdin.flush()

    def state(self):
        self.command("state"); return tuple(map(int, self.wait("STATE ").split()[1:]))

    def certificate(self):
        deadline = time.monotonic()+5
        while True:
            self.command("tls-cert"); encoded = self.wait("CERT ")[5:]
            if encoded: break
            assert time.monotonic() < deadline, "local TLS certificate deadline"
            time.sleep(0.01)
        cert = x509.load_der_x509_certificate(bytes.fromhex(encoded))
        assert cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == public(SEEDS[0])
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def close(self):
        if self.process.poll() is None: self.command("quit")
        try: self.process.wait(timeout=10)
        except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(); raise
        self.errors.seek(0); errors = self.errors.read().decode(errors="replace")
        assert self.process.returncode == 0 and "CRITICAL" not in errors, (self.process.returncode, errors)
        self.selector.close(); self.errors.close(); self.process.stdin.close(); self.process.stdout.close()


class Wire:
    def __init__(self, sock):
        self.socket = sock; self.socket.settimeout(10); self.buffer = b""

    def send(self, text): self.socket.sendall(text.encode())

    def closed(self):
        try: data = self.socket.recv(16384)
        except socket.timeout: raise
        except OSError: data = b""
        assert data in (b"", b"</stream:stream>"), ("application bytes on rejected stream", data)

    def until(self, token):
        while token not in self.buffer:
            data = self.socket.recv(16384)
            assert data, ("socket EOF", token, self.buffer)
            self.buffer += data
        end = self.buffer.index(token)+len(token)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def header(self):
        data = self.until(b">")
        if data.startswith(b"<?xml"): data += self.until(b">")
        root = ET.fromstring(data+b"</stream:stream>")
        assert root.tag == "{"+STREAM+"}stream" and root.get("from") == "alice@200::1", data

    def stanza(self):
        parser = ET.XMLPullParser(events=("start", "end")); depth = 1
        parser.feed(f"<stream:stream xmlns:stream='{STREAM}' xmlns='jabber:client'>"); list(parser.read_events())
        while True:
            if not self.buffer:
                self.buffer = self.socket.recv(16384)
                assert self.buffer, "stanza EOF"
            byte, self.buffer = self.buffer[:1], self.buffer[1:]; parser.feed(byte)
            if hasattr(parser, "flush"): parser.flush()
            for event, item in parser.read_events():
                depth += 1 if event == "start" else -1
                if depth == 1: return item


def opening(peer="bob@200::2"):
    return f"<stream:stream xmlns:stream='{STREAM}' xmlns='jabber:client' from='{peer}' to='alice@200::1'>"


parser = argparse.ArgumentParser()
parser.add_argument("--native", type=Path)
parser.add_argument("--c", nargs=2, type=Path, metavar=("HOST", "PLUGIN"))
parser.add_argument("--cross-only", action="store_true")
options = parser.parse_args()
assert options.native or options.c
assert not options.cross_only or (options.native and options.c)
checks = 0
with tempfile.TemporaryDirectory(prefix="barev-auth-protocol-") as temporary:
    root = Path(temporary)
    private = Ed25519PrivateKey.from_private_bytes(SEEDS[1])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "barev")]); now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
            .serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).sign(private, None))
    cert_path, key_path = root/"peer.pem", root/"peer.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    modes = [("native", options.native)] if options.native else []
    if options.c: modes.append(("c", options.c))
    if options.cross_only: modes = []
    for mode, tool in modes:
        for case in ("accept", "haze", "queued", "backpressure", "pin-replacement", "cutover-junk", "deadline", "early-message", "wrong-pin", "corrupt-pin", "changed-tls-header", "early-tls-message", "wrong-external", "changed-final-header"):
            profile = root/(mode+"-"+case); profile.mkdir(mode=0o700)
            persistent = profile/".purple" if case == "haze" else profile
            pin = prepare(persistent, bytes(32) if case == "wrong-pin" else public(SEEDS[1]))
            extra_env = {"BAREV_TEST_CORE_UI": "telepathy-haze"} if case == "haze" else {}
            if case == "corrupt-pin": pin.write_bytes(b"damaged")
            if mode == "native":
                host = Host([str(tool/"ProtocolHost"), str(tool/"libvoc-barev-test.so"), str(profile), "9", "test"], profile, extra_env=extra_env)
                wire = Wire(socket.create_connection(("::1", host.port), timeout=10))
            else:
                local, remote = socket.socketpair()
                try: host = Host([str(tool[0]), str(profile), str(tool[1]), str(local.fileno())], profile, (local.fileno(),), extra_env)
                finally: local.close()
                wire = Wire(remote)
            try:
                wire.send(opening())
                if case == "corrupt-pin":
                    wire.closed()
                    assert host.state()[0] == 0; checks += 1; continue
                wire.header()
                features = wire.stanza()
                assert features.tag == "{"+STREAM+"}features" and features.find("{"+TLS+"}starttls/{"+TLS+"}required") is not None
                assert host.state()[0] == 0
                if case == "deadline":
                    host.command("advance 31" if mode == "native" else "expire")
                    host.wait("ADVANCED" if mode == "native" else "EXPIRED")
                    wire.closed(); assert host.state()[0] == 0; checks += 1; continue
                if case == "pin-replacement":
                    record = pin.read_bytes(); pin.write_bytes(record[:72]+bytes(32))
                if case == "queued":
                    host.command("send "+base64.b64encode(b"queued before authentication").decode())
                    assert int(host.wait("SENT ").split()[1]) > 0
                    wire.socket.settimeout(0.1)
                    try:
                        data = wire.socket.recv(16384)
                        raise AssertionError(("application traffic before TLS", data))
                    except socket.timeout: pass
                    finally: wire.socket.settimeout(10)
                if case == "early-message":
                    wire.send("<message><body>forbidden</body></message>")
                    wire.closed()
                    assert host.state()[0] == 0; checks += 1; continue
                wire.send(f"<starttls xmlns='{TLS}'/>"+("<message><body>cutover</body></message>" if case == "cutover-junk" else ""))
                assert wire.stanza().tag == "{"+TLS+"}proceed" and not wire.buffer
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.load_cert_chain(cert_path, key_path)
                if case == "cutover-junk":
                    try: context.wrap_socket(wire.socket, server_hostname="barev")
                    except OSError: pass
                    else: raise AssertionError("plaintext across the TLS boundary was accepted")
                    assert host.state()[0] == 0; checks += 1; continue
                wire.socket = context.wrap_socket(wire.socket, server_hostname="barev")
                peer = x509.load_der_x509_certificate(wire.socket.getpeercert(binary_form=True))
                assert peer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == public(SEEDS[0])
                if case == "wrong-pin":
                    try: data = wire.socket.recv(16384)
                    except OSError: data = b""
                    assert not data; assert host.state()[0] == 0; checks += 1; continue
                wire.send(opening("other@200::2" if case == "changed-tls-header" else "bob@200::2"))
                if case == "changed-tls-header":
                    wire.closed(); checks += 1; continue
                wire.header(); assert host.state()[0] == 0
                assert wire.stanza().find("{"+SASL+"}mechanisms/{"+SASL+"}mechanism").text == "EXTERNAL"
                if case == "early-tls-message": wire.send("<message><body>forbidden</body></message>")
                else: wire.send(f"<auth xmlns='{SASL}' mechanism='{'PLAIN' if case == 'wrong-external' else 'EXTERNAL'}'>=</auth>")
                if case in ("early-tls-message", "wrong-external"):
                    wire.closed(); assert host.state()[0] == 0; checks += 1; continue
                assert wire.stanza().tag == "{"+SASL+"}success"; assert host.state()[0] == 0
                wire.send(opening("other@200::2" if case == "changed-final-header" else "bob@200::2"))
                if case == "changed-final-header":
                    wire.closed(); checks += 1; continue
                wire.header(); assert wire.stanza().tag == "{"+STREAM+"}features"
                first = wire.stanza()
                if case == "queued":
                    second = wire.stanza()
                    assert {first.tag, second.tag} == {"{jabber:client}presence", "{jabber:client}message"}
                    message = first if first.tag == "{jabber:client}message" else second
                    assert message.find("{jabber:client}body").text == "queued before authentication"
                else: assert first.tag == "{jabber:client}presence"
                assert host.state()[0] == 1
                wire.send("<message type='chat'><body>authenticated hello</body></message>")
                assert base64.b64decode(host.wait("MESSAGE ").split()[1]) == b"authenticated hello"
                host.command("send "+base64.b64encode(b"authenticated reply").decode())
                assert int(host.wait("SENT ").split()[1]) > 0
                assert wire.stanza().find("{jabber:client}body").text == "authenticated reply"
                if case == "backpressure":
                    messages = [str(i)+"."+"x"*4000 for i in range(64)]
                    for message in messages:
                        host.command("send "+base64.b64encode(message.encode()).decode())
                        assert int(host.wait("SENT ").split()[1]) > 0
                    for message in messages:
                        assert wire.stanza().find("{jabber:client}body").text == message
                checks += 1
            finally:
                wire.socket.close(); host.close()
        for case in ("accept", "missing-tls", "early-proceed", "wrong-pin", "wrong-mechanisms", "changed-final-header"):
            profile = root/(mode+"-outgoing-"+case); profile.mkdir(mode=0o700)
            prepare(profile, bytes(32) if case == "wrong-pin" else public(SEEDS[1]))
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.bind(("::1", 0)); listener.listen(1); listener.settimeout(10)
            if mode == "native":
                host = Host([str(tool/"ProtocolHost"), str(tool/"libvoc-barev-test.so"), str(profile),
                             str(listener.getsockname()[1]), "test"], profile)
                wire = Wire(listener.accept()[0])
            else:
                local, remote = socket.socketpair()
                try: host = Host([str(tool[0]), str(profile), str(tool[1]), str(local.fileno()), "client"], profile, (local.fileno(),))
                finally: local.close()
                wire = Wire(remote)
            try:
                wire.header(); wire.send(opening()); assert host.state()[0] == 0
                if case in ("missing-tls", "early-proceed"):
                    wire.send("<stream:features/>" if case == "missing-tls" else f"<proceed xmlns='{TLS}'/>")
                    wire.closed(); assert host.state()[0] == 0; checks += 1; continue
                wire.send(f"<stream:features><starttls xmlns='{TLS}'><required/></starttls></stream:features>")
                assert wire.stanza().tag == "{"+TLS+"}starttls" and not wire.buffer
                wire.send(f"<proceed xmlns='{TLS}'/>")
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.load_cert_chain(cert_path, key_path); context.num_tickets = 0
                context.verify_mode = ssl.CERT_REQUIRED; context.load_verify_locations(cadata=host.certificate())
                if case == "wrong-pin":
                    try: context.wrap_socket(wire.socket, server_side=True)
                    except OSError: pass
                    else: raise AssertionError("client accepted a mismatched server pin")
                    assert host.state()[0] == 0; checks += 1; continue
                wire.socket = context.wrap_socket(wire.socket, server_side=True)
                wire.header(); wire.send(opening())
                wire.send(f"<stream:features><mechanisms xmlns='{SASL}'><mechanism>{'PLAIN' if case == 'wrong-mechanisms' else 'EXTERNAL'}</mechanism></mechanisms></stream:features>")
                if case == "wrong-mechanisms":
                    wire.closed(); assert host.state()[0] == 0; checks += 1; continue
                auth = wire.stanza()
                assert auth.tag == "{"+SASL+"}auth" and auth.get("mechanism") == "EXTERNAL" and auth.text == "="
                wire.send(f"<success xmlns='{SASL}'/>"); wire.header()
                wire.send(opening("other@200::2" if case == "changed-final-header" else "bob@200::2"))
                if case == "changed-final-header":
                    wire.closed(); assert host.state()[0] == 0; checks += 1; continue
                wire.send("<stream:features/>")
                assert wire.stanza().tag == "{jabber:client}presence" and host.state()[0] == 1
                checks += 1
            finally:
                listener.close(); wire.socket.close(); host.close()
        print(mode+": both STARTTLS roles, restarts, SASL EXTERNAL and fail-closed gates passed", flush=True)
    if options.native and options.c:
        for c_client in (False, True):
            profiles = [root/("cross-"+str(c_client)+"-"+str(i)) for i in range(2)]
            for profile in profiles: profile.mkdir(mode=0o700)
            prepare(profiles[0], public(SEEDS[1]))
            prepare(profiles[1], public(SEEDS[0]), SEEDS[1], "bob", "alice@200::1")
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.bind(("::1", 0)); listener.listen(1); listener.settimeout(10)
            peer_port = 9 if c_client else listener.getsockname()[1]
            native = Host([str(options.native/"ProtocolHost"), str(options.native/"libvoc-barev-test.so"),
                           str(profiles[1]), str(peer_port), "test", "bob", "alice@200::1"], profiles[1],
                          extra_env={"BAREV_TEST_LOCAL_IPV6": "200::2", "BAREV_TEST_PEER_IPV6": "200::1"})
            c_host = None
            try:
                connection = socket.create_connection(("::1", native.port), timeout=10) if c_client else listener.accept()[0]
                try:
                    c_host = Host([str(options.c[0]), str(profiles[0]), str(options.c[1]), str(connection.fileno()),
                                   "client" if c_client else "server"], profiles[0], (connection.fileno(),))
                finally: connection.close()
                deadline = time.monotonic()+15
                while c_host.state()[0] != 1 or native.state()[0] != 1:
                    assert time.monotonic() < deadline, ("cross-plugin readiness", c_client, c_host.events, native.events)
                    time.sleep(0.01)
                for sender, receiver, message in [(c_host, native, b"C to Oberon authenticated"),
                                                  (native, c_host, b"Oberon to C authenticated")]:
                    sender.command("send "+base64.b64encode(message).decode())
                    assert int(sender.wait("SENT ").split()[1]) > 0
                    received = base64.b64decode(receiver.wait("MESSAGE ").split()[1])
                    rendered = "".join(ET.fromstring("<root>"+received.decode()+"</root>").itertext()).encode()
                    assert rendered == message, ("cross-plugin message", c_client, message, received)
                checks += 1
            finally:
                listener.close()
                if c_host: c_host.close()
                native.close()
        print("C/Oberon: authenticated messages passed with both initiating roles", flush=True)
print(f"Authenticated plugin streams: {checks} scenarios passed")
