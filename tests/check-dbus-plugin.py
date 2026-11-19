#!/usr/bin/env python3
"""Check plugin account discovery on a disposable session bus."""
import ast
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile

build = Path(sys.argv[1]).resolve()
c_plugin = len(sys.argv) == 3 and sys.argv[2] == "--c"
destination = "org.barev.C" if c_plugin else "org.barev.Native"
object_path = "/org/barev/C/Publishing" if c_plugin else "/org/barev/Native/Publishing"
implementation = "c" if c_plugin else "oberon"
checks = 0


def check(value):
    global checks
    assert value
    checks += 1


def call(method):
    result = subprocess.check_output([
        "gdbus", "call", "--session", "--dest", destination,
        "--object-path", object_path,
        "--method", "org.barev.Publishing1." + method,
    ], text=True, timeout=10)
    return ast.literal_eval(result.replace("uint32 ", "").replace("@a(sss) ", ""))


class Host:
    def __init__(self, profile):
        self.profile = profile
        self.errors = tempfile.TemporaryFile(dir=profile)
        env = dict(os.environ, HOME=str(profile), XDG_CONFIG_HOME=str(profile),
                   XDG_CACHE_HOME=str(profile), XDG_DATA_HOME=str(profile), G_DEBUG="fatal-criticals",
                   GIO_USE_VFS="local", GSETTINGS_BACKEND="memory")
        argv = [str(build / "tests/dbus-plugin-host"), str(build / "libbarev.so"), str(profile)] if c_plugin else [
            str(build / "ProtocolHost"), str(build / "libvoc-barev-test.so"),
            str(profile), "9", "test", "Անի", "bob@200::2",
        ]
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.errors, env=env, bufsize=0)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = b""

    def wait(self, prefix):
        while True:
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                text = line.decode()
                if text.startswith(prefix):
                    return text
            assert self.selector.select(30), ("host deadline", prefix)
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                self.errors.seek(0)
                raise AssertionError(("host EOF", self.errors.read().decode(errors="replace")))
            self.buffer += data

    def command(self, text):
        self.process.stdin.write((text + "\n").encode())
        self.process.stdin.flush()

    def close(self):
        try:
            if self.process.poll() is None:
                self.command("disconnect")
                self.wait("DISCONNECTED")
                for _ in range(20):
                    self.command("can-unload")
                    if self.wait("UNLOAD ") == "UNLOAD 1":
                        break
                else:
                    raise AssertionError("adapter callbacks did not retire")
                self.command("quit")
                status = self.process.wait(timeout=10)
                self.errors.seek(0)
                assert status == 0, (status, self.errors.read().decode(errors="replace"))
                check(True)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
            self.selector.close()
            self.process.stdin.close()
            self.process.stdout.close()
            self.errors.close()


with tempfile.TemporaryDirectory(prefix="dbus-plugin-", dir=build) as directory:
    hosts = []
    try:
        for index in range(2):
            profile = Path(directory) / str(index)
            profile.mkdir()
            host = Host(profile)
            hosts.append(host)
            host.wait("READY ")
            if index == 0:
                subprocess.run(["gdbus", "wait", "--session", "--timeout", "10", destination], check=True)
                check(call("GetInfo") == (1, implementation, ["accounts"]))
                first = call("ListAccounts")
                identity = next((profile / "barev/identities").glob("*.key")).stem
                check(first == ([(identity, "Անի", "200::1")],))
            else:
                check(call("ListAccounts") == first)
        hosts.pop().close()
        check(call("ListAccounts") == first)
        host = hosts[0]
        host.command("can-unload")
        check(host.wait("UNLOAD ") == "UNLOAD 0")
        host.command("disconnect")
        host.wait("DISCONNECTED")
        check(call("ListAccounts") == ([],))
        host.command("reconnect")
        host.wait("READY ")
        check(call("ListAccounts") == first)
    finally:
        for host in reversed(hosts):
            host.close()

print(f"D-Bus {implementation} plugin: {checks} checks passed")
