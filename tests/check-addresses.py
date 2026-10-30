#!/usr/bin/env python3
"""Check the local codec against an independent base32 reference and plugin UI."""
import base64
import ctypes
import ipaddress
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile

plugin = ctypes.CDLL(sys.argv[2])
plugin.barev_address_encode.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
plugin.barev_address_decode.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
plugin.barev_address_identity.argtypes = [ctypes.c_char_p, ctypes.c_int]
plugin.barev_address_identity.restype = ctypes.c_void_p
plugin.g_free.argtypes = [ctypes.c_void_p]
checks = 0
suffix = ".barev.v6.alt"


def check(value):
    global checks
    checks += 1
    assert value, f"address check {checks} failed"


def encode(raw):
    label = base64.b32encode(raw).decode().lower().rstrip("=")
    runs = list(re.finditer("a{2,}", label[1:-1]))
    if runs:
        run = max(runs, key=lambda match: len(match[0]))
        label = label[:run.start()+1] + "-" + label[run.end()+1:]
    return label + suffix


def decode(host):
    host = host.lower().removesuffix(".")
    if not host.endswith(suffix):
        return None
    label = host[:-len(suffix)]
    if not 3 <= len(label) <= 26:
        return None
    if "-" in label:
        if label.count("-") != 1 or label[0] == "-" or label[-1] == "-" or len(label) > 25:
            return None
        label = label.replace("-", "a" * (27-len(label)))
    if not re.fullmatch("[a-z2-7]{26}", label):
        return None
    raw = base64.b32decode(label.upper() + "======")
    if base64.b32encode(raw).decode().lower().rstrip("=") != label:
        return None
    return raw


vectors = [
    ("200::1", "ai-e"),
    ("200:cab8:deb4:ce60:4362:4492:e539:4b5", "aiamvog6wthgaq3cisjokoiewu"),
    ("::", "a-a"), ("::1", "a-e"),
    ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "77777777777777777777777774"),
    ("1111:0:0:1111::1111", "ceiqaaaaaairc-rce"),
    ("1111::1111:0:0:1111", "ceiq-eiraaaaaaarce"),
    ("202:0:108:4210:0:842:1084:2109", "aib-bbbbbaaaabbbbbbbbbe"),
]
buffer = ctypes.create_string_buffer(40)
decoded = ctypes.create_string_buffer(16)
for address, label in vectors:
    raw = ipaddress.IPv6Address(address).packed
    check(encode(raw) == label+suffix)
    check(plugin.barev_address_encode(raw, buffer, 40) and buffer.value.decode() == label+suffix)
    for host in (label+suffix, (label+suffix).upper()+"."):
        check(plugin.barev_address_decode(host.encode(), decoded) and decoded.raw == raw)

rng = random.Random(6173)
for sample in range(4096):
    raw = bytes(rng.randrange(256) if sample % 3 else 0 for _ in range(16))
    check(plugin.barev_address_encode(raw, buffer, 40) and buffer.value.decode() == encode(raw))
    check(plugin.barev_address_decode(buffer.value, decoded) and decoded.raw == raw)
    full = base64.b32encode(raw).decode().lower().rstrip("=")+suffix
    check(plugin.barev_address_decode(full.encode(), decoded) and decoded.raw == raw)

malformed = ["ai--e", "-aie", "aie-", "aie", "ai-f", "ai-0", "ai-=", "a"*27,
             "a"*25+"-", "a"*26+"-", "ai-e.barev", "x.ai-e"]
hosts = [part+suffix for part in malformed]
hosts += ["ai-e.v6.alt", "ai-e"+suffix+"..", "ai-e"+suffix+".evil", ""]
hosts += ["aibaaaabbbbb-bbbbbbbbbe"+suffix]
for _ in range(4096):
    hosts.append("".join(rng.choice("abcde23457-=.0AZ") for _ in range(rng.randrange(42)))+suffix)
for host in hosts:
    expected = decode(host)
    okay = bool(plugin.barev_address_decode(host.encode(), decoded))
    check(okay == (expected is not None))
    if okay:
        check(decoded.raw == expected)
check(not plugin.barev_address_encode(bytes(16), buffer, 39))
for name, expected in [("Անի@AI-E.BAREV.V6.ALT.", "Անի@200::1"),
                       ("Alice😀@300::1", "Alice😀@300::1"),
                       ("x"*256+"@ai-e.barev.v6.alt", "x"*256+"@200::1")]:
    pointer = plugin.barev_address_identity(name.encode(), False)
    check(pointer and ctypes.string_at(pointer).decode() == expected)
    plugin.g_free(pointer)
for name in ["bob@a-e.barev.v6.alt", "bob@a-a.barev.v6.alt", "bob@72-e.barev.v6.alt",
             "bob@ai-f.barev.v6.alt", "bob@ai-e.v6.alt", "bob@ai--e.barev.v6.alt",
             "bob@ai-e.barev.v6.alt/resource", "@ai-e.barev.v6.alt", "bob@@ai-e.barev.v6.alt",
             "a b@ai-e.barev.v6.alt", "x"*257+"@ai-e.barev.v6.alt", "bob\u200b@ai-e.barev.v6.alt"]:
    pointer = plugin.barev_address_identity(name.encode(), False)
    check(not pointer)
    plugin.g_free(pointer)
print(f"Barev C codec checks passed: {checks}", flush=True)

with tempfile.TemporaryDirectory(prefix="barev-address-", dir=Path(sys.argv[1]).resolve().parent) as profile:
    environment = dict(os.environ, HOME=profile, XDG_CONFIG_HOME=profile,
                       XDG_CACHE_HOME=profile, XDG_DATA_HOME=profile,
                       G_DEBUG="fatal-criticals", GST_PLUGIN_SYSTEM_PATH_1_0="",
                       GST_PLUGIN_PATH_1_0="", GST_REGISTRY_1_0=os.path.join(profile, "gst.bin"))
    environment.pop("DBUS_SESSION_BUS_ADDRESS", None)
    subprocess.run([sys.argv[1], profile, sys.argv[2]], check=True, timeout=30, env=environment)
