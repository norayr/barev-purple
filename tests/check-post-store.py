#!/usr/bin/env python3
"""Compare independent post validators and version-one snapshot codecs."""
from copy import deepcopy
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zlib

c_tool = Path(sys.argv[1]).resolve()
native = Path(sys.argv[2]).resolve()
owner = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
checks = 0


def check(value, label):
    global checks
    assert value, label
    checks += 1


def word(value):
    return struct.pack(">I", value)


def text(value):
    data = value if isinstance(value, bytes) else value.encode()
    return word(len(data)) + data


def encode(image):
    data = text(image["magic"]) + text(image["owner"])
    data += b"".join(word(image[key]) for key in ("node_limit", "post_limit", "byte_limit"))
    data += word(len(image["nodes"])) + word(len(image["posts"]))
    for node in image["nodes"]:
        data += text(node["name"]) + text(node["title"]) + word(node["model"]) + word(len(node["names"]))
        data += b"".join(text(name) for name in node["names"])
    for post in image["posts"]:
        data += word(post["node"]) + word(post["state"]) + text(post["item"]) + text(post["id"])
        if post["state"] == 1:
            data += b"".join(text(post[key]) for key in ("author", "title", "published", "updated", "parent", "body"))
    return data + word(zlib.crc32(data))


def decode(data):
    assert zlib.crc32(data[:-4]) == struct.unpack(">I", data[-4:])[0]
    at = 0

    def read_word():
        nonlocal at
        value = struct.unpack_from(">I", data, at)[0]
        at += 4
        return value

    def read_text():
        nonlocal at
        size = read_word()
        value = data[at:at+size].decode()
        assert len(data[at:at+size]) == size
        at += size
        return value

    image = {"magic": read_text(), "owner": read_text()}
    for key in ("node_limit", "post_limit", "byte_limit"):
        image[key] = read_word()
    nodes, posts = read_word(), read_word()
    image["nodes"], image["posts"] = [], []
    for _ in range(nodes):
        node = {"name": read_text(), "title": read_text(), "model": read_word()}
        node["names"] = [read_text() for _ in range(read_word())]
        image["nodes"].append(node)
    for _ in range(posts):
        post = {"node": read_word(), "state": read_word(), "item": read_text(), "id": read_text()}
        if post["state"]:
            for key in ("author", "title", "published", "updated", "parent", "body"):
                post[key] = read_text()
        image["posts"].append(post)
    assert at == len(data)-4
    return image


with tempfile.TemporaryDirectory(prefix="post-store-interop-", dir=c_tool.parent) as directory:
    base = Path(directory)
    env = dict(os.environ, HOME=str(base), XDG_CONFIG_HOME=str(base), XDG_DATA_HOME=str(base), XDG_CACHE_HOME=str(base))

    def run(tool, *args):
        return subprocess.check_output([str(tool), *map(str, args)], text=True, env=env, timeout=30)

    c_matrix = run(c_tool, "--matrix")
    native_matrix = run(native / "PostValidationMatrix")
    if c_matrix != native_matrix:
        for c_row, native_row in zip(c_matrix.splitlines(), native_matrix.splitlines()):
            assert c_row == native_row, ("validator matrix", c_row, native_row)
        raise AssertionError("validator matrix length")
    check(len(c_matrix.splitlines()) == 256, "255 validator rows")
    c_path, native_path = base / "c.state", base / "native.state"
    run(c_tool, "--write", c_path)
    run(native / "PostSnapshotInterop", "--write", native_path)
    data = c_path.read_bytes()
    check(data == native_path.read_bytes(), "independently generated snapshot bytes")
    image = decode(data)
    check(image["magic"] == "BAREVPS1" and image["owner"] == owner, "snapshot identity")
    check(len(image["nodes"]) == 3 and len(image["posts"]) == 4, "snapshot counts")
    check([node["model"] for node in image["nodes"]] == [1, 3, 2], "retained audience models")
    check(image["nodes"][2]["names"] == ["ընկերներ"], "retained Unicode roster")
    check(image["posts"][0]["author"] == "Անի@200::1" and image["posts"][3]["state"] == 0, "canonical author and tombstone")
    run(c_tool, "--roundtrip", native_path, base / "c-roundtrip.state")
    run(native / "PostSnapshotInterop", "--roundtrip", c_path, base / "native-roundtrip.state")
    check(data == (base / "c-roundtrip.state").read_bytes(), "C reads Oberon snapshot")
    check(data == (base / "native-roundtrip.state").read_bytes(), "Oberon reads C snapshot")

    cases = []

    def change(label, mutate, valid=False):
        modified = deepcopy(image)
        mutate(modified)
        cases.append((label, encode(modified), valid))

    def top(key, value):
        change(f"header {key}={value}", lambda item: item.__setitem__(key, value))

    top("magic", "BAREVPS2")
    top("owner", "0" * 64)
    for key, values in (("node_limit", [0, 2, 17, 0xffffffff]), ("post_limit", [0, 3, 257, 0xffffffff]),
                        ("byte_limit", [0, 1, 4194305, 0xffffffff])):
        for value in values:
            top(key, value)
    for model in (0, 4, 0xffffffff):
        change(f"model {model}", lambda item, value=model: item["nodes"][0].__setitem__("model", value))
    change("public names", lambda item: item["nodes"][0].__setitem__("names", ["reader@200::2"]))
    change("duplicate node", lambda item: item["nodes"][1].__setitem__("name", "public"))
    change("duplicate canonical member", lambda item: item["nodes"][1].__setitem__("names", ["reader@200::2", "reader@0200:0:0:0:0:0:0:2"]))
    change("bad member", lambda item: item["nodes"][1].__setitem__("names", ["reader@example.org"]))
    change("duplicate group", lambda item: item["nodes"][2].__setitem__("names", ["friends", "friends"]))
    change("excess groups", lambda item: item["nodes"][2].__setitem__("names", [f"group-{n}" for n in range(17)]))
    change("bad group", lambda item: item["nodes"][2].__setitem__("names", ["a\x85b"]))
    change("NUL node", lambda item: item["nodes"][0].__setitem__("name", b"pub\0lic"))
    for field, values in (("node", [3, 0xffffffff]), ("state", [2, 0xffffffff]),
                          ("item", ["bad item", "", "x" * 129]), ("id", ["relative", "urn:%00", "urn:%xx", "urn:bad id"]),
                          ("author", ["Ani@example.org", "Ani@::1"]), ("title", [b"bad\0title", b"\xed\xa0\x80"]),
                          ("published", ["0000-01-01T00:00:00Z", "2026-02-29T00:00:00Z"]),
                          ("updated", ["2026-11-19T23:59:59Z", "2026-11-20T00:00:60Z"]),
                          ("parent", ["relative", "urn:post:1"]), ("body", ["", b"\x01", b"\xef\xbf\xbe", b"\xc0\xaf"])):
        for value in values:
            change(f"post {field}={value!r}", lambda item, key=field, v=value: item["posts"][0].__setitem__(key, v))
    change("duplicate item", lambda item: item["posts"][1].__setitem__("item", "post-1"))
    change("duplicate Atom ID", lambda item: item["posts"][1].__setitem__("id", "urn:post:1"))
    change("duplicate tombstone", lambda item: item["posts"][3].__setitem__("item", "post-1"))
    change("private parent exposure", lambda item: item["posts"][2].__setitem__("parent", "urn:post:2"))

    def cycle(item):
        item["posts"][0]["parent"] = "urn:post:2"
        item["posts"][1]["parent"] = "urn:post:1"

    change("reply cycle", cycle)
    change("private reply to public", lambda item: item["posts"][1].__setitem__("parent", "urn:post:1"), True)
    change("updated revision", lambda item: item["posts"][0].__setitem__("updated", "2026-11-20T00:00:01Z"), True)
    change("maximum group label", lambda item: item["nodes"][2].__setitem__("names", ["x" * 256]), True)
    change("empty private audience", lambda item: item["nodes"][1].__setitem__("names", []), True)
    change("maximum groups", lambda item: item["nodes"][2].__setitem__("names", [f"group-{n}" for n in range(16)]), True)
    change("maximum whitelist", lambda item: item["nodes"][1].__setitem__("names", [f"reader-{n}@200::2" for n in range(256)]), True)
    change("canonical author alias", lambda item: item["posts"][0].__setitem__("author", "Անի@0200:0:0:0:0:0:0:1"), True)
    change("untitled Unicode body", lambda item: item["posts"][0].update(title="", body="Բարեւ <world> & 😀\r\n\t"), True)
    for reference in ("tag:example.org,2026:post-1", "https://example.org/posts/1?x=1#reply", "http:relative",
                      "file:/tmp/post", "file:relative", "data:text/plain,hello", "xmpp:ani@example.org?message",
                      "x:/", "x://", "x:?", "x:value#", "urn:post:%ff", "urn:" + "x" * 1020):
        change(f"absolute reference {reference}", lambda item, value=reference: item["posts"][0].__setitem__("id", value), True)
    for reference in ("1scheme:value", "x:bad%0", "x:bad%00", "x:/[bad]", "http://[200::1]/", "x:value#y#z", "urn:" + "x" * 1021):
        change(f"invalid reference {reference}", lambda item, value=reference: item["posts"][0].__setitem__("id", value))
    for cut in (0, 1, 3, 4, 8, 12, 100, len(data)-4, len(data)-1):
        cases.append((f"truncation {cut}", data[:cut], False))
    cases.append(("trailing bytes", data + b"x", False))
    cases.append(("bad checksum", data[:-1] + bytes([data[-1] ^ 1]), False))
    for label, contents, valid in cases:
        path = base / "candidate.state"
        path.write_bytes(contents)
        try:
            c_result = run(c_tool, "--check", path).strip()
            native_result = run(native / "PostSnapshotInterop", "--check", path).strip()
        except subprocess.CalledProcessError as error:
            raise AssertionError((label, error.returncode, error.output)) from error
        check(c_result == native_result == ("0" if valid else "1"), (label, c_result, native_result))
        if valid:
            run(c_tool, "--roundtrip", path, base / "c-valid.state")
            run(native / "PostSnapshotInterop", "--roundtrip", path, base / "native-valid.state")
            check((base / "c-valid.state").read_bytes() == (base / "native-valid.state").read_bytes(), (label, "canonical snapshot bytes"))

print(f"C/Oberon posts: 2295 validator decisions agree; {checks} snapshot/interoperability checks passed")
