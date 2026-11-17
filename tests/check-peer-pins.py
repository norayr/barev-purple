#!/usr/bin/env python3
"""Peer pin persistence and cross-implementation format checks."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    tools = [str(Path(p).resolve()) for p in sys.argv[1:]]
    if not tools:
        raise SystemExit("usage: check-peer-pins.py TEST-EXECUTABLE [TEST-EXECUTABLE ...]")
    own = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    first = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    second = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    peer = "Bob@200::1"
    checks = 0

    def run(tool, root, contact=peer, local=own, expected=None, replacement=None, status=0):
        nonlocal checks
        args = [tool, str(root), local, contact]
        if expected is not None:
            args += [expected, replacement]
        result = subprocess.run(args, text=True, capture_output=True, timeout=15)
        assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
        lines = result.stdout.splitlines()
        assert lines and lines[0] == str(status), (args, lines, status, result.stderr)
        if expected is None and status == 0:
            assert len(lines) == 3 and len(lines[1]) == 64, lines
            assert lines[2] == "SHA256:" + hashlib.sha256(bytes.fromhex(lines[1])).hexdigest(), lines
        else:
            assert len(lines) == 1, lines
        checks += 1
        return lines

    def filename(root, contact=peer, local=own):
        digest = hashlib.sha256(b"Barev peer pin v1\n" + bytes.fromhex(local) + contact.encode()).hexdigest()
        return root / "barev" / ("peer-" + digest + ".pin"), bytes.fromhex(digest)

    with tempfile.TemporaryDirectory(prefix="barev-pins-") as directory:
        base = Path(directory)
        for index, tool in enumerate(tools):
            root = base / str(index)
            (root / "barev").mkdir(parents=True, mode=0o700)
            run(tool, root, status=1)
            assert not list((root / "barev").iterdir())
            run(tool, root, expected="", replacement=first.upper())
            path, digest = filename(root)
            record = b"BAREVPN1" + bytes.fromhex(own) + digest + bytes.fromhex(first)
            assert path.read_bytes() == record
            for other in tools:
                assert run(other, root)[1] == first
                assert run(other, str(root)+"/", contact="Bob@AI-E.BAREV.V6.ALT.")[1] == first
                run(other, root, contact="bob@200::1", status=1)
                run(other, root, local=second, status=1)
                run(other, root, expected="", replacement=second, status=4)
                run(other, root, expected=second, replacement=first, status=4)
                assert path.read_bytes() == record
            for bad in ("", "x", first+"0", "g"*64):
                run(tool, root, expected=first, replacement=bad, status=2)
                assert path.read_bytes() == record
            for bad in ("", "Bob", "../Bob@200::1", "Bob@::1", "Bob@200::1/extra"):
                run(tool, root, contact=bad, status=2)
            run(tool, root, expected=first.upper(), replacement=second)
            for other in tools:
                assert run(other, root)[1] == second
                run(other, root, expected=first, replacement=first, status=4)
                run(other, root, expected=second, replacement=second)
            run(tool, root, contact="Ալիս@200::2", expected="", replacement=first)
            for other in tools:
                assert run(other, root, contact="Ալիս@200::2")[1] == first
            original = path.read_bytes()
            for malformed in (b"", original[:-1], original+b"x", b"X"+original[1:],
                              original[:8]+b"x"*32+original[40:], original[:40]+b"x"*32+original[72:]):
                path.write_bytes(malformed)
                for other in tools:
                    run(other, root, status=2)
                    run(other, root, expected="", replacement=first, status=2)
                    assert path.read_bytes() == malformed
            path.unlink()
            path.mkdir()
            for other in tools:
                run(other, root, status=3)
            path.rmdir()
            outside = root / "outside"
            outside.write_bytes(original)
            path.symlink_to(outside)
            for other in tools:
                run(other, root, status=3)
            path.unlink()
            os.mkfifo(path)
            for other in tools:
                run(other, root, status=3)
            path.unlink()
            assert outside.read_bytes() == original
            assert not list((root / "barev").glob("*.tmp.*"))
    print(f"Peer pin storage: {checks} checks passed across {len(tools)} implementation(s)")


if __name__ == "__main__":
    main()
