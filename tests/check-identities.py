#!/usr/bin/env python3
"""Local identity persistence, record validation and fingerprint checks."""
import hashlib
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


def main():
    tool = str(Path(sys.argv[1]).resolve())
    checks = 0
    with tempfile.TemporaryDirectory(prefix="barev-identities-") as directory:
        root = Path(directory)/"profile"

        def run(account="alice", expected="", status=0):
            nonlocal checks
            result = subprocess.run([tool, str(root), account, expected], check=True, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            lines = result.stdout.splitlines()
            assert int(lines[0]) == status, (status, lines, result.stderr)
            if not status:
                assert len(lines) == 3 and len(lines[1]) == 64
                assert lines[2] == "SHA256:"+hashlib.sha256(bytes.fromhex(lines[1])).hexdigest()
            checks += 1
            return lines

        first = run()
        public = first[1]
        key = root/"barev/identities"/(public+".key")
        record = key.read_bytes()
        assert len(record) == 72 and record[:8] == b"BAREVID1" and record[40:].hex() == public
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        for folder in (root/"barev", root/"barev/identities", root/"barev/accounts"):
            assert stat.S_IMODE(folder.stat().st_mode) == 0o700
        assert run() == first and run(expected=public) == first
        assert run(account="renamed", expected=public) == first
        link_name = hashlib.sha256(b"Barev account v1\nrenamed").hexdigest()+".identity"
        assert (root/"barev/accounts"/link_name).read_bytes() == b"BAREVAC1"+bytes.fromhex(public)
        other = run(account="bob")
        assert other[1] != public
        run(expected=other[1], status=6)
        for invalid in ("x", "G"*64, public+"0"):
            run(expected=invalid, status=4)
        for account in ("", "x"*257):
            run(account=account, status=3)
        for content, status in ((b"", 1), (record[:-1], 1), (record+b"x", 1),
                                (b"X"+record[1:], 2), (record[:8]+bytes([record[8]^1])+record[9:], 2)):
            key.write_bytes(content)
            run(expected=public, status=status)
            assert key.read_bytes() == content
        key.write_bytes(record)
        key.chmod(0o644); run(expected=public, status=1); key.chmod(0o600)
        key.unlink(); run(expected=public, status=1)
        assert not key.exists()
    print(f"Identity storage: {checks} scenarios passed")


if __name__ == "__main__":
    main()
