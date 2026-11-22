#!/usr/bin/env python3
"""Exercise asynchronous post checkpoints in disposable fresh processes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

tool = Path(sys.argv[1]).resolve()
owner = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
with tempfile.TemporaryDirectory(prefix="post-async-", dir=tool.parent) as directory:
    base = Path(directory)
    env = dict(os.environ, HOME=str(base), XDG_CONFIG_HOME=str(base), XDG_DATA_HOME=str(base), XDG_CACHE_HOME=str(base))
    for mode in ("new", "verify", "invalid", "missing"):
        profile = base / "profile"
        profile.mkdir(mode=0o700, exist_ok=True)
        path = profile / "barev" / f"posts-{owner}.state"
        if mode == "invalid":
            data = bytearray(path.read_bytes())
            data[-1] ^= 1
            path.write_bytes(data)
        elif mode == "missing":
            path.unlink()
        result = subprocess.run([str(tool), str(profile), mode], env=env, text=True,
                                capture_output=True, timeout=60)
        assert result.returncode == 0, (mode, result.stdout, result.stderr)
        print(result.stdout, end="")
