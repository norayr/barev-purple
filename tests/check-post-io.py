#!/usr/bin/env python3
"""Run worker fault and lifecycle checks with disposable profile storage."""
from pathlib import Path
import subprocess
import sys
import tempfile

tool = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="post-io-", dir=tool.parent) as directory:
    subprocess.run([str(tool), directory], check=True, timeout=60)
