#!/usr/bin/env python3
"""Compare C and Oberon live-audience decisions using independent fixtures."""
from pathlib import Path
import subprocess
import sys

c_tool, native_tool = (Path(value).resolve() for value in sys.argv[1:3])
c = subprocess.check_output([str(c_tool), "--matrix"], text=True, timeout=30)
native = subprocess.check_output([str(native_tool)], text=True, timeout=30)
assert c == native, "C and Oberon audience decisions differ"
rows = c.splitlines()
assert rows[0] == "feed-matrix-v1" and len(rows) == 481
assert all(len(row.split()) == 5 and row.split()[-1] in ("0", "1") for row in rows[1:])
print("C/Oberon feed access: 480 audience decisions agree")
