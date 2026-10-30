#!/usr/bin/env python3
"""Run cache fixtures with a disposable libpurple profile."""
import subprocess
import os
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="barev-avatar-cache-") as profile:
    subprocess.run([sys.argv[1], profile, sys.argv[2]], check=True,
                   env=dict(os.environ, G_DEBUG="fatal-criticals"))
