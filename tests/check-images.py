#!/usr/bin/env python3
"""Run native image UI tests in a disposable profile without peer connections."""
import os
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="barev-images-", dir=os.environ.get("TMPDIR")) as profile:
    subprocess.run([sys.argv[1], profile, sys.argv[2]], check=True, timeout=30,
                   env=dict(os.environ, G_DEBUG="fatal-criticals",
                            GST_PLUGIN_SYSTEM_PATH_1_0="", GST_PLUGIN_PATH_1_0="",
                            GST_REGISTRY_1_0=os.path.join(profile, "gstreamer-registry.bin")))
