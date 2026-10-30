#!/usr/bin/env python3
"""Check formatting capabilities in a disposable, network-free login fixture."""
import os
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="barev-formatting-") as profile:
    subprocess.run([sys.argv[1], profile, sys.argv[2]], check=True, timeout=30,
                   env=dict(os.environ, G_DEBUG="fatal-criticals",
                            GST_PLUGIN_SYSTEM_PATH_1_0="", GST_PLUGIN_PATH_1_0="",
                            GST_REGISTRY_1_0=os.path.join(profile, "gstreamer-registry.bin")))
