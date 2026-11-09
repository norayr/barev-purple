#!/usr/bin/env python3
"""Run parser regressions without listeners or real peer connections."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="barev-parser-", dir=Path(sys.argv[1]).resolve().parent) as profile:
    environment = dict(os.environ, HOME=profile, XDG_CONFIG_HOME=profile,
                       XDG_CACHE_HOME=profile, XDG_DATA_HOME=profile,
                       G_DEBUG="fatal-criticals", GST_PLUGIN_SYSTEM_PATH_1_0="",
                       GST_PLUGIN_PATH_1_0="", GST_REGISTRY_1_0=os.path.join(profile, "gst.bin"))
    environment.pop("DBUS_SESSION_BUS_ADDRESS", None)
    subprocess.run([sys.argv[1], profile, sys.argv[2]], check=True, timeout=30, env=environment)
