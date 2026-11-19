#!/usr/bin/env python3
"""Embed the D-Bus introspection document as a C string literal."""
import json
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
destination.write_text(json.dumps(source.read_text()) + "\n")
