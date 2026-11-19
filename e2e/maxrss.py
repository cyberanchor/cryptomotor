#!/usr/bin/env python3
"""maxrss.py <cmd...> — run a command, then print its wall time and peak RSS to stderr.

The child's exit code is passed through. Output line format:
    [maxrss] rc=<code> wall=<seconds>s maxrss=<MiB>MiB
"""
import resource
import subprocess
import sys
import time

if len(sys.argv) < 2:
    sys.exit("usage: maxrss.py <cmd...>")

t0 = time.monotonic()
rc = subprocess.call(sys.argv[1:])
wall = time.monotonic() - t0
peak_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
print(f"[maxrss] rc={rc} wall={wall:.2f}s maxrss={peak_kib / 1024:.1f}MiB", file=sys.stderr)
sys.exit(rc if rc >= 0 else 128 - rc)
