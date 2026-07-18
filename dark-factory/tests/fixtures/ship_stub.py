#!/usr/bin/env python3
"""Deterministic stub ship action for M41 tests. NO real infra.
Usage: ship_stub.py <mode> [path]
  touch  <path>   -> create file <path>, exit 0
  remove <path>   -> delete file <path> if present, exit 0 (a rollback)
  fail            -> exit 1
  echo-secret     -> print os.environ['SHIP_SECRET'] to stdout, exit 0
  hang            -> sleep forever (for timeout tests)
"""
import os
import sys
import time

mode = sys.argv[1] if len(sys.argv) > 1 else ""
if mode == "touch":
    with open(sys.argv[2], "w") as f:
        f.write("shipped")
elif mode == "remove":
    p = sys.argv[2]
    if os.path.exists(p):
        os.unlink(p)
elif mode == "fail":
    sys.stderr.write("stub: deliberate failure\n")
    sys.exit(1)
elif mode == "echo-secret":
    sys.stdout.write("token=" + os.environ.get("SHIP_SECRET", "<unset>") + "\n")
elif mode == "hang":
    time.sleep(3600)
else:
    sys.stderr.write(f"stub: unknown mode {mode!r}\n")
    sys.exit(2)
