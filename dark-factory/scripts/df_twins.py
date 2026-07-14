"""Digital-twin lifecycle (spec 5.2). Stdlib only.

A twin is a launchable service defined by <control_root>/twins/<name>.json.
The supervisor starts twins around build/verify and exposes each as an env var
(DF_TWIN_<NAME>=host:port). Twins are SHARED dev stubs in this milestone (not
verifier-only hidden variants). Results built against them are 'twin-observed',
never production-verified.
"""
import glob
import json
import os
import re
import signal
import subprocess
import time

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")


class TwinError(RuntimeError):
    pass


def load_defs(twins_dir: str) -> list:
    defs, seen = [], set()
    for path in sorted(glob.glob(os.path.join(twins_dir, "*.json"))):
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        if not isinstance(d, dict) or d.get("twin_version") != "0.1":
            raise TwinError(f"{os.path.basename(path)}: twin_version must be '0.1'")
        name = d.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise TwinError(f"{os.path.basename(path)}: invalid twin name {name!r}")
        if name in seen:
            raise TwinError(f"duplicate twin name {name!r}")
        seen.add(name)
        launch = d.get("launch")
        if not isinstance(launch, list) or not launch or not all(isinstance(x, str) for x in launch):
            raise TwinError(f"{name}: launch must be a non-empty list of strings")
        d.setdefault("env_var", "DF_TWIN_" + name.upper())
        defs.append(d)
    return defs


class TwinSet:
    def __init__(self):
        self._procs = []      # list[(subprocess.Popen, def)]
        self.env = {}

    def start(self, defs, run_dir: str, timeout_s: int) -> dict:
        twdir = os.path.join(run_dir, "twins")
        os.makedirs(twdir, exist_ok=True)
        env_map, pending = {}, []
        for d in defs:
            ep_file = os.path.join(twdir, d["name"] + ".endpoint")
            if os.path.exists(ep_file):
                os.unlink(ep_file)
            child_env = dict(os.environ, DF_ENDPOINT_FILE=ep_file)
            proc = subprocess.Popen(d["launch"], cwd=run_dir, env=child_env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._procs.append((proc, d))
            pending.append((d, ep_file, proc))
        deadline = time.time() + timeout_s
        for d, ep_file, proc in pending:
            while True:
                if proc.poll() is not None:
                    self.stop()
                    raise TwinError(f"twin {d['name']!r} exited before ready")
                if os.path.exists(ep_file) and os.path.getsize(ep_file) > 0:
                    env_map[d["env_var"]] = open(ep_file, encoding="utf-8").read().strip()
                    break
                if time.time() > deadline:
                    self.stop()
                    raise TwinError(f"twin {d['name']!r} not ready within {timeout_s}s (timeout)")
                time.sleep(0.05)
        self.env = env_map
        return env_map

    def reset(self, defs, run_dir: str, timeout_s: int) -> dict:
        self.stop()
        return self.start(defs, run_dir, timeout_s)

    def stop(self) -> None:
        for proc, _ in self._procs:
            try:
                proc.terminate()
            except (OSError, ProcessLookupError):
                pass
        deadline = time.time() + 3
        for proc, _ in self._procs:
            try:
                while proc.poll() is None and time.time() < deadline:
                    time.sleep(0.02)
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        self._procs = []
        self.env = {}
