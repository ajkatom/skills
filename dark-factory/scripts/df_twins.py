"""Digital-twin lifecycle (spec 5.2). Stdlib only.

A twin is a launchable service defined by <control_root>/twins/<name>.json.
The supervisor starts twins around build/verify and exposes each as an env var
(DF_TWIN_<NAME>=host:port). Twins are SHARED dev stubs in this milestone (not
verifier-only hidden variants). Results built against them are 'twin-observed',
never production-verified.

Observation contract (M12): each twin process is handed
DF_OBSERVER_FILE=<run_dir>/twins/<name>.observations.ndjson in its env. A twin
SHOULD append one flushed JSON line per interaction it serves:
{"event": "<short>", "detail": "<short>", "token": "<str, optional>"}. Lines
must be flushed immediately (one write, one flush) so a concurrent reader
never observes a partial line. This is best-effort: a twin that ignores the
env var still works exactly as before -- it simply produces no evidence, so
any verification assertion that requires twin evidence fails closed (no
log => no evidence), while scenarios that don't ask for twin evidence are
unaffected.

Verifier-only variants (M12): callers may pass `extra_env` to `start`/`reset`
(e.g. DF_TWIN_VARIANT_SEED=<per-pass random value>) which is merged into each
twin's child environment. Twins that support it (see `supports_variants` on
the twin def) derive per-request tokens from the seed so responses are
unpredictable to a builder that never sees the seed (the seed is verifier-only
and must never reach the builder or any feedback channel). Twins that ignore
extra_env behave exactly as they did before it existed.

CAUTION (supervisor-only channel): `extra_env` is merged into `child_env`
AFTER `DF_ENDPOINT_FILE`/`DF_OBSERVER_FILE` (`dict(os.environ,
DF_ENDPOINT_FILE=..., DF_OBSERVER_FILE=..., **(extra_env or {}))`), so an
`extra_env` entry with either of those keys SILENTLY CLOBBERS the endpoint
or observer wiring for that twin process. The supervisor is the only caller
of `start`/`reset` with a non-None `extra_env`, and it must pass ONLY
`DF_TWIN_VARIANT_SEED` -- never `DF_ENDPOINT_FILE` or `DF_OBSERVER_FILE`.
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
        supports_variants = d.setdefault("supports_variants", False)
        if not isinstance(supports_variants, bool):
            raise TwinError(f"{name}: supports_variants must be a bool")
        defs.append(d)
    return defs


class TwinSet:
    def __init__(self):
        self._procs = []      # list[(subprocess.Popen, def, pgid)]
        self.env = {}
        self.observer_files = {}

    def start(self, defs, run_dir: str, timeout_s: int, extra_env: dict = None) -> dict:
        twdir = os.path.join(run_dir, "twins")
        os.makedirs(twdir, exist_ok=True)
        env_map, obs_map, pending = {}, {}, []
        try:
            for d in defs:
                ep_file = os.path.join(twdir, d["name"] + ".endpoint")
                if os.path.exists(ep_file):
                    os.unlink(ep_file)
                obs_file = os.path.join(twdir, d["name"] + ".observations.ndjson")
                child_env = dict(os.environ, DF_ENDPOINT_FILE=ep_file,
                                  DF_OBSERVER_FILE=obs_file, **(extra_env or {}))
                obs_map[d["name"]] = obs_file
                proc = subprocess.Popen(d["launch"], cwd=run_dir, env=child_env,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
                # start_new_session=True makes proc the session/process-group
                # leader, so its pgid == pid at this instant. Capture it NOW,
                # while the child is definitely alive -- resolving it later at
                # stop() time via os.getpgid(proc.pid) can raise
                # ProcessLookupError on macOS if this direct child (e.g. a
                # shell wrapper) has already exited, which would otherwise
                # leak any grandchild it backgrounded in the same group.
                pgid = proc.pid
                self._procs.append((proc, d, pgid))
                pending.append((d, ep_file, proc))
        except OSError as e:
            self.stop()
            raise TwinError(f"failed to launch twin: {e}")
        deadline = time.time() + timeout_s
        for d, ep_file, proc in pending:
            while True:
                # Check readiness before liveness: a direct child (e.g. a shell
                # wrapper) may write the endpoint and then exit immediately
                # (backgrounding a longer-lived grandchild). That is a valid
                # ready state, not a failure, so the endpoint file must win the
                # race against an already-exited direct child.
                if os.path.exists(ep_file) and os.path.getsize(ep_file) > 0:
                    with open(ep_file, encoding="utf-8") as fh:
                        env_map[d["env_var"]] = fh.read().strip()
                    break
                if proc.poll() is not None:
                    self.stop()
                    raise TwinError(f"twin {d['name']!r} exited before ready")
                if time.time() > deadline:
                    self.stop()
                    raise TwinError(f"twin {d['name']!r} not ready within {timeout_s}s (timeout)")
                time.sleep(0.05)
        self.env = env_map
        self.observer_files = obs_map
        return env_map

    def reset(self, defs, run_dir: str, timeout_s: int, extra_env: dict = None) -> dict:
        self.stop()
        return self.start(defs, run_dir, timeout_s, extra_env=extra_env)

    def stop(self) -> None:
        # pgid is captured at start() time (see start()), while each child was
        # definitely alive -- start_new_session=True makes it the process-group
        # leader, so pgid == pid at launch. Signaling/escalating on that
        # captured pgid (rather than re-resolving it here via
        # os.getpgid(proc.pid)) means a direct Popen child (e.g. a shell
        # wrapper) that has ALREADY exited by the time stop() runs does not
        # cause any grandchild it backgrounded in the same process group to
        # leak: os.getpgid() on an exited/zombie pid raises
        # ProcessLookupError on macOS, which used to fall back to
        # proc.terminate() -- signaling only the already-dead direct child.
        for proc, _, pgid in self._procs:
            if pgid is None:
                # Defensive fallback only; pgid is always captured at
                # start() time, so this should not happen in practice.
                try:
                    proc.terminate()
                except (OSError, ProcessLookupError):
                    pass
                continue
            try:
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass

        grace_deadline = time.time() + 3
        for proc, _, pgid in self._procs:
            # Reap the direct child to clear its zombie, whether it already
            # exited on its own or just got SIGTERM'd above.
            try:
                proc.wait(timeout=max(0.0, grace_deadline - time.time()))
            except (subprocess.TimeoutExpired, OSError):
                pass

            if pgid is None:
                try:
                    proc.kill()
                except (OSError, ProcessLookupError):
                    pass
                continue

            try:
                os.killpg(pgid, 0)
            except (ProcessLookupError, PermissionError, OSError):
                # Group is empty (or otherwise gone) -- nothing left to reap,
                # even if the direct child itself exited earlier.
                continue

            # Group still has live members (e.g. a backgrounded grandchild
            # whose leader already exited) -- escalate the whole group.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass

            kill_deadline = time.time() + 2
            while time.time() < kill_deadline:
                try:
                    os.killpg(pgid, 0)
                except (ProcessLookupError, OSError):
                    break
                time.sleep(0.02)

        self._procs = []
        self.env = {}
        self.observer_files = {}
