# dark-factory M3a — Digital Twins (minimal viable) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build the second verification pillar — a **digital-twin universe** — so dark-factory can handle tasks whose code talks to external services. The supervisor launches behavioral twin services, exposes each to the builder and the scenario runner via a `DF_TWIN_<NAME>` env var, gives the verifier a **freshly reset** twin per verify phase, tears them down at every terminal, and labels results **twin-observed** with a fidelity note. Barrier and exit-code contracts are unchanged.

**Architecture:** A twin is a launchable process defined by `<control_root>/twins/<name>.json`. `df_twins.py` starts it, waits for readiness via an **endpoint file** the twin writes (`$DF_ENDPOINT_FILE` → `host:port`), returns `{name: endpoint}`, and can `reset` (stop+start a fresh instance for deterministic state) and `stop` (teardown). The supervisor starts twins before BUILD (shared dev instance — the builder develops against them) and **resets them fresh before each VERIFY** (deterministic verification), injecting `DF_TWIN_<NAME>=<endpoint>` into both the builder adapter's env and each scenario's execution env; twins are torn down at every terminal and on error. Twins run **outside** the OS sandbox; the sandboxed candidate reaches them over localhost (the `standard` profile allows network), so cross-tier and cross-model builders inherit twin access with no change.

**Honest scope (M3a):** ONE twin definition is shared between builder (dev stub) and verifier. Spec §5.2 wants **verifier-only hidden variants** chosen post-freeze — that requires the orchestrator/verifier to hold twins the builder can't see, which (like enforced skill allowlists) needs the sandboxed-orchestrator machinery of `hardened`/`enterprise`. M3a ships the shared-twin universe honestly labeled ("dev-shared twin — not an independent verifier variant"), and defers hidden variants + fidelity *scoring* to M3b/M5. Results are labeled **twin-observed**, never "production-verified"; a human-gated real check stays a documented rule.

**Tech Stack:** Python ≥ 3.9 stdlib only at runtime (twins/df_twins use `subprocess`, `os`, `socket`, `time`, `json`, `signal`; the fixture twin uses `http.server`). pytest for tests. No new deps.

**Source spec:** `…/2026-07-13-dark-factory-skill-design.md` §5.2 (digital twins, split visibility, fidelity, human-gated real check), §4 role table.

## Global Constraints

- **Runtime code is Python stdlib only.** Tests run `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.
- **Twins are optional and self-contained:** a control root with no `twins/` dir (or an empty `twins` config) runs exactly as today. Absence is never an error.
- **Barrier unchanged:** twin definitions live in the SHARED plane (builder may read/use them — they are dev stubs, like `spec.md`). They are NOT holdout. Scenario files remain the only holdout; nothing in this milestone routes scenario content anywhere new.
- **Exit-code invariance:** twin lifecycle (start/reset/stop) is side-effect infrastructure and must NEVER change the run's exit code (0/2/3/10). A twin that fails to start before BUILD/VERIFY is a real run failure → abort with exit 2 and a journaled `TWIN_ERROR` (this is a legitimate build-precondition failure, not a silent pass). Teardown failures are journaled and swallowed.
- **Deterministic teardown:** every terminal and every error path stops all twins (no orphaned processes). Use a `try/finally` around the loop so twins are always reaped.
- **Results are twin-observed:** never claim production fidelity. The manifest/report label stays honest.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_config.py                # Task 1 — validate + inject twins config as cfg["_twins"]
    df_twins.py                 # Task 2 — launch/ready/reset/stop + endpoint env map
    run_scenarios.py            # Task 3 — inject DF_TWIN_* env into scenario execution
    supervisor.py               # Task 4 — twin lifecycle around build/verify; teardown
  references/
    digital-twins.md            # Task 5 — twin def schema + fidelity + human-gated real check
    config-reference.md         # Task 1 — twins rows
  SKILL.md                      # Task 5 — twins authoring step + honesty
  tests/
    fixtures/twin_greeter       # Task 2 — stdlib http twin: writes endpoint file, serves greeting
    test_twins_config.py        # Task 1
    test_df_twins.py            # Task 2
    test_oracle_twins.py        # Task 3
    test_supervisor_twins.py    # Task 4
    test_e2e_twins.py           # Task 6
```

Control plane (per project): `<control_root>/twins/<name>.json` — a twin definition (Task 2 schema).

---

### Task 1: `twins` config block + twin-def discovery

**Files:**
- Modify: `dark-factory/scripts/df_config.py`
- Modify: `dark-factory/references/config-reference.md`
- Create: `dark-factory/tests/test_twins_config.py`

**Interfaces:**
- Produces: `cfg["_twins"]` — `{"enabled": bool, "startup_timeout_s": int}`. Absent `twins` block → `{"enabled": False, "startup_timeout_s": 20}`. If present: `enabled` must be bool (default True when the block exists), `startup_timeout_s` an int 1..120 (default 20). The actual twin *definitions* are discovered by df_twins from `<control_root>/twins/*.json` at runtime — config only carries the toggle + timeout. When `enabled` is True the control root MUST contain a `twins/` directory with ≥1 `*.json` (else `ConfigError` — enabling twins with none defined is a config error).

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_twins_config.py`:

```python
import json

import pytest

import df_config
from test_config import write_config


def _twindir(cr, n=1):
    d = cr / "twins"; d.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (d / f"t{i}.json").write_text("{}", encoding="utf-8")


def test_absent_twins_defaults_disabled(tmp_path):
    cr = tmp_path / "control"; write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_twins"] == {"enabled": False, "startup_timeout_s": 20}


def test_enabled_requires_twin_defs(tmp_path):
    cr = tmp_path / "control"; write_config(cr, twins={"enabled": True})
    with pytest.raises(df_config.ConfigError, match="twins"):
        df_config.load_config(str(cr))


def test_enabled_with_defs_ok(tmp_path):
    cr = tmp_path / "control"; write_config(cr, twins={"enabled": True, "startup_timeout_s": 30})
    _twindir(cr, 2)
    cfg = df_config.load_config(str(cr))
    assert cfg["_twins"] == {"enabled": True, "startup_timeout_s": 30}


def test_startup_timeout_bounds(tmp_path):
    cr = tmp_path / "control"; _twindir(cr)
    for bad in (0, 121, "5", True):
        write_config(cr, twins={"enabled": True, "startup_timeout_s": bad})
        with pytest.raises(df_config.ConfigError, match="startup_timeout_s"):
            df_config.load_config(str(cr))


def test_enabled_must_be_bool(tmp_path):
    cr = tmp_path / "control"; _twindir(cr)
    write_config(cr, twins={"enabled": "yes"})
    with pytest.raises(df_config.ConfigError, match="enabled"):
        df_config.load_config(str(cr))
```

- [ ] **Step 2: Verify fail** — `.venv/bin/python -m pytest dark-factory/tests/test_twins_config.py -v` → FAIL (`KeyError: '_twins'`).

- [ ] **Step 3: Implement in `df_config.py`**

Following the file's established pattern (validate before the final cfg injection), add:

```python
    tw_raw = raw.get("twins", {})
    if not isinstance(tw_raw, dict):
        raise ConfigError("twins must be an object")
    tw_enabled = tw_raw.get("enabled", bool(tw_raw))  # present-but-no-enabled → True
    if not isinstance(tw_enabled, bool):
        raise ConfigError("twins.enabled must be a bool")
    tw_timeout = tw_raw.get("startup_timeout_s", 20)
    if not isinstance(tw_timeout, int) or isinstance(tw_timeout, bool) or not (1 <= tw_timeout <= 120):
        raise ConfigError("twins.startup_timeout_s must be an int in 1..120")
    if tw_enabled:
        tdir = os.path.join(control_root, "twins")
        if not os.path.isdir(tdir) or not [n for n in os.listdir(tdir) if n.endswith(".json")]:
            raise ConfigError("twins.enabled is true but no twins/*.json definitions found")
```

Inject: `cfg["_twins"] = {"enabled": tw_enabled, "startup_timeout_s": tw_timeout}`.

Add `config-reference.md` rows:

```markdown
| `twins.enabled` | bool | default false. When true, the supervisor launches the twin services defined in `<control_root>/twins/*.json` around build/verify and exposes each as `DF_TWIN_<NAME>`. Requires ≥1 twin def. |
| `twins.startup_timeout_s` | int | 1..120, default 20. Max seconds to wait for a twin to write its endpoint file before the run aborts (exit 2). |
```

- [ ] **Step 4: Verify pass + full suite** — `140 + 5 new = 145 passed, 1 skipped`.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/df_config.py dark-factory/references/config-reference.md dark-factory/tests/test_twins_config.py
git commit -m "feat(dark-factory): optional twins config toggle + def discovery

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: `df_twins.py` — launch / ready / reset / stop + fixture twin

**Files:**
- Create: `dark-factory/scripts/df_twins.py`
- Create: `dark-factory/tests/fixtures/twin_greeter` (executable)
- Create: `dark-factory/tests/test_df_twins.py`

**Interfaces:**
- Twin definition `<control_root>/twins/<name>.json`: `{"twin_version":"0.1","name":"greeter","launch":["<cmd>",...],"env_var":"DF_TWIN_GREETER","fidelity":"dev-shared mock; not a production contract"}`. `name` must match `^[a-z][a-z0-9_]{0,30}$`; `env_var` defaults to `DF_TWIN_<NAME_UPPER>`.
- The launched process receives env `DF_ENDPOINT_FILE=<path>`; it MUST write its `host:port` (one line) to that path once ready to accept connections, then keep running.
- Produces:
  - `df_twins.TwinError(RuntimeError)`.
  - `df_twins.load_defs(twins_dir) -> list[dict]` — validated defs sorted by name; raises `TwinError` on bad shape / duplicate name / bad name.
  - `df_twins.TwinSet` — a handle managing running twins:
    - `TwinSet.start(defs, run_dir, timeout_s) -> dict[env_var, endpoint]` — launches each twin (cwd = run_dir), each with a unique `DF_ENDPOINT_FILE` under `run_dir/twins/<name>.endpoint`; polls (0.05s) up to `timeout_s` for every endpoint file; on timeout stops all and raises `TwinError`. Returns the env map `{env_var: "host:port"}`.
    - `TwinSet.reset(defs, run_dir, timeout_s) -> dict` — stop all, then start fresh (deterministic clean state); returns a new env map.
    - `TwinSet.stop() -> None` — terminate every child (SIGTERM, then SIGKILL after 3s), reap, never raise.
    - `TwinSet.env` — the current env map (or `{}`).

- [ ] **Step 1: Write the fixture twin + failing tests**

`dark-factory/tests/fixtures/twin_greeter`:

```python
#!/usr/bin/env python3
"""A stdlib HTTP twin for tests. Binds an ephemeral port, writes host:port to
$DF_ENDPOINT_FILE, then serves GET /greet/<name> -> 'Hello, <name>!' (200).
Behavioral mock of a 'greeter service' — never a production contract."""
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/greet/"):
            name = self.path[len("/greet/"):]
            body = f"Hello, {name}!".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *a):  # quiet
        pass


def main():
    srv = HTTPServer(("127.0.0.1", 0), H)
    host, port = srv.server_address
    ep = os.environ.get("DF_ENDPOINT_FILE")
    if ep:
        with open(ep, "w", encoding="utf-8") as f:
            f.write(f"{host}:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
```

`dark-factory/tests/test_df_twins.py`:

```python
import json
import os
import socket
import urllib.request

import pytest

import df_twins

HERE = os.path.dirname(os.path.abspath(__file__))
GREETER = os.path.join(HERE, "fixtures", "twin_greeter")


def write_def(twins_dir, name="greeter", **over):
    twins_dir.mkdir(parents=True, exist_ok=True)
    d = {"twin_version": "0.1", "name": name,
         "launch": ["python3", GREETER], "fidelity": "dev mock"}
    d.update(over)
    (twins_dir / f"{name}.json").write_text(json.dumps(d), encoding="utf-8")
    return d


def test_load_defs_validates_and_defaults_env_var(tmp_path):
    write_def(tmp_path / "twins")
    defs = df_twins.load_defs(str(tmp_path / "twins"))
    assert defs[0]["name"] == "greeter" and defs[0]["env_var"] == "DF_TWIN_GREETER"


def test_load_defs_rejects_bad_name(tmp_path):
    write_def(tmp_path / "twins", name="Bad-Name")
    with pytest.raises(df_twins.TwinError, match="name"):
        df_twins.load_defs(str(tmp_path / "twins"))


def test_start_returns_reachable_endpoint(tmp_path):
    defs = [write_def(tmp_path / "twins")]
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        env = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
        assert set(env) == {"DF_TWIN_GREETER"}
        host, port = env["DF_TWIN_GREETER"].split(":")
        body = urllib.request.urlopen(f"http://{host}:{port}/greet/World", timeout=5).read().decode()
        assert body == "Hello, World!"
    finally:
        ts.stop()


def test_reset_gives_a_fresh_running_endpoint(tmp_path):
    write_def(tmp_path / "twins")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        env1 = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
        env2 = ts.reset(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
        # reachable after reset
        h, p = env2["DF_TWIN_GREETER"].split(":")
        assert urllib.request.urlopen(f"http://{h}:{p}/greet/X", timeout=5).status == 200
    finally:
        ts.stop()


def test_stop_reaps_processes(tmp_path):
    write_def(tmp_path / "twins")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    env = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
    host, port = env["DF_TWIN_GREETER"].split(":")
    ts.stop()
    # port no longer accepts connections
    s = socket.socket(); s.settimeout(1)
    with pytest.raises((ConnectionRefusedError, OSError)):
        s.connect((host, int(port)))
    s.close()


def test_start_times_out_when_endpoint_never_written(tmp_path):
    # a launch that never writes the endpoint file
    write_def(tmp_path / "twins", launch=["python3", "-c", "import time; time.sleep(30)"])
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        with pytest.raises(df_twins.TwinError, match="timeout|ready"):
            ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 1)
    finally:
        ts.stop()
```

```bash
chmod +x dark-factory/tests/fixtures/twin_greeter
```

- [ ] **Step 2: Verify fail** — `ModuleNotFoundError: No module named 'df_twins'`.

- [ ] **Step 3: Implement `df_twins.py`**

`dark-factory/scripts/df_twins.py`:

```python
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
```

- [ ] **Step 4: Verify pass** — `.venv/bin/python -m pytest dark-factory/tests/test_df_twins.py -v` (6 passed). Full suite: `151 passed, 1 skipped`.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/df_twins.py dark-factory/tests/fixtures/twin_greeter dark-factory/tests/test_df_twins.py
git commit -m "feat(dark-factory): digital-twin lifecycle (launch/ready/reset/stop) + http fixture

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Inject twin env into scenario execution

**Files:**
- Modify: `dark-factory/scripts/run_scenarios.py`
- Create: `dark-factory/tests/test_oracle_twins.py`

**Interfaces:**
- `run_scenarios.run_scenario(sc, workspace, env_extra=None)` and `run_all(scenarios_dir, workspace, exec_wrapper=None, env_extra=None)` gain an optional `env_extra: dict` — extra env vars (the `DF_TWIN_*` map) merged over `os.environ` for the scenario subprocess. Default `None` → behaves exactly as today (no env change). This lets a scenario's `when.run` command reach the twins.

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_oracle_twins.py`:

```python
import json
import os

import run_scenarios


def sc(tmp, **then):
    return {"ir_version": "0.1", "id": "BHV-001-S1", "behavior_id": "BHV-001",
            "title": "t", "given": "g",
            "when": {"run": ["python3", "readenv.py"], "timeout_s": 10},
            "then": then}


def ws_with_reader(tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    # prints the twin env var it was given
    (ws / "readenv.py").write_text(
        "import os; print(os.environ.get('DF_TWIN_GREETER', 'MISSING'))\n", encoding="utf-8")
    return ws


def test_env_extra_reaches_scenario(tmp_path):
    ws = ws_with_reader(tmp_path)
    r = run_scenarios.run_scenario(
        sc(tmp_path, exit_code=0, stdout_equals="127.0.0.1:9"),
        str(ws), env_extra={"DF_TWIN_GREETER": "127.0.0.1:9"})
    assert r["observed"]["stdout"].strip() == "127.0.0.1:9"


def test_no_env_extra_is_unchanged(tmp_path):
    ws = ws_with_reader(tmp_path)
    r = run_scenarios.run_scenario(sc(tmp_path, exit_code=0, stdout_equals="MISSING"), str(ws))
    assert r["observed"]["stdout"].strip() == "MISSING"
```

- [ ] **Step 2: Verify fail** — TypeError (`run_scenario` has no `env_extra`).

- [ ] **Step 3: Implement**

In `run_scenarios.py`, thread `env_extra` through. In `run_scenario`, build the subprocess env:

```python
def run_scenario(sc, workspace, exec_wrapper=None, env_extra=None):
    ...
    env = None
    if env_extra:
        env = dict(os.environ, **env_extra)
    ...
        proc = subprocess.run(cmd, cwd=workspace, capture_output=True, text=True,
                              timeout=timeout, env=env)
```

(Preserve the existing `exec_wrapper` handling from M2b — if the current signature is `run_scenario(sc, workspace, exec_wrapper=None)`, add `env_extra=None` after it. Match the current signature exactly; read the file first.) Thread `env_extra` from `run_all(..., env_extra=None)` into each `run_scenario` call.

- [ ] **Step 4: Verify pass + full suite** — `153 passed, 1 skipped`.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/run_scenarios.py dark-factory/tests/test_oracle_twins.py
git commit -m "feat(dark-factory): scenario runner accepts twin env injection

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Supervisor twin lifecycle around build/verify

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Create: `dark-factory/tests/test_supervisor_twins.py`

**Interfaces:**
- Read the current `supervisor.py` first (`_run_loop`, `invoke_adapter`, the `run_all(...)` call, the terminals).
- When `cfg["_twins"]["enabled"]`: in `_run_loop`, create a `df_twins.TwinSet` and load defs from `<control_root>/twins/`. Wrap the per-iteration body in a `try/finally` that calls `twins.stop()` at the end (every terminal + exception path). Before the builder runs, ensure twins are started (once, shared dev instance) and pass the env map to `invoke_adapter` (extend it to accept `env_extra` merged into the adapter subprocess env). Before each VERIFY, `twins.reset(...)` for a fresh deterministic instance and pass the fresh env map to `run_all(..., env_extra=...)`. A `TwinError` at start/reset → journal `TWIN_ERROR`, finalize an `ABORTED_BUILD_ERROR` manifest, return 2 (a build-precondition failure — NOT a silent pass). Twin lifecycle must not change any other exit code.
- Pass `control_root` into `_run_loop` (or derive it) so it can find `twins/` — check how `_run_loop` currently receives paths.

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_supervisor_twins.py`:

```python
import json
import os

import supervisor
from test_supervisor import setup_control  # existing helper

HERE = os.path.dirname(os.path.abspath(__file__))
GREETER = os.path.join(HERE, "fixtures", "twin_greeter")
FAKE_TWIN_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_twin")


def _twin_control(tmp_path, adapter, **cfg_over):
    cr = setup_control(tmp_path, adapter, checkpoint="auto", **cfg_over)
    (cr / "twins").mkdir()
    (cr / "twins" / "greeter.json").write_text(json.dumps(
        {"twin_version": "0.1", "name": "greeter", "launch": ["python3", GREETER],
         "fidelity": "dev mock"}), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"] = {"enabled": True, "startup_timeout_s": 20}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def test_twin_enabled_run_converges_and_reaps(tmp_path):
    # FAKE_TWIN_BUILDER writes greet.py that GETs the twin and prints the greeting
    cr = _twin_control(tmp_path, FAKE_TWIN_BUILDER)
    # spec + scenarios that exercise the twin are set by the fixture-aware setup; see Step 3
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    run_id = os.listdir(cr / "runs")[0]
    j = (cr / "runs" / run_id / "journal.jsonl").read_text()
    assert "TWIN_ERROR" not in j


def test_twin_startup_failure_aborts_exit_2(tmp_path):
    cr = _twin_control(tmp_path, FAKE_TWIN_BUILDER)
    # break the twin: launch never writes endpoint
    (cr / "twins" / "greeter.json").write_text(json.dumps(
        {"twin_version": "0.1", "name": "greeter",
         "launch": ["python3", "-c", "import time;time.sleep(60)"]}), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"]["startup_timeout_s"] = 1
    (cr / "config.json").write_text(json.dumps(cfg))
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    run_id = os.listdir(cr / "runs")[0]
    j = (cr / "runs" / run_id / "journal.jsonl").read_text()
    assert "TWIN_ERROR" in j
```

(Task 4 also creates the `fake_builder_twin` fixture and a twin-aware variant of `setup_control` OR reuses `setup_control` and overwrites `spec.md`/scenarios in `_twin_control` to a twin-using toy. Implement whichever is cleaner; the toy: spec = "write greet.py that reads env DF_TWIN_GREETER and prints `curl http://$DF_TWIN_GREETER/greet/<argv1>`"; scenarios assert `greet.py World` prints `Hello, World!`. The fixture `fake_builder_twin` writes the correct greet.py directly on the first iteration.)

- [ ] **Step 2–4:** Read supervisor.py; implement the lifecycle (start before build, reset before verify, `try/finally` stop, `TWIN_ERROR`→exit 2); create `fixtures/fake_builder_twin` (writes a `greet.py` that GETs the twin) and wire the twin-using toy spec/scenarios in `_twin_control`. Verify the two tests pass, then the full suite (existing 153 stay green — twin-disabled runs are unaffected because the whole block is gated on `cfg["_twins"]["enabled"]`).

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/supervisor.py dark-factory/tests/test_supervisor_twins.py dark-factory/tests/fixtures/fake_builder_twin
git commit -m "feat(dark-factory): supervisor twin lifecycle (start/reset/reap) around build+verify

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Fidelity labeling + docs (digital-twins.md, SKILL.md)

**Files:**
- Create: `dark-factory/references/digital-twins.md`
- Modify: `dark-factory/SKILL.md`

**Interfaces:** docs + an honest label. The twin `fidelity` string is surfaced in the run report (Task 4 may already journal it); ensure `references/digital-twins.md` states: twins are **dev-shared behavioral mocks**, results are **twin-observed** (never production-verified), verifier-only hidden variants + fidelity *scoring* are deferred to a later milestone, and a **human-gated real contract/staging check** is required before calling anything ship-ready.

- [ ] **Step 1:** Write `references/digital-twins.md` (schema of `twins/<name>.json`, the `DF_TWIN_<NAME>` env contract, the endpoint-file readiness protocol, the honest scope + human-gated real check).
- [ ] **Step 2:** Add a SKILL.md workflow note: if the task's code talks to external services, define twins in `<control_root>/twins/*.json` and set `twins.enabled`; the builder develops against them and the verifier resets them fresh; results are twin-observed — require a real check before shipping.
- [ ] **Step 3:** Verify docs match code; full suite unchanged; commit `docs(dark-factory): digital-twins reference + SKILL.md twins step`.

---

### Task 6: E2E — a twin-using task builds and verifies (holdout still denied under standard)

**Files:**
- Create: `dark-factory/tests/test_e2e_twins.py`

**Interfaces:** drives the supervisor CLI as a subprocess on a twin-using toy, asserting: (a) CONVERGES; (b) the built `greet.py` actually calls the twin (its output is the twin's `Hello, <name>!`); (c) no twin processes remain after (ports closed); (d) under `assurance: standard` (skipif backend), the run still converges qualified AND a `cat` of a real holdout scenario file through the sandbox is OS-denied — i.e. twins + OS isolation compose. If codex/sandbox unavailable, the standard-tier assertion is guarded/skipped like other real-sandbox tests.

- [ ] **Step 1:** Write the e2e test (cooperative path always; standard path backend-guarded). **Step 2:** run it; if it fails, a real earlier-task defect exists — report BLOCKED, don't weaken. **Step 3:** full suite green. **Step 4:** commit `test(dark-factory): e2e twin-using task builds+verifies, composes with OS isolation`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M3a):** the digital-twin pillar (§5.2) — a launchable twin universe with endpoint-file readiness, env exposure to builder + scenarios, fresh reset before verify, deterministic teardown at every terminal; twin-startup failure is an honest exit-2 abort (never a silent pass); twins compose with the OS sandbox (candidate reaches localhost twins under `standard`) and with cross-model builders; results honestly **twin-observed**; a human-gated real check documented.

**Deliberately deferred (honest, stated in digital-twins.md):** verifier-only **hidden twin variants** chosen post-freeze (§5.2) — needs the sandboxed-orchestrator machinery of hardened/enterprise, so M3a ships a **dev-shared** twin; per-service **fidelity scoring + drift** (M3b); network-authority separation of twin data-plane vs control-plane (§7.4 hardened+).

**Known honesty notes:** the shared dev-stub twin is correlated with what the verifier uses (Codex R1 finding P0-6) — M3a labels it as such and does not claim independent evidence; that independence is a hardened/enterprise property. Twins run outside the sandbox (they are trusted infra the human defined), reachable by the candidate over localhost only.
```
