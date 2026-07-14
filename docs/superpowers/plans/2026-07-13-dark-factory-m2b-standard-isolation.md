# dark-factory M2b — Standard-Tier Sandbox Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `standard` a real, selectable, *qualified* assurance tier by running the builder and the candidate under an OS-enforced read-denial sandbox that cannot read the holdout control root — verified at startup by a **fail-closed denial probe**, so a run only *claims* `standard` when isolation is actually proven on this machine.

**Architecture:** An OS-pluggable sandbox layer (`df_sandbox.py`) exposes a per-OS backend whose `wrap_prefix(deny_root, workspace)` returns an argv prefix that denies reads of `deny_root` while leaving `workspace` + system readable/writable. macOS uses `sandbox-exec` (built & verified here); Linux uses `bwrap` (code-complete, probe-gated, unverified on this macOS box); Windows has no backend yet (unsupported → fail closed). A `probe_denial(...)` harness plants a canary in the control root and confirms a wrapped process genuinely *cannot* read it — the safety net that keeps unverified backends honest. The supervisor probes at startup: on success it wraps both the builder adapter invocation and the candidate execution and produces a **qualified** outcome; on failure it **fails closed** (abort, or `--allow-downgrade` → cooperative).

**Tech Stack:** Python ≥ 3.9 stdlib only. `pytest` for tests. Builds on merged M1 + M2a in `dark-factory/`. macOS `sandbox-exec` and Linux `bwrap` are the OS primitives.

**Source spec:** `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md` — §2.2 (assurance tiers), §2.3 (probe-verified, fail-closed, downgrade transaction), §7.1/§7.2 (standard OS read-denial), §7.4 (verification-time isolation), §1.4 (per-tier threat model / qualified). Implements the M2b `standard`-isolation slice. Deferred: dev/final holdout split, coverage gate, mutation validation, mandatory security gates, hardened/enterprise tiers.

## Global Constraints

- **Runtime code is Python stdlib only** — nothing under `dark-factory/scripts/` may import a pip dependency.
- **A tier is claimed only when probe-verified.** `standard` requires (a) an OS backend for this platform that reports `available()`, AND (b) `probe_denial(...)` returning True at startup. If either fails → **fail closed**: abort with exit 2, unless `--allow-downgrade` is passed, which downgrades to `cooperative` (qualified:false) with a loud stderr warning + an audit note. A tier is never a cosmetic label.
- **Read-denial target = the entire control root** (`control_root`), which holds `scenarios/`, `runs/`, `spec.md`, `config.json`. The workspace (`workspace_root`, disjoint from control_root per M1) stays readable/writable.
- **Both the builder AND the candidate run wrapped** at `standard` tier (§7.2 build-time, §7.4 verification-time). At `cooperative` tier nothing is wrapped (unchanged M1/M2a behavior).
- **Qualified honesty:** a `standard` run whose probe passed and which converges is **qualified** — manifest `qualified: true`, `outcome: "COMPLETE_QUALIFIED"`, and **no** "COOPERATIVE MODE" banner. A `cooperative` run is unchanged (`COMPLETE_UNQUALIFIED`, `qualified:false`, banner). A human `accept` remains `ACCEPTED_WAIVED` + forced `qualified:false` regardless of tier (from M2a — do not regress this).
- **New manifest fields:** `sandbox_backend` (str|null) and `denial_probe_passed` (bool|null) recorded in every run's manifest.
- **Exit codes unchanged:** 0 converged/accepted, 2 config/build/abort/lock/probe-fail-closed, 3 cap, 10 paused.
- **Barrier is strengthened, never weakened:** the sandbox is an *additional* enforcement on top of the M1/M2a out-of-tree + spec-only-prompt design; nothing about what crosses into the workspace/prompt/feedback changes.
- **All hashing = SHA-256 over canonical JSON.**
- **Platform-gated tests:** macOS-only functional sandbox tests use `@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec")`; Linux-only use `sys.platform != "linux"`. The suite must stay green on macOS (Linux tests skip, not fail).
- **Tests run with** `.venv/bin/python -m pytest dark-factory/tests -v` from the repo root `/Users/alonadelson/Projects/ai_projects/skills`.
- **Every commit message ends with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/scripts/
  df_sandbox.py          # CREATE — OS detection, Backend protocol, macOS + linux backends, probe_denial
  supported_tiers.json   # MODIFY — register `standard` (qualified:true)
  df_config.py           # MODIFY — accept assurance:"standard"; _qualified true for it
  run_scenarios.py       # MODIFY — run_all/run_scenario accept exec_wrapper prefix
  supervisor.py          # MODIFY — probe + fail-closed/downgrade; wrap builder+candidate; qualified outcome; manifest fields
dark-factory/references/
  isolation.md           # CREATE — the sandbox model, per-OS primitives, honest limits
  config-reference.md    # MODIFY — assurance tiers incl. standard; --allow-downgrade
dark-factory/tests/
  test_sandbox.py        # CREATE — backend detection; macOS denial (real); linux gated; probe fail-closed
  test_standard_tier.py  # CREATE — config + supervisor standard path, fail-closed, downgrade, qualified outcome
  test_e2e_standard.py   # CREATE — macOS: standard run converges qualified, builder cannot read a control-root canary
```

---

### Task 1: Sandbox backend layer — detection + protocol + null (unsupported) handling

**Files:**
- Create: `dark-factory/scripts/df_sandbox.py`
- Create: `dark-factory/tests/test_sandbox.py`

**Interfaces:**
- Consumes: stdlib only (`sys`, `shutil`, `os`, `subprocess`, `tempfile`, `uuid`).
- Produces:
  - `df_sandbox.SandboxError(RuntimeError)`.
  - Backend objects with attributes/methods: `.name -> str`, `.available() -> bool`, `.wrap_prefix(deny_root: str, workspace: str) -> list[str]`.
  - `df_sandbox.current_backend() -> Backend | None` — returns the backend for `sys.platform` (`"darwin"`→macOS, `"linux"`→linux), else `None` (e.g. Windows). The returned backend may still report `available() is False` if the OS primitive is missing.
  - Module constant `df_sandbox.BACKENDS: dict[str, Backend]` keyed by platform string.

- [ ] **Step 1: Write the failing tests** — create `dark-factory/tests/test_sandbox.py`:

```python
import sys

import pytest

import df_sandbox


def test_current_backend_matches_platform():
    b = df_sandbox.current_backend()
    if sys.platform == "darwin":
        assert b is not None and b.name == "macos-sandbox-exec"
    elif sys.platform == "linux":
        assert b is not None and b.name == "linux-bwrap"
    else:
        assert b is None  # unsupported platform (e.g. windows) → no backend


def test_backend_reports_availability_as_bool():
    b = df_sandbox.current_backend()
    if b is not None:
        assert isinstance(b.available(), bool)


def test_wrap_prefix_is_nonempty_arg_list_when_available():
    b = df_sandbox.current_backend()
    if b is not None and b.available():
        pref = b.wrap_prefix("/some/control", "/some/ws")
        assert isinstance(pref, list) and len(pref) >= 1
        assert all(isinstance(x, str) for x in pref)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_sandbox.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'df_sandbox'`.

- [ ] **Step 3: Implement the skeleton in `df_sandbox.py`** (macOS/linux bodies land in Tasks 2/3; here define the classes with `wrap_prefix`/`available` raising `NotImplementedError` placeholders is NOT allowed — instead give `available()` real implementations now and a minimal `wrap_prefix` that Tasks 2/3 fill in). Write:

```python
"""OS-pluggable read-denial sandbox for dark-factory standard tier. Stdlib only.

A backend denies a wrapped process from READING `deny_root` (the holdout control
root) while leaving `workspace` and the system usable. `current_backend()` returns
the backend for this OS or None (unsupported). No backend is trusted without a
passing `probe_denial` (Task 4) — the probe is the fail-closed safety net.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import uuid


class SandboxError(RuntimeError):
    pass


class _MacOSBackend:
    name = "macos-sandbox-exec"

    def available(self):
        return shutil.which("sandbox-exec") is not None

    def wrap_prefix(self, deny_root, workspace):
        # Filled in Task 2.
        raise SandboxError("macOS wrap_prefix not implemented yet")


class _LinuxBackend:
    name = "linux-bwrap"

    def available(self):
        return shutil.which("bwrap") is not None

    def wrap_prefix(self, deny_root, workspace):
        # Filled in Task 3.
        raise SandboxError("linux wrap_prefix not implemented yet")


BACKENDS = {"darwin": _MacOSBackend(), "linux": _LinuxBackend()}


def current_backend():
    return BACKENDS.get(sys.platform)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_sandbox.py -v
```

Expected: 3 passed (the `wrap_prefix` test only calls it when a backend is available; on macOS it currently raises — so guard: the test calls `wrap_prefix` and expects a list. To avoid depending on Task 2, this step's macOS `wrap_prefix` must already return a list). **Correction:** to keep Step 4 green independent of Task 2, implement the macOS `wrap_prefix` now as the real Task-2 body (see Task 2 Step 3 code) — move that code here. If you are executing tasks strictly in order, instead mark `test_wrap_prefix_is_nonempty_arg_list_when_available` with `@pytest.mark.skipif(not (df_sandbox.current_backend() and df_sandbox.current_backend().available()), reason="filled in Task 2")` until Task 2, then remove the skip in Task 2. Choose the skip approach to keep task boundaries clean.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/df_sandbox.py dark-factory/tests/test_sandbox.py
git commit -m "feat(dark-factory): sandbox backend layer with OS detection

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: macOS `sandbox-exec` backend (built & verified here)

**Files:**
- Modify: `dark-factory/scripts/df_sandbox.py`
- Modify: `dark-factory/tests/test_sandbox.py`

**Interfaces:**
- Produces: `_MacOSBackend.wrap_prefix(deny_root, workspace) -> ["sandbox-exec", "-p", <profile>]` where `<profile>` is an SBPL string: `(version 1)(allow default)(deny file-read* (subpath "<realpath deny_root>"))`. The prefix is prepended to any argv; the wrapped process may read/write everything EXCEPT read under `deny_root`.

- [ ] **Step 1: Write the failing test** (macOS-gated, REAL denial) — add to `test_sandbox.py`:

```python
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec")
def test_macos_backend_denies_deny_root_read_but_allows_workspace(tmp_path):
    b = df_sandbox.current_backend()
    if not b.available():
        pytest.skip("sandbox-exec not present")
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()
    secret = deny_root / "scenarios.json"
    secret.write_text("TOP-SECRET-HOLDOUT", encoding="utf-8")
    ws_file = ws / "ok.txt"
    ws_file.write_text("workspace-ok", encoding="utf-8")

    pref = b.wrap_prefix(str(deny_root), str(ws))
    import subprocess
    # reading the deny_root secret must FAIL under the sandbox
    denied = subprocess.run(pref + ["cat", str(secret)], capture_output=True, text=True)
    assert denied.returncode != 0
    assert "TOP-SECRET-HOLDOUT" not in denied.stdout
    # reading the workspace file must SUCCEED under the same sandbox
    allowed = subprocess.run(pref + ["cat", str(ws_file)], capture_output=True, text=True)
    assert allowed.returncode == 0 and "workspace-ok" in allowed.stdout
```

Also, if you used the skip in Task 1 Step 4, remove that skip now.

- [ ] **Step 2: Run the test to verify it fails**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_sandbox.py -k macos -v
```

Expected (on macOS): FAIL — `SandboxError: macOS wrap_prefix not implemented yet`.

- [ ] **Step 3: Implement `_MacOSBackend.wrap_prefix`** — replace its body:

```python
    def wrap_prefix(self, deny_root, workspace):
        real = os.path.realpath(deny_root)
        profile = (
            "(version 1)"
            "(allow default)"
            f'(deny file-read* (subpath "{real}"))'
        )
        return ["sandbox-exec", "-p", profile]
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_sandbox.py -v
```

Expected (on macOS): all pass, including the real denial test. (If `sandbox-exec` is absent the macOS test skips — but it ships on all stock macOS.)

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/df_sandbox.py dark-factory/tests/test_sandbox.py
git commit -m "feat(dark-factory): macOS sandbox-exec read-denial backend

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Linux `bwrap` backend (code-complete, probe-gated, unverified on this machine)

**Files:**
- Modify: `dark-factory/scripts/df_sandbox.py`
- Modify: `dark-factory/tests/test_sandbox.py`

**Interfaces:**
- Produces: `_LinuxBackend.wrap_prefix(deny_root, workspace)` → a `bwrap` argv prefix that read-only-binds `/`, masks `deny_root` with an empty tmpfs (so its contents are unreadable), binds `workspace` read-write, and `--chdir`s into `workspace`. Ends with `--` so the following argv is the command.

- [ ] **Step 1: Write the tests** (linux-gated real denial; plus a pure-construction test that runs everywhere) — add to `test_sandbox.py`:

```python
def test_linux_wrap_prefix_construction():
    # Runs on any OS: verify the argv shape without executing bwrap.
    b = df_sandbox.BACKENDS["linux"]
    pref = b.wrap_prefix("/ctrl", "/ws")
    assert pref[0] == "bwrap"
    assert "--tmpfs" in pref and "/ctrl" in pref          # deny_root masked
    assert "--bind" in pref and "/ws" in pref             # workspace writable
    assert "--chdir" in pref
    assert pref[-1] == "--"                                # command follows


@pytest.mark.skipif(sys.platform != "linux", reason="linux bwrap")
def test_linux_backend_denies_deny_root_read(tmp_path):
    b = df_sandbox.current_backend()
    if not b.available():
        pytest.skip("bwrap not present")
    deny_root = tmp_path / "control"; deny_root.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    (deny_root / "scenarios.json").write_text("TOP-SECRET-HOLDOUT", encoding="utf-8")
    (ws / "ok.txt").write_text("workspace-ok", encoding="utf-8")
    pref = b.wrap_prefix(str(deny_root), str(ws))
    import subprocess
    denied = subprocess.run(pref + ["cat", str(deny_root / "scenarios.json")],
                            capture_output=True, text=True)
    assert "TOP-SECRET-HOLDOUT" not in denied.stdout
    allowed = subprocess.run(pref + ["cat", str(ws / "ok.txt")],
                             capture_output=True, text=True)
    assert allowed.returncode == 0 and "workspace-ok" in allowed.stdout
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_sandbox.py -k linux -v
```

Expected: `test_linux_wrap_prefix_construction` FAILS (`SandboxError: linux wrap_prefix not implemented yet`); the gated denial test skips on macOS.

- [ ] **Step 3: Implement `_LinuxBackend.wrap_prefix`** — replace its body:

```python
    def wrap_prefix(self, deny_root, workspace):
        real_deny = os.path.realpath(deny_root)
        real_ws = os.path.realpath(workspace)
        return [
            "bwrap",
            "--ro-bind", "/", "/",       # whole fs read-only baseline
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", real_deny,        # mask the control root → contents unreadable
            "--bind", real_ws, real_ws,  # workspace read-write
            "--chdir", real_ws,
            "--die-with-parent",
            "--",
        ]
```

- [ ] **Step 4: Run the tests**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_sandbox.py -v
```

Expected (on macOS): `test_linux_wrap_prefix_construction` passes; the linux denial test skips; macOS tests pass.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/df_sandbox.py dark-factory/tests/test_sandbox.py
git commit -m "feat(dark-factory): linux bwrap read-denial backend (probe-gated, unverified on darwin)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: The fail-closed denial probe

**Files:**
- Modify: `dark-factory/scripts/df_sandbox.py`
- Modify: `dark-factory/tests/test_sandbox.py`

**Interfaces:**
- Produces: `df_sandbox.probe_denial(backend, deny_root: str, workspace: str) -> bool` — plants a random canary file under `deny_root`, runs a wrapped process that attempts to read it, and returns `True` **iff** the wrapped process could NOT read the canary content (denial holds). Any doubt → `False` (fail closed). Cleans up the canary. A `None` backend or an unavailable backend → `False`.

- [ ] **Step 1: Write the tests** — add to `test_sandbox.py`:

```python
class _PassthroughBackend:
    """A deliberately broken 'sandbox' that does NOT deny anything — the probe must
    reject it (return False), proving fail-closed detection."""
    name = "passthrough-insecure"
    def available(self):
        return True
    def wrap_prefix(self, deny_root, workspace):
        return []  # no isolation at all


def test_probe_rejects_a_passthrough_backend(tmp_path):
    deny_root = tmp_path / "control"; deny_root.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    assert df_sandbox.probe_denial(_PassthroughBackend(), str(deny_root), str(ws)) is False


def test_probe_false_for_none_or_unavailable_backend(tmp_path):
    assert df_sandbox.probe_denial(None, str(tmp_path), str(tmp_path)) is False


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real backend")
def test_probe_passes_with_the_real_backend(tmp_path):
    b = df_sandbox.current_backend()
    if not b.available():
        pytest.skip("OS sandbox primitive not present")
    deny_root = tmp_path / "control"; deny_root.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    assert df_sandbox.probe_denial(b, str(deny_root), str(ws)) is True


def test_probe_cleans_up_canary(tmp_path):
    deny_root = tmp_path / "control"; deny_root.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    df_sandbox.probe_denial(_PassthroughBackend(), str(deny_root), str(ws))
    leftovers = [n for n in os.listdir(deny_root) if n.startswith(".probe-canary-")]
    assert leftovers == []
```

- [ ] **Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_sandbox.py -k probe -v
```

Expected: FAIL — `AttributeError: module 'df_sandbox' has no attribute 'probe_denial'`.

- [ ] **Step 3: Implement `probe_denial`** — add to `df_sandbox.py`:

```python
def probe_denial(backend, deny_root, workspace):
    """Fail-closed: True only if a wrapped process provably cannot read a canary
    planted in deny_root. Any error/uncertainty → False."""
    if backend is None or not backend.available():
        return False
    token = "DF-CANARY-" + uuid.uuid4().hex
    canary = os.path.join(deny_root, ".probe-canary-" + uuid.uuid4().hex)
    try:
        with open(canary, "w", encoding="utf-8") as f:
            f.write(token)
        try:
            prefix = backend.wrap_prefix(deny_root, workspace)
        except SandboxError:
            return False
        # Wrapped attempt to read the canary. If the token appears in stdout, the
        # sandbox did NOT deny the read → not isolated → fail closed.
        code = (
            "import sys\n"
            "try:\n"
            "    sys.stdout.write(open(sys.argv[1]).read())\n"
            "except Exception:\n"
            "    sys.stdout.write('DF-READ-DENIED')\n"
        )
        try:
            proc = subprocess.run(
                prefix + [sys.executable, "-c", code, canary],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return token not in proc.stdout
    finally:
        try:
            os.unlink(canary)
        except OSError:
            pass
```

- [ ] **Step 4: Run to verify pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_sandbox.py -v
```

Expected (on macOS): the passthrough-rejection, none, cleanup, and real-backend (macOS) probe tests pass; linux gated tests skip.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/df_sandbox.py dark-factory/tests/test_sandbox.py
git commit -m "feat(dark-factory): fail-closed denial probe harness

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Register `standard` in the tier registry + config

**Files:**
- Modify: `dark-factory/scripts/supported_tiers.json`
- Modify: `dark-factory/scripts/df_config.py`
- Modify: `dark-factory/references/config-reference.md`
- Modify: `dark-factory/tests/test_config.py`

**Interfaces:**
- Consumes: existing `load_config`, `load_supported_tiers`.
- Produces: `supported_tiers.json` now lists `standard` with `{"qualified": true, "backend": "os-read-denial", ...}`. `load_config` accepts `assurance: "standard"` (no longer "no conforming backend") and injects `cfg["_qualified"] = True` for it. `cooperative` still `qualified:false`. Any tier not in the registry (e.g. `hardened`) still rejected.

- [ ] **Step 1: Write the tests** — add to `test_config.py`:

```python
def test_standard_tier_loads_and_is_qualified(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard")
    cfg = df_config.load_config(str(cr))
    assert cfg["assurance"] == "standard"
    assert cfg["_qualified"] is True


def test_hardened_tier_still_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="hardened")
    with pytest.raises(df_config.ConfigError, match="no conforming backend"):
        df_config.load_config(str(cr))
```

- [ ] **Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_config.py -k "standard or hardened" -v
```

Expected: `test_standard_tier_loads_and_is_qualified` FAILS (currently `standard` is rejected).

- [ ] **Step 3: Register the tier.** Replace `dark-factory/scripts/supported_tiers.json` with:

```json
{
  "registry_version": "0.1",
  "tiers": {
    "cooperative": {
      "qualified": false,
      "backend": "process-v0",
      "note": "No OS read-denial; honor-system. Cannot claim probe-proven isolation. Spec 2.2."
    },
    "standard": {
      "qualified": true,
      "backend": "os-read-denial",
      "note": "OS read-denial sandbox (macOS sandbox-exec / Linux bwrap). Usable only when the platform backend is available AND the startup denial probe passes; else fail-closed. Spec 7.2."
    }
  }
}
```

No change is needed in `df_config.py`'s tier check itself — it already accepts any tier present in the registry and reads `qualified` from it. Confirm by reading the existing `load_config`: it does `tiers = load_supported_tiers()["tiers"]; if tier not in tiers: raise` and `cfg["_qualified"] = bool(tiers[tier]["qualified"])`. Adding `standard` to the JSON is sufficient. (If the existing code hardcodes cooperative anywhere, generalize it to read from the registry.)

- [ ] **Step 4: Document tiers** — in `config-reference.md`, update the `assurance` row:

```markdown
| `assurance` | str | `cooperative` (unqualified, honor-system) or `standard` (probe-verified OS read-denial → qualified). `standard` requires a platform sandbox backend + a passing startup denial probe, else the run fails closed (or downgrades with `--allow-downgrade`). Other tiers rejected. |
```

- [ ] **Step 5: Run to verify pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_config.py -v
```

Expected: all config tests pass.

- [ ] **Step 6: Commit**

```bash
git add dark-factory/scripts/supported_tiers.json dark-factory/scripts/df_config.py dark-factory/references/config-reference.md dark-factory/tests/test_config.py
git commit -m "feat(dark-factory): register standard tier (qualified) in the registry

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: run_scenarios — optional exec wrapper for candidate isolation

**Files:**
- Modify: `dark-factory/scripts/run_scenarios.py`
- Modify: `dark-factory/tests/test_oracle.py`

**Interfaces:**
- Produces: `run_scenario(sc, workspace, exec_wrapper=None)` and `run_all(scenarios_dir, workspace, exec_wrapper=None)`. When `exec_wrapper` is a non-empty list, the executed command becomes `exec_wrapper + sc["when"]["run"]` (the candidate runs wrapped). Default `None` → unchanged M1 behavior. The report shape is identical.

- [ ] **Step 1: Write the test** — add to `test_oracle.py`:

```python
def test_exec_wrapper_is_prepended_to_the_command(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(d, "a.json")  # runs ["python3", "ok.py"], expects stdout "ok"
    ws = make_workspace(tmp_path)     # ok.py prints "ok"
    # env -u FOO is a harmless no-op wrapper that execs the following argv unchanged
    r = run_scenarios.run_scenario(sc, str(ws), exec_wrapper=["env"])
    assert r["pass"] is True and r["observed"]["exit_code"] == 0


def test_default_no_wrapper_unchanged(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(d, "a.json")
    ws = make_workspace(tmp_path)
    assert run_scenarios.run_scenario(sc, str(ws))["pass"] is True
```

- [ ] **Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_oracle.py -k wrapper -v
```

Expected: FAIL — `run_scenario() got an unexpected keyword argument 'exec_wrapper'`.

- [ ] **Step 3: Implement** — in `run_scenarios.py`, change `run_scenario` and `run_all` signatures and the subprocess call:

```python
def run_scenario(sc, workspace, exec_wrapper=None):
    timeout = sc["when"].get("timeout_s", 30)
    observed = {"exit_code": None, "stdout": "", "stderr": ""}
    taxonomy = None
    command = (list(exec_wrapper) if exec_wrapper else []) + sc["when"]["run"]
    try:
        proc = subprocess.run(
            command, cwd=workspace, capture_output=True, text=True, timeout=timeout,
        )
        observed = {"exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired:
        taxonomy = "timeout"
    except (FileNotFoundError, PermissionError, OSError):
        taxonomy = "crash"
    # ... (the rest of the then-assertion logic is UNCHANGED) ...
```

(Keep the entire taxonomy/assertion block below the try exactly as it is. Only the signature + the `command` construction + the `subprocess.run(command, ...)` change.)

And:

```python
def run_all(scenarios_dir, workspace, exec_wrapper=None):
    results = [run_scenario(sc, workspace, exec_wrapper) for sc in load_scenarios(scenarios_dir)]
    return {"report_version": "0.1", "results": results, "all_pass": all(r["pass"] for r in results)}
```

- [ ] **Step 4: Run to verify pass, then full oracle suite**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_oracle.py -v
```

Expected: all oracle tests pass (existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/run_scenarios.py dark-factory/tests/test_oracle.py
git commit -m "feat(dark-factory): optional exec_wrapper to sandbox candidate execution

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Supervisor — probe, fail-closed/downgrade, wrap builder + candidate, qualified outcome

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Create: `dark-factory/tests/test_standard_tier.py`
- Create: `dark-factory/references/isolation.md`

**Interfaces:**
- Consumes: `df_sandbox.current_backend`, `df_sandbox.probe_denial`; `_run_loop`, `invoke_adapter`, `run_all`, `finalize_manifest`.
- Produces:
  - `run(control_root, project_src, allow_downgrade=False)` and `resume(control_root, decision, allow_downgrade=False)` gain the flag; CLI adds `--allow-downgrade` to `run` and `resume`.
  - New helper `resolve_isolation(cfg, control_root, workspace, journal) -> tuple[effective_tier, exec_prefix, backend_name, probe_passed]`:
    - `cooperative` → `("cooperative", [], None, None)` (no wrap; unchanged).
    - `standard` → probe. If backend present, available, and `probe_denial` True → `("standard", backend.wrap_prefix(control_root, workspace), backend.name, True)`. Else if `allow_downgrade` → journal `DOWNGRADE`, warn on stderr, return `("cooperative", [], backend_name_or_None, False)`. Else → raise `SandboxError` (supervisor turns it into exit 2 + a `PROBE_FAILED` journal entry).
  - `invoke_adapter(adapter, role, workdir, prompt_file, timeout_s, exec_prefix=None)` — prepends `exec_prefix` to the adapter argv when given (builder runs sandboxed).
  - `_run_loop(..., exec_prefix)` threads the prefix to `run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix)` (candidate runs sandboxed) and to `invoke_adapter(..., exec_prefix=exec_prefix)`.
  - Manifest gains `sandbox_backend` + `denial_probe_passed` (from `manifest_base`). Qualified converged outcome: when the **effective** tier is `standard` and probe passed → `outcome="COMPLETE_QUALIFIED"`, `qualified=True`, NO cooperative banner. When effective tier is `cooperative` → unchanged (`COMPLETE_UNQUALIFIED`, banner). `qualified` in `manifest_base` must reflect the **effective** tier (a downgraded run is `qualified:false`), not the requested tier.

- [ ] **Step 1: Write the tests** — create `dark-factory/tests/test_standard_tier.py`:

```python
import json
import os
import sys

import pytest

import df_sandbox
import supervisor
from test_supervisor import FAKE, setup_control


def _std(tmp_path, **kw):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto", **kw)
    # rewrite assurance to standard
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"; p.write_text(json.dumps(cfg))
    return cr


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_run_converges_qualified_when_probe_passes(tmp_path):
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    cr = _std(tmp_path)
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_QUALIFIED"
    assert m["qualified"] is True
    assert m["denial_probe_passed"] is True
    assert m["sandbox_backend"] in ("macos-sandbox-exec", "linux-bwrap")


def test_standard_fails_closed_when_probe_fails(tmp_path, monkeypatch):
    cr = _std(tmp_path)
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: False)
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend",
                        lambda: df_sandbox.BACKENDS["linux"])  # a real backend object
    assert supervisor.run(str(cr), None) == 2  # fail closed, no downgrade flag
    run_id = os.listdir(cr / "runs")[0]
    states = [json.loads(l)["state"] for l in (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    assert "PROBE_FAILED" in states


def test_standard_downgrades_with_flag(tmp_path, monkeypatch):
    cr = _std(tmp_path)
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: False)
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend",
                        lambda: df_sandbox.BACKENDS["linux"])
    assert supervisor.run(str(cr), None, allow_downgrade=True) == 0
    run_id = os.listdir(cr / "runs")[0]
    entries = [json.loads(l) for l in (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    states = [e["state"] for e in entries]
    assert "DOWNGRADE" in states
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["qualified"] is False and m["outcome"] == "COMPLETE_UNQUALIFIED"


def test_cooperative_unaffected(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # cooperative default
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["qualified"] is False and m["outcome"] == "COMPLETE_UNQUALIFIED"
    assert m["sandbox_backend"] is None


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_resume_stays_qualified_and_reprobes(tmp_path):
    # DEFAULT standard flow: autonomy 4 → pause → resume finalizes. resume MUST
    # re-probe + re-wrap, else the resumed build/verify runs UNSANDBOXED and the
    # qualified claim is a lie. This pins that path.
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    cr = _std(tmp_path)                      # _std sets checkpoint="auto"...
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["checkpoint"] = "pause"; p.write_text(json.dumps(cfg))
    assert supervisor.run(str(cr), None) == 10          # paused at iteration 1
    assert supervisor.resume(str(cr), "continue") == 0  # resume re-probes, converges
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_QUALIFIED" and m["qualified"] is True
    assert m["denial_probe_passed"] is True
```

- [ ] **Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_standard_tier.py -v
```

Expected: FAIL (probe/downgrade/qualified not implemented; `run()` has no `allow_downgrade`).

- [ ] **Step 3: Implement in `supervisor.py`.** Add the import at top: `import df_sandbox`. Add `resolve_isolation`:

```python
def resolve_isolation(cfg, control_root, workspace, journal, allow_downgrade):
    if cfg["assurance"] != "standard":
        return "cooperative", [], None, None
    backend = df_sandbox.current_backend()
    name = backend.name if backend is not None else None
    ok = backend is not None and backend.available() and df_sandbox.probe_denial(
        backend, control_root, workspace)
    if ok:
        return "standard", backend.wrap_prefix(control_root, workspace), name, True
    if allow_downgrade:
        journal.write("DOWNGRADE", requested="standard", effective="cooperative",
                      reason="sandbox unavailable or denial probe failed")
        sys.stderr.write("dark-factory: standard tier UNavailable/probe failed — "
                         "DOWNGRADED to cooperative (unqualified) by --allow-downgrade.\n")
        return "cooperative", [], name, False
    journal.write("PROBE_FAILED", requested="standard",
                  reason="sandbox unavailable or denial probe failed")
    raise df_sandbox.SandboxError(
        "standard tier requires a working OS sandbox + passing denial probe; "
        "none available. Fix the sandbox or set assurance=cooperative "
        "(or pass --allow-downgrade).")
```

In `_run_locked`, AFTER the SNAPSHOT step (so `workspace` exists) and BEFORE the loop, resolve isolation and fold it into `manifest_base` and the loop call:

```python
    try:
        eff_tier, exec_prefix, backend_name, probe_passed = resolve_isolation(
            cfg, control_root, workspace, journal, allow_downgrade)
    except df_sandbox.SandboxError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    manifest_base["qualified"] = (eff_tier == "standard")
    manifest_base["sandbox_backend"] = backend_name
    manifest_base["denial_probe_passed"] = probe_passed
    manifest_base["_effective_tier"] = eff_tier   # internal; strip before finalize if you prefer
    # cooperative banner only when the EFFECTIVE tier is cooperative:
    if eff_tier != "standard":
        sys.stderr.write("dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
                         "isolation; outcome can never be a qualified ship-candidate.\n")
    return _run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
                     adapter, timeout_s, workspace, start_iter=1, feedback=None,
                     exec_prefix=exec_prefix)
```

(Remove the OLD unconditional cooperative-banner line from `_run_locked` if it printed regardless of tier — the banner must now be conditional on the effective tier. Keep the `if not cfg["_qualified"]` banner logic replaced by this `eff_tier != "standard"` check.)

Update `_run_loop` signature to accept `exec_prefix` (default `[]`), and:
- change the adapter call to `invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s, exec_prefix=exec_prefix)`;
- change verify to `run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix)`;
- in the CONVERGED branch, choose the outcome by effective tier: read it from `manifest_base.get("_effective_tier")`:

```python
        if report["all_pass"]:
            journal.write("CONVERGED", iteration=i)
            eff = manifest_base.get("_effective_tier", "cooperative")
            outcome = "COMPLETE_QUALIFIED" if eff == "standard" else "COMPLETE_UNQUALIFIED"
            mb = {k: v for k, v in manifest_base.items() if k != "_effective_tier"}
            finalize_manifest(run_dir, dict(mb, outcome=outcome, iterations=i))
            _clear_state()
            print(f"dark-factory: CONVERGED ({'qualified, standard' if eff=='standard' else 'unqualified, cooperative'} tier). "
                  f"Workspace: {workspace}  Run: {run_dir}")
            return 0
```

Also strip `_effective_tier` from `manifest_base` in the other terminal `finalize_manifest` calls (CAP, ABORTED) — simplest: at the top of `_run_loop`, do `mb_clean = {k: v for k, v in manifest_base.items() if k != "_effective_tier"}` and use `mb_clean` in every `finalize_manifest(...)` while keeping `manifest_base` for the `_effective_tier` read. Update all terminal finalize calls to use `mb_clean`.

Update `invoke_adapter` to accept `exec_prefix=None` and prepend it:

```python
def invoke_adapter(adapter, role, workdir, prompt_file, timeout_s, exec_prefix=None):
    req = {"adapter_protocol": "0.1", "role": role, "workdir": workdir,
           "prompt_file": prompt_file, "timeout_s": timeout_s}
    argv = (list(exec_prefix) if exec_prefix else []) + [adapter]
    try:
        proc = subprocess.run(argv, input=json.dumps(req), capture_output=True,
                              text=True, timeout=timeout_s + 60)
    # ... rest UNCHANGED ...
```

Thread `allow_downgrade` through `run(control_root, project_src, allow_downgrade=False)` → `_run_locked(..., allow_downgrade)` and add it to `resume(...)` similarly (resume calls `resolve_isolation` too, since a resumed standard run must re-probe — reuse the same helper before its `_run_loop` call, mirroring `_run_locked`). Add `--allow-downgrade` (store_true) to the `run` and `resume` subparsers and pass `args.allow_downgrade`.

Create `dark-factory/references/isolation.md`:

```markdown
# dark-factory isolation (standard tier)

`standard` runs the builder AND the candidate under an OS read-denial sandbox that
cannot read the control root (scenarios/runs). Backends: macOS `sandbox-exec`
(`(allow default)(deny file-read* (subpath control_root))`), Linux `bwrap`
(masks the control root with a tmpfs). Windows: no backend yet → unsupported.

A tier is claimed only when **probe-verified**: at startup a canary is planted in
the control root and a wrapped process must fail to read it. If the backend is
missing or the probe fails, the run **fails closed** (exit 2) unless
`--allow-downgrade` drops it to `cooperative` (unqualified) with a warning + a
`DOWNGRADE` audit entry. The Linux backend ships code-complete but is unverified on
the maintainer's macOS machine — the denial probe is the guarantee that it is never
trusted without proof on the actual host.
```

- [ ] **Step 4: Run the standard-tier tests, then the FULL suite**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_standard_tier.py -v
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: standard-tier tests pass (the qualified one runs for real on macOS); full suite green (M1/M2a unaffected — cooperative path identical).

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/supervisor.py dark-factory/tests/test_standard_tier.py dark-factory/references/isolation.md
git commit -m "feat(dark-factory): standard-tier isolation — probe, fail-closed/downgrade, wrapped build+verify, qualified outcome

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: E2E (macOS) + SKILL.md — a qualified standard run that provably can't read the holdout

**Files:**
- Create: `dark-factory/tests/test_e2e_standard.py`
- Modify: `dark-factory/SKILL.md`

**Interfaces:**
- Consumes: the supervisor CLI + `df_sandbox`; `test_supervisor.setup_control`, `FAKE`.
- Produces: executable proof (macOS) that a `standard` run converges **qualified** and that a process wrapped by the SAME backend genuinely cannot read a planted control-root canary; plus SKILL.md tier guidance.

- [ ] **Step 1: Write the test** — create `dark-factory/tests/test_e2e_standard.py`:

```python
import json
import os
import subprocess
import sys

import pytest

import df_sandbox
from test_supervisor import FAKE, setup_control

SUP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py")


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_run_is_qualified_and_holdout_is_os_denied(tmp_path):
    b = df_sandbox.current_backend()
    if not (b and b.available()):
        pytest.skip("no OS sandbox primitive")
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"; p.write_text(json.dumps(cfg))

    proc = subprocess.run([sys.executable, SUP, "run", "--control-root", str(cr)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "COOPERATIVE MODE" not in proc.stderr        # not downgraded
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_QUALIFIED" and m["qualified"] is True
    assert m["denial_probe_passed"] is True

    # Independent OS-level proof: a process wrapped by the same backend cannot read
    # the real holdout scenarios living under the control root.
    secret = next((cr / "scenarios").glob("*.json"))
    pref = b.wrap_prefix(str(cr), str(tmp_path / "ws"))
    denied = subprocess.run(pref + ["cat", str(secret)], capture_output=True, text=True)
    assert denied.returncode != 0                        # OS denied the read
```

- [ ] **Step 2: Run it**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_e2e_standard.py -v
```

Expected (macOS): PASS. If it fails, fix the responsible earlier task — don't weaken the test.

- [ ] **Step 3: Update `dark-factory/SKILL.md`** — change the frontmatter description's final sentence and the Engage step to reflect tiers. Replace the description's last sentence "M1 walking skeleton: cooperative tier only ..." with:

```
Tiers: `cooperative` (honor-system, unqualified) and `standard` (OS read-denial sandbox — macOS/Linux — probe-verified and qualified). Per-iteration human checkpoints (pause/resume) at autonomy 4.
```

And update workflow step 4 (Config) to add:

```markdown
   - `assurance`: `cooperative` (works everywhere, unqualified) or `standard` (real OS
     read-denial sandbox → qualified; needs macOS `sandbox-exec` or Linux `bwrap`, and a
     passing startup denial probe). If `standard` can't be honored, the run fails closed
     unless you pass `run --allow-downgrade` (→ cooperative, unqualified).
```

- [ ] **Step 4: Verify the CLI help matches the docs, then the full suite**

```bash
.venv/bin/python dark-factory/scripts/supervisor.py run --help   # shows --allow-downgrade
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: `--allow-downgrade` present; full suite green.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/tests/test_e2e_standard.py dark-factory/SKILL.md
git commit -m "test(dark-factory): e2e standard run is qualified and holdout is OS-denied; SKILL.md tiers

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review Notes (plan ↔ spec)

**Covered (M2b slice):** `standard` as a probe-verified, qualified tier (§2.2, §1.4); OS read-denial for builder (§7.2) AND candidate (§7.4); fail-closed with `--allow-downgrade` transaction + `DOWNGRADE`/`PROBE_FAILED` audit (§2.3); per-tier backend registry (`supported_tiers`); honest cross-OS posture (macOS proven, Linux code-complete + probe-gated, Windows unsupported→fail closed); manifest records `sandbox_backend` + `denial_probe_passed`.

**Type/name consistency:** `current_backend()` / `Backend.available()` / `Backend.wrap_prefix(deny_root, workspace)` / `probe_denial(backend, deny_root, workspace)` (Tasks 1-4) · `exec_wrapper` param on `run_all`/`run_scenario` (Task 6) · `resolve_isolation(...)` + `exec_prefix` threaded through `_run_loop`/`invoke_adapter`, `allow_downgrade` on `run`/`resume`, outcomes `COMPLETE_QUALIFIED`/`COMPLETE_UNQUALIFIED`, journal states `DOWNGRADE`/`PROBE_FAILED`, manifest keys `sandbox_backend`/`denial_probe_passed` (Task 7) — used consistently.

**Deferred (later plans):** dev/final holdout split, coverage gate, mutation-validated oracle, mandatory security gates; hardened/enterprise tiers (containers, credential broker, signed audit, network authority); Windows sandbox backend. The registry + probe design leaves each slot open without redesign.

**Known M2b limitations (stated, not hidden):** the Linux `bwrap` backend is unverified on the maintainer's macOS machine — trusted only via the runtime denial probe on the actual host; `sandbox-exec` is deprecated-but-present on macOS (documented in isolation.md); the sandbox denies *reads* of the control root but M2b does not yet add network-egress control or per-role principals (those are hardened+); a resumed `standard` run re-probes at resume time (correct — isolation must hold for the resumed builder too).
