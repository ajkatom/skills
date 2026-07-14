# dark-factory M4 — Cross-Model Builders Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Let the user choose which model *builds* — Claude, Codex, or Gemini — via the existing adapter seam, with a capability probe that offers only installed tools, no silent fallback, and vendor-diversity guidance for scenario authoring. Verification stays the deterministic scenario runner (no LLM judge).

**Architecture:** The supervisor already invokes `roles.builder.adapter` (any executable, protocol 0.1) generically, so M4 adds no supervisor logic. It ships two new adapter executables (`codex`, `gemini`) mirroring the `claude` adapter, a `df_adapters.py` helper that reports which builder CLIs are on PATH, and SKILL.md/docs for the "which model builds?" invocation step. Under `standard` tier the OS sandbox already denies the holdout to whatever model builds — cross-model inherits isolation with zero supervisor change.

**Tech Stack:** Python ≥ 3.9 stdlib only at runtime (adapters use `json`, `shutil`, `subprocess`, `sys`). `pytest` for tests. No new deps.

**Source spec:** `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md` §3/§3.1 (pluggable roles, principled defaults), §7.8 (versioned adapter protocol, no silent fallback). This plan implements the *builder* cross-model axis; the deterministic verifier is unchanged by design (§5.1). Skill-composition allowlist and KB integration are deferred to a later M4b (they carry separate security surface — same rationale as the M2 split).

## Global Constraints

- **Adapters are stdlib-only executables** speaking **protocol 0.1** (unchanged): request `{"adapter_protocol":"0.1","role":"builder","workdir","prompt_file","timeout_s"}` on stdin → response `{"adapter_protocol":"0.1","status":"ok"|"error","detail","usage":{"known":false}}` on stdout, **exit 0 even on in-band error**; non-zero exit or unparseable stdout is a supervisor `ABORTED_BUILD_ERROR`.
- **No silent fallback** — a configured adapter whose CLI is absent returns `status:"error"` (the run aborts, exit 2); it must NEVER substitute a different model.
- **Portable `#!/usr/bin/env python3` shebang**; both new adapters committed **executable (mode 100755)**.
- **The adapter reads the prompt only from `req["prompt_file"]`** (in the workspace since M2b's C1 fix) and runs with `cwd = req["workdir"]`. It passes the prompt to the model and nothing else — the barrier is the supervisor's job; adapters must not read the control root.
- **Do not pin a model** (`-m`) in the Codex adapter — use the user's `~/.codex/config.toml` default (pinning `-codex` variants breaks ChatGPT-account auth; documented dark-factory learning).
- **Tests must not require codex/gemini to be installed** — test the missing-CLI error path (PATH without the tool) and the success/argv path via a PATH-shim (a fake `codex`/`gemini` executable on a temp PATH), mirroring the existing `test_adapters.py::test_claude_adapter_reports_error_when_cli_missing`.
- **Runtime stdlib only.** Tests run `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    adapters/
      codex                     # Task 1 — Codex builder adapter (executable)
      gemini                    # Task 2 — Gemini builder adapter (executable)
    df_adapters.py              # Task 3 — builder registry + which-are-installed
  references/
    role-adapters.md            # Task 4 — protocol + 3 adapters + probe + no-fallback
  SKILL.md                      # Task 4 — "which model builds?" invocation step
  tests/
    test_adapters_codex.py      # Task 1
    test_adapters_gemini.py     # Task 2
    test_df_adapters.py         # Task 3
    fixtures/
      fake_cli_ok               # Task 1 — records argv, exits 0 (PATH-shim for codex/gemini)
      fake_cli_fail             # Task 1 — exits nonzero (error-path shim)
```

---

### Task 1: Codex builder adapter

**Files:**
- Create: `dark-factory/scripts/adapters/codex` (executable)
- Create: `dark-factory/tests/fixtures/fake_cli_ok` (executable)
- Create: `dark-factory/tests/fixtures/fake_cli_fail` (executable)
- Create: `dark-factory/tests/test_adapters_codex.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (standalone executable).
- Produces (protocol 0.1, builder role): spawns `codex exec` headless in `workdir`, feeding the prompt. Because the dark-factory `standard` tier provides the OS sandbox itself, the adapter disables Codex's own sandbox and skips the git check: `codex exec --sandbox danger-full-access --skip-git-repo-check <prompt>` with `cwd=workdir`, stdin `/dev/null`, no `-m` pin. Missing `codex` on PATH → `status:"error"` (no fallback). Non-zero exit → `status:"error"` with tail of stderr. Timeout → `status:"error"`.
- `fake_cli_ok`: writes its argv (one per line) to `$DF_ARGV_OUT` if set, then exits 0. `fake_cli_fail`: writes `boom` to stderr, exits 1.

- [ ] **Step 1: Write the fixtures and the failing tests**

`dark-factory/tests/fixtures/fake_cli_ok`:

```python
#!/usr/bin/env python3
"""Records argv to $DF_ARGV_OUT (if set) and exits 0. A stand-in for a
model CLI so adapter tests don't require the real tool."""
import os
import sys

out = os.environ.get("DF_ARGV_OUT")
if out:
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(sys.argv[1:]))
sys.exit(0)
```

`dark-factory/tests/fixtures/fake_cli_fail`:

```python
#!/usr/bin/env python3
import sys

print("boom", file=sys.stderr)
sys.exit(1)
```

`dark-factory/tests/test_adapters_codex.py`:

```python
import json
import os
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "codex")
OK = os.path.join(HERE, "fixtures", "fake_cli_ok")
FAIL = os.path.join(HERE, "fixtures", "fake_cli_fail")


def make_req(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    pf = tmp_path / "prompt.md"
    pf.write_text("Build greet.py per SPEC.", encoding="utf-8")
    return {"adapter_protocol": "0.1", "role": "builder",
            "workdir": str(ws), "prompt_file": str(pf), "timeout_s": 20}


def invoke(tmp_path, env):
    proc = subprocess.run(
        [ADAPTER], input=json.dumps(make_req(tmp_path)),
        capture_output=True, text=True, timeout=30, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def bindir_with(tmp_path, toolname, target):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    os.symlink(target, b / toolname)
    os.symlink(shutil.which("python3") or "/usr/bin/python3", b / "python3")
    return b


def test_codex_adapter_error_when_cli_missing(tmp_path):
    env = dict(os.environ, PATH=str(bindir_with(tmp_path, "nothere", OK)))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "error" and "codex" in resp["detail"]


def test_codex_adapter_invokes_codex_exec_and_reports_ok(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "codex", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "ok" and resp["adapter_protocol"] == "0.1"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert argv[0] == "exec"
    assert "--skip-git-repo-check" in argv
    assert "Build greet.py per SPEC." in argv  # prompt passed through
    assert not any(a == "-m" for a in argv)  # no model pin


def test_codex_adapter_reports_error_on_nonzero_exit(tmp_path):
    env = dict(os.environ, PATH=str(bindir_with(tmp_path, "codex", FAIL)))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "error" and "boom" in resp["detail"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/alonadelson/Projects/ai_projects/skills
chmod +x dark-factory/tests/fixtures/fake_cli_ok dark-factory/tests/fixtures/fake_cli_fail
.venv/bin/python -m pytest dark-factory/tests/test_adapters_codex.py -v
```

Expected: FAIL — adapter `codex` does not exist (`FileNotFoundError`).

- [ ] **Step 3: Implement the codex adapter**

`dark-factory/scripts/adapters/codex`:

```python
#!/usr/bin/env python3
"""Codex builder adapter, protocol 0.1. Invokes `codex exec` headless with
cwd = the build workspace. dark-factory provides the OS sandbox itself (the
standard tier wraps this adapter), so Codex's own sandbox is disabled and the
git-repo check is skipped. No -m pin (uses the user's ~/.codex default; pinning
-codex variants breaks ChatGPT-account auth). The model sees only the prompt
file content (spec + ID feedback) and the workspace directory."""
import json
import shutil
import subprocess
import sys


def respond(status, detail=""):
    print(json.dumps({"adapter_protocol": "0.1", "status": status,
                      "detail": detail, "usage": {"known": False}}))


def main():
    req = json.load(sys.stdin)
    with open(req["prompt_file"], encoding="utf-8") as f:
        prompt = f.read()
    if shutil.which("codex") is None:
        respond("error", "codex CLI not found on PATH")
        return
    try:
        proc = subprocess.run(
            ["codex", "exec", "--sandbox", "danger-full-access",
             "--skip-git-repo-check", prompt],
            cwd=req["workdir"],
            timeout=req.get("timeout_s", 600),
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        respond("error", "codex CLI timed out")
        return
    if proc.returncode != 0:
        respond("error", (proc.stderr or proc.stdout)[-2000:])
        return
    respond("ok")


if __name__ == "__main__":
    main()
```

```bash
chmod +x dark-factory/scripts/adapters/codex
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_adapters_codex.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Full suite + commit**

```bash
.venv/bin/python -m pytest dark-factory/tests -q | tail -1   # expect 108 passed, 1 skipped
git add dark-factory/scripts/adapters/codex dark-factory/tests/fixtures/fake_cli_ok dark-factory/tests/fixtures/fake_cli_fail dark-factory/tests/test_adapters_codex.py
git commit -m "feat(dark-factory): Codex builder adapter (protocol 0.1, no model pin)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Gemini builder adapter

**Files:**
- Create: `dark-factory/scripts/adapters/gemini` (executable)
- Create: `dark-factory/tests/test_adapters_gemini.py`

**Interfaces:**
- Consumes: the `fake_cli_ok` / `fake_cli_fail` fixtures from Task 1.
- Produces (protocol 0.1, builder role): spawns the Gemini CLI headless in `workdir`: `gemini --yolo --prompt <prompt>` (`--yolo` auto-approves file edits so the model can write the build; `--prompt` is the non-interactive form), `cwd=workdir`, stdin `/dev/null`. Missing `gemini` on PATH → `status:"error"`. Non-zero → error with stderr tail. Timeout → error.

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_adapters_gemini.py`:

```python
import json
import os
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "gemini")
OK = os.path.join(HERE, "fixtures", "fake_cli_ok")
FAIL = os.path.join(HERE, "fixtures", "fake_cli_fail")


def make_req(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    pf = tmp_path / "prompt.md"
    pf.write_text("Build greet.py per SPEC.", encoding="utf-8")
    return {"adapter_protocol": "0.1", "role": "builder",
            "workdir": str(ws), "prompt_file": str(pf), "timeout_s": 20}


def invoke(tmp_path, env):
    proc = subprocess.run(
        [ADAPTER], input=json.dumps(make_req(tmp_path)),
        capture_output=True, text=True, timeout=30, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def bindir_with(tmp_path, toolname, target):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    os.symlink(target, b / toolname)
    os.symlink(shutil.which("python3") or "/usr/bin/python3", b / "python3")
    return b


def test_gemini_adapter_error_when_cli_missing(tmp_path):
    env = dict(os.environ, PATH=str(bindir_with(tmp_path, "nothere", OK)))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "error" and "gemini" in resp["detail"]


def test_gemini_adapter_invokes_gemini_and_reports_ok(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "gemini", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "ok"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert "--yolo" in argv
    assert "Build greet.py per SPEC." in argv


def test_gemini_adapter_reports_error_on_nonzero_exit(tmp_path):
    env = dict(os.environ, PATH=str(bindir_with(tmp_path, "gemini", FAIL)))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "error" and "boom" in resp["detail"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_adapters_gemini.py -v
```

Expected: FAIL — adapter `gemini` does not exist.

- [ ] **Step 3: Implement the gemini adapter**

`dark-factory/scripts/adapters/gemini`:

```python
#!/usr/bin/env python3
"""Gemini builder adapter, protocol 0.1. Invokes the Gemini CLI headless with
cwd = the build workspace. --yolo auto-approves file edits so the model can
write the build; --prompt is the non-interactive form. The model sees only the
prompt file content (spec + ID feedback) and the workspace directory."""
import json
import shutil
import subprocess
import sys


def respond(status, detail=""):
    print(json.dumps({"adapter_protocol": "0.1", "status": status,
                      "detail": detail, "usage": {"known": False}}))


def main():
    req = json.load(sys.stdin)
    with open(req["prompt_file"], encoding="utf-8") as f:
        prompt = f.read()
    if shutil.which("gemini") is None:
        respond("error", "gemini CLI not found on PATH")
        return
    try:
        proc = subprocess.run(
            ["gemini", "--yolo", "--prompt", prompt],
            cwd=req["workdir"],
            timeout=req.get("timeout_s", 600),
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        respond("error", "gemini CLI timed out")
        return
    if proc.returncode != 0:
        respond("error", (proc.stderr or proc.stdout)[-2000:])
        return
    respond("ok")


if __name__ == "__main__":
    main()
```

```bash
chmod +x dark-factory/scripts/adapters/gemini
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_adapters_gemini.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Full suite + commit**

```bash
.venv/bin/python -m pytest dark-factory/tests -q | tail -1   # expect 111 passed, 1 skipped
git add dark-factory/scripts/adapters/gemini dark-factory/tests/test_adapters_gemini.py
git commit -m "feat(dark-factory): Gemini builder adapter (protocol 0.1)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Builder registry + capability probe (`df_adapters.py`)

**Files:**
- Create: `dark-factory/scripts/df_adapters.py`
- Create: `dark-factory/tests/test_df_adapters.py`

**Interfaces:**
- Consumes: `shutil` (stdlib).
- Produces:
  - `df_adapters.BUILDERS` — ordered dict `{"claude": "claude", "codex": "codex", "gemini": "gemini"}` mapping builder name → required CLI and (implicitly) the shipped adapter file `scripts/adapters/<name>`.
  - `df_adapters.adapter_path(name: str) -> str` — absolute path to `scripts/adapters/<name>`; raises `KeyError` for unknown names.
  - `df_adapters.available_builders(which=shutil.which) -> dict[str, bool]` — `{name: cli_present}` for each builder (the `which` param is injectable so tests don't depend on the host's installed CLIs).
  - `df_adapters.resolve_builder(name: str, which=shutil.which) -> str` — returns `adapter_path(name)` if the CLI is present; raises `df_adapters.BuilderUnavailable` (a `RuntimeError`) naming the missing CLI otherwise. **This is the no-silent-fallback gate the SKILL.md invocation step uses — it never returns a different builder.**

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_df_adapters.py`:

```python
import os

import pytest

import df_adapters


def test_builders_are_the_three_known_names():
    assert set(df_adapters.BUILDERS) == {"claude", "codex", "gemini"}


def test_adapter_path_points_at_shipped_executable():
    p = df_adapters.adapter_path("codex")
    assert p.endswith(os.path.join("scripts", "adapters", "codex"))
    assert os.access(p, os.X_OK)  # shipped executable


def test_adapter_path_unknown_raises():
    with pytest.raises(KeyError):
        df_adapters.adapter_path("llama")


def test_available_builders_reflects_which(monkeypatch):
    present = {"claude", "gemini"}
    fake_which = lambda name: ("/usr/bin/" + name) if name in present else None
    avail = df_adapters.available_builders(which=fake_which)
    assert avail == {"claude": True, "codex": False, "gemini": True}


def test_resolve_builder_returns_path_when_present():
    fake_which = lambda name: "/usr/bin/" + name
    assert df_adapters.resolve_builder("codex", which=fake_which) == df_adapters.adapter_path("codex")


def test_resolve_builder_never_falls_back():
    fake_which = lambda name: None  # nothing installed
    with pytest.raises(df_adapters.BuilderUnavailable, match="codex"):
        df_adapters.resolve_builder("codex", which=fake_which)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_df_adapters.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'df_adapters'`.

- [ ] **Step 3: Implement `df_adapters.py`**

`dark-factory/scripts/df_adapters.py`:

```python
"""Builder registry + capability probe. Stdlib only.

Reports which builder CLIs are installed so the skill's invocation step can
offer only usable models, and resolves a chosen builder to its shipped adapter
path WITHOUT ever substituting a different model (no silent fallback, spec 7.8).
"""
import os
import shutil

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

# builder name -> required CLI on PATH. The shipped adapter is scripts/adapters/<name>.
BUILDERS = {"claude": "claude", "codex": "codex", "gemini": "gemini"}


class BuilderUnavailable(RuntimeError):
    pass


def adapter_path(name: str) -> str:
    if name not in BUILDERS:
        raise KeyError(f"unknown builder {name!r}; known: {sorted(BUILDERS)}")
    return os.path.join(SCRIPTS_DIR, "adapters", name)


def available_builders(which=shutil.which) -> dict:
    return {name: which(cli) is not None for name, cli in BUILDERS.items()}


def resolve_builder(name: str, which=shutil.which) -> str:
    if name not in BUILDERS:
        raise KeyError(f"unknown builder {name!r}; known: {sorted(BUILDERS)}")
    if which(BUILDERS[name]) is None:
        raise BuilderUnavailable(
            f"builder {name!r} requires the {BUILDERS[name]!r} CLI, which is not on "
            f"PATH; install it or choose an available builder (no fallback)"
        )
    return adapter_path(name)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_df_adapters.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Full suite + commit**

```bash
.venv/bin/python -m pytest dark-factory/tests -q | tail -1   # expect 117 passed, 1 skipped
git add dark-factory/scripts/df_adapters.py dark-factory/tests/test_df_adapters.py
git commit -m "feat(dark-factory): builder registry + capability probe (no silent fallback)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: SKILL.md cross-model workflow + docs

**Files:**
- Modify: `dark-factory/SKILL.md` (config/engage step)
- Modify: `dark-factory/references/role-adapters.md`
- Modify: `dark-factory/references/config-reference.md`

**Interfaces:**
- Consumes: `df_adapters` (Task 3) conceptually (the workflow tells the operator to run it).
- Produces: operator guidance only; no code.

- [ ] **Step 1: Read the current SKILL.md config/engage step**

Read `dark-factory/SKILL.md`. Find the workflow step that writes `config.json` / sets `roles.builder.adapter` (currently it hardcodes the claude adapter path).

- [ ] **Step 2: Replace that step with the cross-model choice**

Change the builder-adapter step to (adjust surrounding numbering to match the file):

```markdown
- **Choose the builder model.** Run
  `python3 <skill_dir>/scripts/df_adapters.py -c "import df_adapters,json;print(json.dumps(df_adapters.available_builders()))"`
  (or import `available_builders()`) to see which of claude / codex / gemini
  are installed. Ask the user which model should BUILD; offer only the available
  ones. Set `roles.builder.adapter` to `<skill_dir>/scripts/adapters/<name>`.
  **No silent fallback** — if the chosen model's CLI is absent the run fails
  closed (`resolve_builder` raises; the run aborts). Verification stays the
  deterministic scenario runner regardless of builder — dark-factory has no LLM
  judge to swap.
- **Vendor diversity (recommended, not required).** Author the spec and the
  holdout scenarios with a *different* model/session than the builder (e.g.
  Claude authors, Codex builds). Different vendors have different blind spots,
  which hardens the holdout — the "second librarian from a different library."
  Never author scenarios in the same session that will drive the builder.
```

- [ ] **Step 3: Update role-adapters.md**

Replace the M1 "Codex/Gemini adapters land in M4" line with:

```markdown
Shipped adapters (protocol 0.1, all in `scripts/adapters/`):
- `claude` — claude CLI, headless, `--permission-mode acceptEdits`.
- `codex` — `codex exec`, Codex's own sandbox disabled (dark-factory provides
  the OS sandbox), no `-m` pin (uses ~/.codex default).
- `gemini` — Gemini CLI, `--yolo --prompt`.

Pick the builder with `df_adapters.available_builders()` (installed CLIs) and
`df_adapters.resolve_builder(name)` — the latter raises rather than substitute a
different model. Under the `standard` tier the OS sandbox denies the holdout to
whatever model builds, so cross-model builders inherit isolation. Verification is
always the deterministic scenario runner — there is no cross-model "judge".
```

- [ ] **Step 4: Update config-reference.md**

Change the `roles.builder.adapter` row to note the three shipped adapters and no-fallback:

```markdown
| `roles.builder.adapter` | str | path to a protocol-0.1 adapter executable. Shipped: `scripts/adapters/{claude,codex,gemini}`. The chosen model's CLI must be installed (no silent fallback — an absent CLI aborts the run). |
```

- [ ] **Step 5: Verify docs match reality + commit**

```bash
# the documented df_adapters call actually works:
.venv/bin/python -c "import sys; sys.path.insert(0,'dark-factory/scripts'); import df_adapters, json; print(json.dumps(df_adapters.available_builders()))"
.venv/bin/python -m pytest dark-factory/tests -q | tail -1   # still 117 passed, 1 skipped (docs-only)
git add dark-factory/SKILL.md dark-factory/references/role-adapters.md dark-factory/references/config-reference.md
git commit -m "docs(dark-factory): cross-model builder selection + vendor-diversity guidance

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Live cross-model smoke run (Codex) + capability report

**Files:**
- None committed (smoke run is human-observed, like M1 Task 10). Optionally create `dark-factory/references/example-cross-model.md` capturing the observed output.

**Interfaces:**
- Consumes: everything shipped in Tasks 1–4 + the real `codex` CLI (known installed on this machine).

- [ ] **Step 1: Report installed builders**

```bash
cd /Users/alonadelson/Projects/ai_projects/skills
.venv/bin/python -c "import sys; sys.path.insert(0,'dark-factory/scripts'); import df_adapters, json; print(json.dumps(df_adapters.available_builders(), indent=2))"
```

Record which are present (expect `codex: true`; `gemini` may be false).

- [ ] **Step 2: Run a real Codex-built dark-factory run (cooperative tier, toy greet spec)**

Reuse the M1 smoke-run control root but point the builder adapter at codex. Set up a fresh control root in the scratchpad (`$SCRATCH/df-xmodel/control`) with the greet `spec.md`, two scenarios (BHV-001 greets, BHV-002 usage error), and `config.json` with `"assurance":"cooperative"`, `"feedback":"ids"`, `"max_iterations":3`, and `roles.builder.adapter` = `<repo>/dark-factory/scripts/adapters/codex`. Then:

```bash
python3 dark-factory/scripts/supervisor.py run --control-root "$SCRATCH/df-xmodel/control"
```

Expected: Codex builds `greet.py` from spec-only (never seeing the scenarios), the deterministic verifier runs the hidden scenarios, and the run CONVERGES (cooperative → `COMPLETE_UNQUALIFIED`). If Codex needs a flag adjustment (auth/sandbox), capture the exact error and note it — that's the value of the live run.

- [ ] **Step 3: Verify convergence + no holdout leak, then show the user**

```bash
CR="$SCRATCH/df-xmodel/control"; RUN_DIR=$(ls -d "$CR"/runs/* | tail -1); WS=$(ls -d "$SCRATCH"/df-xmodel/ws/* | tail -1)
python3 dark-factory/scripts/supervisor.py verify-manifest --run-dir "$RUN_DIR"
grep -rl "greets by name\|usage error" "$WS" "$RUN_DIR"/prompt_iter_*.md 2>/dev/null && echo "LEAK!" || echo "no holdout leak"
cat "$WS/greet.py" 2>/dev/null; (cd "$WS" && python3 greet.py Alon)
```

Show the user: which model built, CONVERGED line, verify-manifest OK, no-leak result, and the artifact working. This is the human-observed acceptance of cross-model. If Codex's CLI flags needed changes to run, apply them to `scripts/adapters/codex`, re-run, and commit the adapter fix separately.

- [ ] **Step 4 (optional): capture the run in a reference doc**

If it converged, write `dark-factory/references/example-cross-model.md` with the observed transcript (model, journal states, verify OK, no-leak), and commit it.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M4 builder cross-model slice):** Codex + Gemini builder adapters on the proven protocol 0.1 (§3, §7.8); a capability probe that offers only installed tools and a `resolve_builder` gate that never substitutes (no silent fallback, §7.8); the "which model builds?" invocation step + vendor-diversity authoring guidance (§3.1 principled defaults — different-vendor test authority hardens the holdout); confirmation that under `standard` tier the OS sandbox denies the holdout to any builder; a live Codex-built run as human-observed acceptance.

**Deliberately deferred (later milestones):** cross-model for the *verifier* is intentionally NOT built — verification is the deterministic scenario runner by design (§5.1); an LLM judge would be gameable. Skill-composition (per-tier allowlist, §3B) and KB integration (§9) are a separate M4b (independent security surface). `hardened`/`enterprise` sandbox tiers remain M5.

**Known M4 honesty notes:** the Codex/Gemini adapter CLI invocations are version-sensitive (flags like `--sandbox danger-full-access`, `--skip-git-repo-check`, `--yolo`, `--prompt` may shift across CLI versions); the PATH-shim tests prove the adapter *contract* (argv shape, ok/error/timeout handling) without asserting a specific CLI version, and Task 5's live run validates the real flags on this machine. Gemini is unverified live if its CLI isn't installed (honest — like Linux bwrap in M2b).
```
