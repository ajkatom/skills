# dark-factory M2a — Resumable Per-Iteration Checkpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the human supervise the build/verify loop iteration-by-iteration (autonomy L4) — the supervisor pauses after each non-converging iteration, writes a human-readable checkpoint report of the twin-observed results, and exits *resumably*; the human then continues, accepts, or aborts.

**Architecture:** Refactor the supervisor's inline loop into a re-enterable `_run_loop(...)` driven by a persisted `state.json`, so a run can start fresh OR resume from a saved iteration. A new `checkpoint` config field (`pause`|`auto`, default `pause` at autonomy 4 / `auto` at 5) gates whether the loop stops at each iteration boundary. Pausing is a distinct non-terminal outcome (exit code 10) — not the manifest-finalizing terminal states — and a new `resume` subcommand re-acquires the lock and continues from `state.json`.

**Tech Stack:** Python ≥ 3.9 stdlib only (as M1). `pytest` for tests. Builds directly on the merged M1 code in `dark-factory/`.

**Source spec:** `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md` — §2.1 (L4 = evaluate outcomes each iteration), §6 (checkpoints: accept · adjust spec · continue · abort), §6.2/§7.7 (resumable runs, sole state-changer). This plan implements the M2a checkpoint slice; the `standard`-tier sandbox is M2b.

## Global Constraints

- **Runtime code is Python stdlib only** — nothing under `dark-factory/scripts/` may import a pip dependency.
- **The barrier is unchanged:** the checkpoint report is written to `runs/<id>/` (control side) and carries only behavior IDs + pass/fail + taxonomy + observed exit codes — **never** scenario `title`/`given`/`when`/`then` bodies, and it is **never** written into the workspace.
- **The supervisor remains the SOLE state-changer.** Only it writes `runs/`, including `state.json`.
- **Exit codes:** `0` converged (or human-accepted), `2` config/usage/build/abort error, `3` iteration cap reached, **`10` paused at a checkpoint** (new; the only non-terminal exit).
- **Pause is NOT a terminal state** — no `manifest.json` is finalized on pause (the manifest is finalized only at CONVERGED/CAP_REACHED/ABORTED/ACCEPTED terminals). `state.json` is the pause artifact.
- **`checkpoint` config values:** exactly `"pause"` or `"auto"`. Default when the key is absent: `pause` if `autonomy == 4`, `auto` if `autonomy == 5`.
- **All hashing = SHA-256 over canonical JSON** (reuse `df_common`).
- **Journal states** add: `CHECKPOINT` (non-terminal), `ACCEPTED_BY_HUMAN` (terminal), `ABORTED_BY_HUMAN` (terminal). Existing states unchanged.
- **Tests run with** `.venv/bin/python -m pytest dark-factory/tests -v` from the repo root `/Users/alonadelson/Projects/ai_projects/skills`.
- **Every commit message ends with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- **Cooperative-tier honesty is preserved:** a run that is accepted-by-human without passing all scenarios is recorded as **waived/unverified**, never a qualified ship-candidate.

## File Structure

```
dark-factory/scripts/
  df_config.py          # MODIFY — validate `checkpoint`; inject cfg["_checkpoint"] resolved default
  supervisor.py         # MODIFY — extract _run_loop; add save/load state, checkpoint report,
                        #          CHECKPOINT/ACCEPTED/ABORTED states, exit 10, `resume` subcommand
dark-factory/references/
  config-reference.md   # MODIFY — document the `checkpoint` field + resume workflow
dark-factory/tests/
  test_config.py        # MODIFY — checkpoint validation + default resolution
  test_checkpoints.py   # CREATE — pause/report/state + resume(continue|accept|abort)
  test_e2e_checkpoint.py# CREATE — pause → resume-continue → converge, barrier still holds
```

Control-plane additions at runtime (written only by the supervisor):

```
<control_root>/runs/<invocation_id>/
  state.json            # {state_version, next_iter, feedback, workspace, run_dir} — pause artifact
  checkpoint_iter_N.md  # human-readable per-iteration report (control side; behavior IDs + results)
```

---

### Task 1: Config — `checkpoint` field with autonomy-based default

**Files:**
- Modify: `dark-factory/scripts/df_config.py`
- Modify: `dark-factory/tests/test_config.py`
- Modify: `dark-factory/references/config-reference.md`

**Interfaces:**
- Consumes: existing `load_config(control_root) -> dict` (raises `ConfigError`).
- Produces: `load_config` now injects `cfg["_checkpoint"]` ∈ {`"pause"`, `"auto"`}, resolved as: explicit `checkpoint` value if present (validated), else `"pause"` when `cfg["autonomy"] == 4`, else `"auto"`. An explicit `checkpoint` not in {`pause`,`auto`} raises `ConfigError`.

- [ ] **Step 1: Write the failing tests** — add to `dark-factory/tests/test_config.py`:

```python
def test_checkpoint_defaults_to_pause_at_autonomy_4(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, autonomy=4)  # no explicit checkpoint
    cfg = df_config.load_config(str(cr))
    assert cfg["_checkpoint"] == "pause"


def test_checkpoint_defaults_to_auto_at_autonomy_5(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, autonomy=5)
    cfg = df_config.load_config(str(cr))
    assert cfg["_checkpoint"] == "auto"


def test_explicit_checkpoint_overrides_default(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, autonomy=4, checkpoint="auto")
    cfg = df_config.load_config(str(cr))
    assert cfg["_checkpoint"] == "auto"


def test_invalid_checkpoint_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, checkpoint="sometimes")
    with pytest.raises(df_config.ConfigError, match="checkpoint"):
        df_config.load_config(str(cr))
```

(The `write_config` helper already exists in this file and passes `**overrides` into the JSON config; `autonomy=4` is already its default.)

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_config.py -k checkpoint -v
```

Expected: FAIL — `KeyError: '_checkpoint'` (and the invalid case raises nothing).

- [ ] **Step 3: Implement in `df_config.py`** — add validation + injection just before the final `cfg = dict(raw)` block. Insert this block after the existing `adapter` check and before `cfg = dict(raw)`:

```python
    checkpoint = raw.get("checkpoint")
    if checkpoint is None:
        checkpoint = "pause" if raw.get("autonomy") == 4 else "auto"
    elif checkpoint not in ("pause", "auto"):
        raise ConfigError("checkpoint must be 'pause' or 'auto'")
```

Then, inside the existing `cfg` construction (after `cfg["_config_sha256"] = ...`), add:

```python
    cfg["_checkpoint"] = checkpoint
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_config.py -v
```

Expected: all config tests pass (existing + 4 new).

- [ ] **Step 5: Document the field** — in `dark-factory/references/config-reference.md`, add a row to the field table:

```markdown
| `checkpoint` | str | `"pause"` \| `"auto"`. Default: `pause` at autonomy 4, `auto` at autonomy 5. `pause` stops the loop after each non-converging iteration (exit 10) for human review via `resume`. |
```

- [ ] **Step 6: Commit**

```bash
git add dark-factory/scripts/df_config.py dark-factory/tests/test_config.py dark-factory/references/config-reference.md
git commit -m "feat(dark-factory): checkpoint config field with autonomy-based default

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: State persistence + checkpoint report writer

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Modify: `dark-factory/tests/test_checkpoints.py` (create)

**Interfaces:**
- Consumes: `df_common.canonical_json`, `df_common.atomic_write`; `_now` (already in supervisor).
- Produces (module-level functions in supervisor.py):
  - `save_state(run_dir: str, next_iter: int, feedback, workspace: str) -> None` — writes `run_dir/state.json` atomically: `{"state_version": "0.1", "next_iter": int, "feedback": <dict|null>, "workspace": str, "run_dir": str}`.
  - `load_state(run_dir: str) -> dict` — reads and returns it; raises `FileNotFoundError` if absent.
  - `latest_paused_run(control_root: str) -> str | None` — returns the `run_dir` of the most recent run that has a `state.json` (by directory name sort, which is timestamp-ordered), else None.
  - `write_checkpoint_report(run_dir: str, iteration: int, report: dict) -> str` — writes `run_dir/checkpoint_iter_{iteration}.md` (human-readable; behavior IDs + pass/fail + taxonomy + observed exit code only) and returns its path.

- [ ] **Step 1: Write the failing tests** — create `dark-factory/tests/test_checkpoints.py`:

```python
import json
import os

import pytest

import supervisor

SAMPLE_REPORT = {
    "report_version": "0.1",
    "all_pass": False,
    "results": [
        {"id": "BHV-001-S1", "behavior_id": "BHV-001", "pass": False,
         "taxonomy": "wrong_output", "observed": {"exit_code": 0, "stdout": "x", "stderr": ""}},
        {"id": "BHV-002-S1", "behavior_id": "BHV-002", "pass": True,
         "taxonomy": None, "observed": {"exit_code": 2, "stdout": "", "stderr": "usage"}},
    ],
}


def test_save_and_load_state_roundtrip(tmp_path):
    rd = tmp_path / "runs" / "r1"
    rd.mkdir(parents=True)
    supervisor.save_state(str(rd), next_iter=3, feedback={"failing_count": 1}, workspace="/ws/x")
    st = supervisor.load_state(str(rd))
    assert st["state_version"] == "0.1"
    assert st["next_iter"] == 3
    assert st["feedback"] == {"failing_count": 1}
    assert st["workspace"] == "/ws/x"
    assert st["run_dir"] == str(rd)


def test_latest_paused_run_picks_newest_with_state(tmp_path):
    cr = tmp_path / "control"
    (cr / "runs" / "20260101T000000Z-aaaa").mkdir(parents=True)
    newer = cr / "runs" / "20260201T000000Z-bbbb"
    newer.mkdir(parents=True)
    # only the newer one is paused (has state.json)
    supervisor.save_state(str(newer), 2, None, str(tmp_path / "ws"))
    assert supervisor.latest_paused_run(str(cr)) == str(newer)


def test_latest_paused_run_none_when_no_state(tmp_path):
    cr = tmp_path / "control"
    (cr / "runs" / "20260101T000000Z-aaaa").mkdir(parents=True)
    assert supervisor.latest_paused_run(str(cr)) is None


def test_checkpoint_report_has_ids_and_results_no_scenario_text(tmp_path):
    rd = tmp_path / "runs" / "r1"
    rd.mkdir(parents=True)
    path = supervisor.write_checkpoint_report(str(rd), 1, SAMPLE_REPORT)
    text = open(path, encoding="utf-8").read()
    assert "BHV-001" in text and "BHV-002" in text
    assert "wrong_output" in text
    assert "1/2" in text  # passing summary
    # observed exit codes are fine for the (trusted) human; raw stdout bodies are not echoed
    assert "stdout" not in text
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_checkpoints.py -v
```

Expected: FAIL — `AttributeError: module 'supervisor' has no attribute 'save_state'`.

- [ ] **Step 3: Implement in `supervisor.py`** — add these functions after the `Journal` class:

```python
def save_state(run_dir, next_iter, feedback, workspace):
    atomic_write(
        os.path.join(run_dir, "state.json"),
        canonical_json({
            "state_version": "0.1",
            "next_iter": next_iter,
            "feedback": feedback,
            "workspace": workspace,
            "run_dir": run_dir,
        }),
    )


def load_state(run_dir):
    with open(os.path.join(run_dir, "state.json"), encoding="utf-8") as f:
        return json.load(f)


def latest_paused_run(control_root):
    runs_dir = os.path.join(control_root, "runs")
    if not os.path.isdir(runs_dir):
        return None
    paused = [
        os.path.join(runs_dir, name)
        for name in sorted(os.listdir(runs_dir), reverse=True)
        if os.path.exists(os.path.join(runs_dir, name, "state.json"))
    ]
    return paused[0] if paused else None


def write_checkpoint_report(run_dir, iteration, report):
    passing = sum(1 for r in report["results"] if r["pass"])
    total = len(report["results"])
    lines = [
        f"# Checkpoint — iteration {iteration}",
        "",
        f"Passing: **{passing}/{total}**  (twin-observed, cooperative tier — unqualified)",
        "",
        "| behavior | scenario | pass | taxonomy | exit |",
        "|---|---|:--:|---|--:|",
    ]
    for r in report["results"]:
        mark = "✅" if r["pass"] else "❌"
        tax = r["taxonomy"] or ""
        code = r["observed"].get("exit_code")
        lines.append(f"| {r['behavior_id']} | {r['id']} | {mark} | {tax} | {code} |")
    lines += [
        "",
        "Decide: `resume --decision continue` (build again) · edit `spec.md` then "
        "`resume --decision continue` (adjust) · `resume --decision accept` (stop, "
        "waived/unverified) · `resume --decision abort`.",
        "",
    ]
    path = os.path.join(run_dir, f"checkpoint_iter_{iteration}.md")
    atomic_write(path, "\n".join(lines))
    return path
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_checkpoints.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/supervisor.py dark-factory/tests/test_checkpoints.py
git commit -m "feat(dark-factory): checkpoint state persistence and report writer

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Refactor the loop into a re-enterable `_run_loop` that pauses

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Modify: `dark-factory/tests/test_checkpoints.py`

**Interfaces:**
- Consumes: `save_state`, `write_checkpoint_report` (Task 2); existing `compose_prompt`, `invoke_adapter`, `run_all`, `project_feedback`, `finalize_manifest`, `Journal`.
- Produces:
  - `PAUSED = 10` (module constant; the paused exit code).
  - `_run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir, adapter, timeout_s, workspace, start_iter, feedback) -> int` — runs iterations `start_iter..max_iterations`. Returns `0` (converged), `2` (build error), `3` (cap), or `PAUSED` (10, when `cfg["_checkpoint"] == "pause"` after a non-converging iteration). On pause it writes the checkpoint report, calls `save_state(run_dir, next_iter, feedback, workspace)`, journals `CHECKPOINT`, and returns `PAUSED` **without** finalizing a manifest. On a real terminal it deletes `state.json` if present, then finalizes the manifest as today.
  - `_run_locked` is rewritten to call `_run_loop(..., start_iter=1, feedback=None)` after the SNAPSHOT step (all pre-loop setup unchanged).

- [ ] **Step 1: Write the failing tests** — add to `dark-factory/tests/test_checkpoints.py` (imports `setup_control`, `FAKE` from test_supervisor):

```python
from test_supervisor import FAKE, setup_control, read_journal


def test_pause_mode_stops_after_first_iteration_with_exit_10(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # FAKE builds buggy first, fixes after feedback
    # setup_control defaults autonomy 4 → checkpoint pause
    rc = supervisor.run(str(cr), None)
    assert rc == 10
    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 1  # paused after iteration 1
    assert "CHECKPOINT" in states
    assert "CONVERGED" not in states
    run_dir = cr / "runs" / run_id
    assert (run_dir / "state.json").exists()
    assert (run_dir / "checkpoint_iter_1.md").exists()
    assert not (run_dir / "manifest.json").exists()  # pause is non-terminal


def test_auto_mode_runs_to_convergence_without_pausing(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "CHECKPOINT" not in states and "CONVERGED" in states
```

Note: `setup_control` must accept a `checkpoint` kwarg. In `dark-factory/tests/test_supervisor.py`, update `setup_control` to add `checkpoint=None` to its signature and, when not None, include `"checkpoint": checkpoint` in the config dict it writes. (This is a test-helper change; make it in this task.)

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_checkpoints.py -k "pause_mode or auto_mode" -v
```

Expected: FAIL — pause path not implemented (run converges/returns 0, no exit 10).

- [ ] **Step 3: Refactor `supervisor.py`.** First add the constant near the top (after `LockError`):

```python
PAUSED = 10
```

Then extract the loop. Replace the current `for i in range(1, cfg["max_iterations"] + 1):` block **and** the post-loop CAP handling inside `_run_locked` with a single call:

```python
    return _run_loop(
        cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
        adapter, timeout_s, workspace, start_iter=1, feedback=None,
    )
```

And define `_run_loop` (its body is the M1 loop, with the pause branch added and terminal branches deleting `state.json`):

```python
def _run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
              adapter, timeout_s, workspace, start_iter, feedback):

    def _clear_state():
        p = os.path.join(run_dir, "state.json")
        if os.path.exists(p):
            os.unlink(p)

    last_report = None
    for i in range(start_iter, cfg["max_iterations"] + 1):
        prompt = compose_prompt(spec_text, feedback)
        prompt_file = os.path.join(run_dir, f"prompt_iter_{i}.md")
        atomic_write(prompt_file, prompt)
        resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s)
        if err or resp.get("status") != "ok":
            journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=err or resp.get("detail", ""))
            finalize_manifest(run_dir, dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=i))
            _clear_state()
            sys.stderr.write(f"dark-factory: build error at iteration {i}\n")
            return 2
        journal.write("BUILD", iteration=i)

        try:
            report = run_all(scenarios_dir, workspace)
        except OracleError as e:
            journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=f"invalid scenarios: {e}")
            finalize_manifest(run_dir, dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=i))
            _clear_state()
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        last_report = report
        atomic_write(os.path.join(run_dir, f"verifier_report_iter_{i}.json"), canonical_json(report))
        passing = sum(1 for r in report["results"] if r["pass"])
        journal.write("VERIFY", iteration=i, passing=passing, total=len(report["results"]))

        if report["all_pass"]:
            journal.write("CONVERGED", iteration=i)
            finalize_manifest(run_dir, dict(manifest_base, outcome="COMPLETE_UNQUALIFIED", iterations=i))
            _clear_state()
            print(f"dark-factory: CONVERGED (unqualified, cooperative tier). "
                  f"Workspace: {workspace}  Run: {run_dir}")
            return 0

        feedback = project_feedback(report)
        atomic_write(os.path.join(run_dir, f"feedback_iter_{i}.json"), canonical_json(feedback))
        atomic_write(os.path.join(workspace, "feedback.json"), canonical_json(feedback))
        journal.write("FEEDBACK", iteration=i, failing=[f["behavior_id"] for f in feedback["failures"]])

        if cfg["_checkpoint"] == "pause" and i < cfg["max_iterations"]:
            write_checkpoint_report(run_dir, i, report)
            save_state(run_dir, next_iter=i + 1, feedback=feedback, workspace=workspace)
            journal.write("CHECKPOINT", iteration=i,
                          failing=[f["behavior_id"] for f in feedback["failures"]])
            print(f"dark-factory: PAUSED at checkpoint (iteration {i}). "
                  f"Review {run_dir}/checkpoint_iter_{i}.md, then "
                  f"`supervisor.py resume --control-root {cfg.get('_control_root', '<CR>')}`.")
            return PAUSED

    failing = sorted({r["behavior_id"] for r in last_report["results"] if not r["pass"]})
    journal.write("CAP_REACHED", failing_behaviors=failing,
                  note="likely spec ambiguity — human decision needed")
    finalize_manifest(run_dir, dict(manifest_base, outcome="CAP_REACHED", iterations=cfg["max_iterations"]))
    _clear_state()
    print(f"dark-factory: CAP REACHED after {cfg['max_iterations']} iterations. "
          f"Still failing: {', '.join(failing)}. Run: {run_dir}")
    return 3
```

(The `_run_locked` you are editing already builds `manifest_base`, sets `snapshot_sha256` on it, writes the INIT and SNAPSHOT journal entries, and defines `spec_text`, `scenarios_dir`, `adapter`, `timeout_s`, `workspace`. Keep all of that; only the loop tail changes to the single `_run_loop(...)` call. Also add `cfg["_control_root"] = control_root` right after `load_config` in `run()` so the pause message can print the path — a one-line addition in `run()`.)

- [ ] **Step 4: Run the focused tests, then the full suite**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_checkpoints.py -v
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: the two new pause/auto tests pass; the **existing** `test_supervisor.py` tests still pass — note `test_converging_run_exits_zero_and_journals` uses the default (autonomy 4) which is now `pause`, so that test will now see exit 10, not 0. **Update that existing test** to pass `checkpoint="auto"` to `setup_control` so it still asserts the straight-through convergence path (the pause path is covered by the new tests). Do the same for any existing test_supervisor/test_manifest/test_e2e test that relied on a default-autonomy run converging in one call (search for `setup_control(` and add `checkpoint="auto"` where the test asserts CONVERGED/CAP without expecting a pause). This keeps each test asserting exactly one loop mode.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/supervisor.py dark-factory/tests/test_checkpoints.py dark-factory/tests/test_supervisor.py dark-factory/tests/test_manifest.py dark-factory/tests/test_e2e_loop.py
git commit -m "refactor(dark-factory): re-enterable _run_loop with pause-at-checkpoint

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: The `resume` subcommand (continue · accept · abort)

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Modify: `dark-factory/tests/test_checkpoints.py`

**Interfaces:**
- Consumes: `load_state`, `latest_paused_run`, `_run_loop`, `acquire_lock`/`release_lock`, `load_config`, `finalize_manifest`, `_scenario_set_hash`, `sha256_str`, `sha256_file`.
- Produces:
  - `resume(control_root: str, decision: str) -> int` — `decision` ∈ {`"continue"`,`"accept"`,`"abort"`}. Finds the latest paused run; re-acquires the lock; re-reads `spec.md` (so an edited spec is honored — the "adjust" path is edit-then-`continue`). Reconstructs `journal`, `manifest_base` (deterministically, as in `_run_locked`), and appends. Then:
    - `continue` → calls `_run_loop(..., start_iter=state["next_iter"], feedback=state["feedback"])` and returns its code (0/2/3/10 again).
    - `accept` → journals `ACCEPTED_BY_HUMAN` (with the failing behavior IDs from the last verifier report), finalizes the manifest with `outcome="ACCEPTED_WAIVED"`, deletes `state.json`, prints a **waived/unverified** notice, returns 0.
    - `abort` → journals `ABORTED_BY_HUMAN`, finalizes `outcome="ABORTED_BY_HUMAN"`, deletes `state.json`, returns 2.
  - No paused run → stderr message, return 2.
  - CLI: `supervisor.py resume --control-root CR [--decision continue|accept|abort]` (default `continue`).

- [ ] **Step 1: Write the failing tests** — add to `dark-factory/tests/test_checkpoints.py`:

```python
def test_resume_continue_converges(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # pause mode
    assert supervisor.run(str(cr), None) == 10          # paused after iter 1
    assert supervisor.resume(str(cr), "continue") == 0  # iter 2 converges
    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 2 and "CONVERGED" in states
    assert not (cr / "runs" / run_id / "state.json").exists()  # cleared at terminal
    assert (cr / "runs" / run_id / "manifest.json").exists()


def test_resume_abort_exits_2_and_is_terminal(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "abort") == 2
    entries, run_id = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BY_HUMAN"
    assert not (cr / "runs" / run_id / "state.json").exists()


def test_resume_accept_is_waived_and_exits_0(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "accept") == 0
    entries, run_id = read_journal(cr)
    assert entries[-1]["state"] == "ACCEPTED_BY_HUMAN"
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["outcome"] == "ACCEPTED_WAIVED"
    assert manifest["qualified"] is False


def test_resume_with_no_paused_run_exits_2(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.run(str(cr), None) == 0  # converges, no pause
    assert supervisor.resume(str(cr), "continue") == 2  # nothing to resume
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_checkpoints.py -k resume -v
```

Expected: FAIL — `AttributeError: module 'supervisor' has no attribute 'resume'`.

- [ ] **Step 3: Implement `resume` in `supervisor.py`.** Add this function (it mirrors the setup half of `_run_locked`, then dispatches):

```python
def resume(control_root, decision="continue"):
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    cfg["_control_root"] = control_root

    run_dir = latest_paused_run(control_root)
    if run_dir is None:
        sys.stderr.write("dark-factory: no paused run to resume\n")
        return 2

    lock = acquire_lock(control_root)
    try:
        state = load_state(run_dir)
        journal = Journal(os.path.join(run_dir, "journal.jsonl"))
        spec_text = open(os.path.join(control_root, "spec.md"), encoding="utf-8").read()
        scenarios_dir = os.path.join(control_root, "scenarios")
        adapter = cfg["roles"]["builder"]["adapter"]
        timeout_s = cfg["roles"]["builder"].get("timeout_s", 600)
        manifest_base = {
            "invocation": os.path.basename(run_dir),
            "tier": cfg["assurance"],
            "qualified": cfg["_qualified"],
            "config_sha256": cfg["_config_sha256"],
            "spec_sha256": sha256_str(spec_text),
            "scenario_set_sha256": _scenario_set_hash(scenarios_dir),
            "adapter_sha256": sha256_file(adapter) if os.path.exists(adapter) else None,
            "snapshot_sha256": None,
        }

        if decision == "abort":
            journal.write("ABORTED_BY_HUMAN")
            finalize_manifest(run_dir, dict(manifest_base, outcome="ABORTED_BY_HUMAN",
                                            iterations=state["next_iter"] - 1))
            os.unlink(os.path.join(run_dir, "state.json"))
            print("dark-factory: ABORTED by human.")
            return 2
        if decision == "accept":
            journal.write("ACCEPTED_BY_HUMAN",
                          note="human accepted a non-passing build — waived/unverified")
            finalize_manifest(run_dir, dict(manifest_base, outcome="ACCEPTED_WAIVED",
                                            iterations=state["next_iter"] - 1))
            os.unlink(os.path.join(run_dir, "state.json"))
            print("dark-factory: ACCEPTED (waived/unverified — not a qualified ship-candidate).")
            return 0
        # decision == "continue"
        return _run_loop(
            cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
            adapter, timeout_s, state["workspace"],
            start_iter=state["next_iter"], feedback=state["feedback"],
        )
    finally:
        release_lock(lock)
```

- [ ] **Step 4: Add the CLI subcommand.** In `main()`, after the `verify-manifest` parser, add:

```python
    p_res = sub.add_parser("resume", help="resume a paused run")
    p_res.add_argument("--control-root", required=True)
    p_res.add_argument("--decision", choices=["continue", "accept", "abort"], default="continue")
```

and in the dispatch chain add:

```python
    elif args.cmd == "resume":
        sys.exit(resume(args.control_root, args.decision))
```

- [ ] **Step 5: Run the focused tests, then the full suite**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_checkpoints.py -v
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: all checkpoint tests pass; full suite green.

- [ ] **Step 6: Commit**

```bash
git add dark-factory/scripts/supervisor.py dark-factory/tests/test_checkpoints.py
git commit -m "feat(dark-factory): resume subcommand (continue/accept/abort) for paused runs

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: E2E — pause → resume → converge, with the barrier intact across the pause

**Files:**
- Create: `dark-factory/tests/test_e2e_checkpoint.py`

**Interfaces:**
- Consumes: the supervisor CLI as a subprocess; `test_supervisor.setup_control`, `MARKER`, `FAKE`.
- Produces: executable proof that a paused-then-resumed run converges and that the holdout MARKER never leaks across the pause (checkpoint report, state.json, prompts, workspace, stdout).

- [ ] **Step 1: Write the test** — create `dark-factory/tests/test_e2e_checkpoint.py`:

```python
import json
import os
import subprocess
import sys

from test_supervisor import FAKE, MARKER, setup_control

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def _run(cr, *args):
    return subprocess.run([sys.executable, SUP, *args, "--control-root", str(cr)],
                          capture_output=True, text=True, timeout=120)


def test_pause_then_resume_converges_without_leaking_holdout(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # pause mode (autonomy 4 default)

    p1 = _run(cr, "run")
    assert p1.returncode == 10, p1.stderr           # paused at checkpoint
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    assert (run_dir / "checkpoint_iter_1.md").exists()
    assert (run_dir / "state.json").exists()

    # MARKER (planted in scenario titles/givens) must not be in anything the human-review
    # surface shares with the builder, nor in the checkpoint artifacts.
    for name in os.listdir(run_dir):
        if name.startswith(("prompt_iter_", "feedback_iter_", "checkpoint_iter_")) or name == "state.json":
            assert MARKER not in (run_dir / name).read_text(encoding="utf-8"), name

    p2 = _run(cr, "resume", "--decision", "continue")
    assert p2.returncode == 0, p2.stderr            # converged after resume
    assert not (run_dir / "state.json").exists()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"

    # built artifact really works; MARKER absent from the whole workspace
    st = json.loads("[" + ",".join(
        (run_dir / "journal.jsonl").read_text().strip().splitlines()) + "]")
    workspace = next(e["data"]["workspace"] for e in st if e["state"] == "SNAPSHOT")
    out = subprocess.run(["python3", "greet.py", "World"], cwd=workspace,
                         capture_output=True, text=True)
    assert out.stdout.strip() == "Hello, World!"
    for dp, _, fns in os.walk(workspace):
        for fn in fns:
            assert MARKER.encode() not in open(os.path.join(dp, fn), "rb").read()
```

- [ ] **Step 2: Run it**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_e2e_checkpoint.py -v
```

Expected: PASS. If it fails, the failure names the broken invariant — fix the responsible earlier task, don't weaken the test.

- [ ] **Step 3: Run the full suite**

```bash
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add dark-factory/tests/test_e2e_checkpoint.py
git commit -m "test(dark-factory): e2e pause/resume converges with barrier intact across the pause

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: SKILL.md + config docs — the checkpoint/resume workflow

**Files:**
- Modify: `dark-factory/SKILL.md`

**Interfaces:**
- Consumes: everything shipped in Tasks 1–5.
- Produces: the user-facing description of the pause/resume loop so the skill drives it.

- [ ] **Step 1: Update `dark-factory/SKILL.md`** — replace the workflow's Step 5 ("Run.") and Step 6 ("Report.") with:

```markdown
5. **Run.** `python3 <skill_dir>/scripts/supervisor.py run --control-root <control_root> [--project-src <dir>]`
   Exit 0 = converged/accepted · 3 = cap reached · 2 = config/build/abort error ·
   **10 = paused at a checkpoint** (autonomy 4 / `checkpoint: pause`).
6. **At a checkpoint (exit 10).** Show the user `runs/<id>/checkpoint_iter_N.md` (per-behavior
   pass/fail — no scenario text). Then, on their decision, run:
   - **continue** → `supervisor.py resume --control-root <cr> --decision continue`
   - **adjust spec** → edit `<control_root>/spec.md`, then `resume --decision continue`
   - **accept** (stop, waived/unverified) → `resume --decision accept`
   - **abort** → `resume --decision abort`
   Repeat until exit 0/2/3.
7. **Report.** Outcome, iterations, per-behavior status from `journal.jsonl`, the workspace
   path, and `verify-manifest --run-dir <run_dir>`. State that cooperative tier is unqualified.
```

- [ ] **Step 2: Verify the doc references match the shipped CLI** — confirm the subcommands/flags named in SKILL.md exist:

```bash
.venv/bin/python dark-factory/scripts/supervisor.py resume --help
.venv/bin/python dark-factory/scripts/supervisor.py run --help
```

Expected: both print usage without error; `resume` shows `--decision {continue,accept,abort}`.

- [ ] **Step 3: Run the full suite one final time**

```bash
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add dark-factory/SKILL.md
git commit -m "docs(dark-factory): document the checkpoint/resume workflow in SKILL.md

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review Notes (plan ↔ spec)

**Covered (M2a slice):** L4 per-iteration human evaluation of twin-observed outcomes (§2.1); the four checkpoint decisions accept · adjust · continue · abort (§6); resumability via persisted state (§6.2); supervisor remains sole state-changer (§7.7); `ship-candidate`/qualified semantics preserved — human `accept` of a non-passing build is recorded `ACCEPTED_WAIVED`, `qualified:false` (spec's "ship-candidate = FSM terminal only"); the barrier holds across the pause (checkpoint report is control-side, IDs+results only, never in the workspace).

**Type/name consistency:** `_checkpoint` (config) · `save_state`/`load_state`/`latest_paused_run`/`write_checkpoint_report` (Task 2) · `PAUSED=10` and `_run_loop(...)` signature (Task 3) · `resume(control_root, decision)` and states `CHECKPOINT`/`ACCEPTED_BY_HUMAN`/`ABORTED_BY_HUMAN` + outcomes `ACCEPTED_WAIVED`/`ABORTED_BY_HUMAN` (Task 4) — all used consistently across tasks.

**Deferred (later plans):** the `standard`-tier OS sandbox + denial probes making runs *qualified* (M2b — this plan keeps cooperative-tier "unqualified" wording); dev/final holdout split, coverage gate, mutation validation, mandatory security gates (later); the spec's "outcome-derived spec edit taints the run / fresh generation" rule (§6) — M2a's `adjust` re-reads `spec.md` on `continue` but does **not** yet regenerate scenarios; noted as a known M2a limitation to harden when the dev/final split lands.

**Known M2a limitations (stated, not hidden):** `adjust` (edit spec + continue) re-reads the spec but does not re-derive scenarios or reset status history; a paused run holds no lock between `run` and `resume` (correct — the process exits), so `state.json` is the only concurrency guard, and `resume` re-acquires the lock.
