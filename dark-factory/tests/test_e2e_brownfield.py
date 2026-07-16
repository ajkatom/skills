"""M15 Task 3 (final): e2e proof of the brownfield path, driven as a real CLI
subprocess against the supervisor (matches test_e2e_gates.py's / test_e2e_
twin_evidence.py's pattern) -- --project-src points at a tmp copy of the
`legacy_app` fixture (a single-file fixture, copied here as `app.py` so the
generated probes/spec read naturally as "an existing app.py CLI").

  (a) regression caught: a brownfield control (probes freezing `add 2 3` ->
      "5" and a bad-args case) + a spec asking for a NEW `double` subcommand
      + `fake_builder_break` (ships `double` correctly, breaks `add`) -> the
      run does NOT converge: the generated BHV-REGRESS scenario for `add`
      fails wrong_output, CAP_REACHED, exit 3 -- and no generated-scenario
      content ever reaches a builder-facing file.
  (b) honest builder converges: `fake_builder_extend` (same control root,
      same probes, same spec -- only the builder differs) ships `double`
      WITHOUT touching `add` -> converges, exit 0, manifest mode brownfield
      with characterization.generated == 2.
  (c) auto-detection matrix: --project-src with files + no brownfield config
      -> manifest mode brownfield (auto-detected, unguarded: zero probes
      configured) + BROWNFIELD_UNGUARDED journaled + stderr WARN; no
      --project-src at all -> mode greenfield.

Self-review baked into the assertions below:
  1. (a) and (b) share the same control-root builder (_brownfield_control),
     the same two probes, and the same spec -- only FAKE_BUILDER_BREAK vs
     FAKE_BUILDER_EXTEND differs, so this is a real A/B.
  2. (a) asserts the CAP_REACHED failing_behaviors AND feedback_iter_1.json
     name specifically BHV-REGRESS-0 (the `add` guard) and specifically
     exclude BHV-DOUBLE (the new-behavior scenario, which passes) -- proving
     the guard fired, not that the new feature was missed.
  3. journal event names (MODE_DETECTED, CHARACTERIZED, BROWNFIELD_UNGUARDED,
     CAP_REACHED, CONVERGED), manifest fields (mode, characterization.*),
     and config keys (brownfield.mode/probes) match df_brownfield.py /
     supervisor.py / df_config.py exactly -- see references/brownfield.md
     and references/config-reference.md for the docs side of this check.
"""
import json
import os
import shutil
import subprocess
import sys

from test_brownfield_config import LEGACY_APP_FIXTURE, set_brownfield
from test_supervisor import FAKE, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
FAKE_BUILDER_BREAK = os.path.join(HERE, "fixtures", "fake_builder_break")
FAKE_BUILDER_EXTEND = os.path.join(HERE, "fixtures", "fake_builder_extend")

MARKER = "HOLDOUT-MARKER-brownfield-e2e-71c2"

SPEC_TEXT = f"""# {MARKER} app.py -- add a `double` subcommand

The workspace already contains an existing `app.py` CLI. Extend it with ONE
new subcommand, without changing any of its other behavior:

- `python3 app.py double N` prints `2*int(N)` and exits 0.
"""

ADD_OK_PROBE = {
    "id": "add-ok",
    "run": ["python3", "app.py", "add", "2", "3"],
    "timeout_s": 5,
}
ADD_BAD_PROBE = {
    "id": "add-bad",
    "run": ["python3", "app.py", "add", "x", "y"],
    "timeout_s": 5,
}


def _double_scenario():
    return {
        "ir_version": "0.1", "id": "BHV-DOUBLE-S1", "behavior_id": "BHV-DOUBLE",
        "title": f"{MARKER} doubles a number via the new subcommand",
        "given": f"{MARKER} workspace has app.py implementing double",
        "when": {"run": ["python3", "app.py", "double", "4"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_equals": "8\n"},
    }


def _make_app_src(tmp_path, name="app_src"):
    src = tmp_path / name
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "app.py")
    return src


def _brownfield_control(tmp_path, adapter, max_iterations=1):
    cr = setup_control(tmp_path, adapter, max_iterations=max_iterations, checkpoint="auto")
    (cr / "spec.md").write_text(SPEC_TEXT, encoding="utf-8")
    for old in (cr / "scenarios").glob("*.json"):
        old.unlink()
    (cr / "scenarios" / "double.json").write_text(
        json.dumps(_double_scenario()), encoding="utf-8")
    return cr


def _run(cr, project_src=None):
    argv = [sys.executable, SUP, "run", "--control-root", str(cr)]
    if project_src is not None:
        argv += ["--project-src", str(project_src)]
    return subprocess.run(argv, capture_output=True, text=True, timeout=120)


def _run_dir(cr):
    run_id = os.listdir(cr / "runs")[0]
    return cr / "runs" / run_id


def _journal(run_dir):
    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines]


def _workspace_from_journal(entries):
    for e in entries:
        if e["state"] == "SNAPSHOT":
            return e["data"]["workspace"]
    return None


def _walk_all_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


# ---------------------------------------------------------------------------
# (a) regression caught
# ---------------------------------------------------------------------------

def test_regression_caught_cap_reached_and_barrier_holds(tmp_path):
    cr = _brownfield_control(tmp_path, FAKE_BUILDER_BREAK, max_iterations=1)
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = _make_app_src(tmp_path)

    proc = _run(cr, project_src=src)
    assert proc.returncode == 3, proc.stdout + proc.stderr  # CAP_REACHED

    run_dir = _run_dir(cr)
    entries = _journal(run_dir)
    states = [e["state"] for e in entries]
    assert "MODE_DETECTED" in states
    assert "CHARACTERIZED" in states
    assert states[-1] == "CAP_REACHED"

    char_entry = next(e for e in entries if e["state"] == "CHARACTERIZED")
    assert char_entry["data"]["generated"] == 2
    assert set(char_entry["data"]["behavior_ids"]) == {"BHV-REGRESS-0", "BHV-REGRESS-1"}

    # The guard for `add` fired -- and ONLY that guard. The new-behavior
    # scenario (BHV-DOUBLE) and the untouched bad-args guard both pass.
    cap = entries[-1]["data"]
    assert cap["failing_behaviors"] == ["BHV-REGRESS-0"]

    report = json.loads((run_dir / "verifier_report_iter_1.json").read_text(encoding="utf-8"))
    regress_result = next(r for r in report["results"] if r["behavior_id"] == "BHV-REGRESS-0")
    assert regress_result["pass"] is False
    assert regress_result["taxonomy"] == "wrong_output"
    double_result = next(r for r in report["results"] if r["behavior_id"] == "BHV-DOUBLE")
    assert double_result["pass"] is True

    # The (would-be) builder-facing feedback names the behavior_id + taxonomy
    # only -- never the probe content.
    feedback = json.loads((run_dir / "feedback_iter_1.json").read_text(encoding="utf-8"))
    fb = {f["behavior_id"]: f["taxonomy"] for f in feedback["failures"]}
    assert fb == {"BHV-REGRESS-0": ["wrong_output"]}

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "CAP_REACHED"
    assert manifest["mode"] == "brownfield"
    assert manifest["characterization"]["generated"] == 2

    # Barrier: no generated-scenario content (title/given, the distinctive
    # strings that could ONLY come from a generated regression scenario)
    # ever reaches a file the builder could see, or the audited prompt copy.
    forbidden = ["regression guard: add-ok", "regression guard: add-bad",
                 "captured from the pre-change system"]
    workspace = _workspace_from_journal(entries)
    assert workspace and os.path.isdir(workspace)
    checked = False
    for path in _walk_all_files(workspace):
        checked = True
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        for marker in forbidden:
            assert marker not in text, f"generated scenario content leaked into {path}"
    for name in os.listdir(run_dir):
        if name.startswith("prompt_iter_"):
            checked = True
            text = (run_dir / name).read_text(encoding="utf-8")
            for marker in forbidden:
                assert marker not in text
    assert checked, "no builder-facing files were scanned -- assertion would be vacuous"


# ---------------------------------------------------------------------------
# (b) honest builder converges
# ---------------------------------------------------------------------------

def test_honest_builder_converges_with_regression_guards_green(tmp_path):
    cr = _brownfield_control(tmp_path, FAKE_BUILDER_EXTEND, max_iterations=1)
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = _make_app_src(tmp_path)

    proc = _run(cr, project_src=src)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    run_dir = _run_dir(cr)
    entries = _journal(run_dir)
    states = [e["state"] for e in entries]
    assert "CONVERGED" in states
    assert states.count("BUILD") == 1  # converged on the very first iteration

    report = json.loads((run_dir / "verifier_report_iter_1.json").read_text(encoding="utf-8"))
    assert all(r["pass"] for r in report["results"]), report["results"]

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] in ("COMPLETE_UNQUALIFIED", "COMPLETE_QUALIFIED")
    assert manifest["mode"] == "brownfield"
    assert manifest["characterization"]["probes"] == 2
    assert manifest["characterization"]["generated"] == 2
    assert manifest["characterization"]["note"] == (
        "behavioral snapshot at probe points; unprobed behavior may regress"
    )


# ---------------------------------------------------------------------------
# (c) auto-detection matrix
# ---------------------------------------------------------------------------

def test_project_src_with_no_brownfield_config_autodetects_brownfield_unguarded(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # no brownfield block at all
    src = _make_app_src(tmp_path)

    proc = _run(cr, project_src=src)
    assert proc.returncode == 0, proc.stdout + proc.stderr  # FAKE's own greet spec converges

    assert "brownfield detected but no probes configured" in proc.stderr
    assert "NO regression guards were captured" in proc.stderr

    run_dir = _run_dir(cr)
    entries = _journal(run_dir)
    states = [e["state"] for e in entries]
    assert "BROWNFIELD_UNGUARDED" in states
    assert "CHARACTERIZED" not in states

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["mode"] == "brownfield"  # legacy source is never silently greenfield
    assert manifest["characterization"]["generated"] == 0
    assert "unguarded" in manifest["characterization"]["note"]


def test_no_project_src_is_greenfield(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")

    proc = _run(cr, project_src=None)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    run_dir = _run_dir(cr)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["mode"] == "greenfield"
    assert manifest["characterization"] == {"probes": 0, "generated": 0}

    entries = _journal(run_dir)
    states = [e["state"] for e in entries]
    assert "CHARACTERIZED" not in states
    assert "BROWNFIELD_UNGUARDED" not in states
