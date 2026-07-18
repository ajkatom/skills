"""M43b Task 6: full-run e2e — a dev cohort with a CONCURRENCY property.

A builder that ships a racy read-modify-write counter fails the
`serializable_counter` concurrency property with `property_violated` (a lost
update observed under parallel execution); the impoverished feedback drives it
to a locked version and the run converges. THE BARRIER, end to end: no
generated input value AND no per-worker counterexample ever appears in the
workspace, any builder prompt, or any feedback file — while the counterexample
IS recorded in the control-plane verifier report and journaled value-free
(PROPERTY_VIOLATED: behavior-id + invariant + case index + attempt index).
The manifest records workers x attempts so the probabilistic detection
strength is auditable.
"""
import json
import os
import subprocess
import sys

import id_feedback

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_CONC = os.path.join(HERE, "fixtures", "fake_builder_concurrency")
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")

SPEC = """# Atomic counter

Build `app.py`: invoked as `python3 app.py`, it increments a shared persistent
counter by one and prints the new value. Concurrent invocations must each be
counted — N parallel increments must leave the counter at initial + N (no lost
updates).
"""


def setup_control(tmp_path, adapter=FAKE_CONC):
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    config = {
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": 4, "checkpoint": "auto",
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": adapter, "timeout_s": 30}},
        "budget": {"billing": "subscription"},
    }
    (cr / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (cr / "spec.md").write_text(SPEC, encoding="utf-8")
    scenarios = [
        {
            "ir_version": "0.1", "id": "BHV-CTR-S1", "behavior_id": "BHV-CTR",
            "cohort": "dev", "class": "happy",
            "title": "increments and exits cleanly", "given": "",
            "when": {"run": ["python3", "app.py"], "timeout_s": 10},
            "then": {"exit_code": 0},
        },
        {
            "ir_version": "0.4", "id": "BHV-CTR-P1", "behavior_id": "BHV-CTR",
            "cohort": "dev", "class": "failure",
            "title": "concurrent increments do not lose updates", "given": "",
            "when": {"property": {
                "generate": {"vars": {"w": {"kind": "int", "min": 0, "max": 9}},
                             "cases": 2, "seed": 99},
                "steps": [{"run": ["python3", "app.py"]}],
                "concurrency": {"workers": 3, "attempts": 3, "per_worker_vars": []},
                "timeout_s": 10,
            }},
            "then": {"invariant": {"name": "serializable_counter"}},
        },
    ]
    for i, sc in enumerate(scenarios):
        (cr / "scenarios" / f"s{i}.json").write_text(json.dumps(sc), encoding="utf-8")
    return cr


def journal_entries(run_dir):
    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines]


def test_e2e_concurrency_converges_and_counterexample_stays_control_plane(tmp_path):
    cr = setup_control(tmp_path)

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    entries = journal_entries(run_dir)
    states = [e["state"] for e in entries]

    # 1. Convergence: racy build -> property_violated -> locked build -> converged.
    assert states.count("BUILD") == 2
    assert "CONVERGED" in states

    # 2. PROPERTY_VIOLATED journaled, VALUE-FREE, with the attempt index.
    pv = [e for e in entries if e["state"] == "PROPERTY_VIOLATED"]
    assert len(pv) == 1
    data = pv[0]["data"]
    assert data["behavior_id"] == "BHV-CTR"
    assert data["invariant"] == "serializable_counter"
    assert isinstance(data["case_index"], int)
    assert isinstance(data["attempt_index"], int)
    assert data["counterexample_recorded"] is True
    # value-free: exactly these keys, nothing that could carry an input.
    assert set(data) == {"cohort", "iteration", "behavior_id", "invariant",
                         "case_index", "attempt_index", "counterexample_recorded"}

    # 3. Feedback carried ONLY the taxonomy (schema-clean, in-vocabulary).
    fb1 = json.loads((run_dir / "feedback_iter_1.json").read_text(encoding="utf-8"))
    id_feedback.validate_feedback(fb1)
    assert fb1["failures"] == [{"behavior_id": "BHV-CTR",
                                "taxonomy": ["property_violated"]}]

    # 4. THE BARRIER: the per-worker counterexample (each worker's counter
    #    values) exists ONLY in the control-plane report, never anywhere the
    #    builder could read.
    report1 = json.loads(
        (run_dir / "verifier_report_iter_1.json").read_text(encoding="utf-8"))
    prop = [r for r in report1["results"] if r["id"] == "BHV-CTR-P1"][0]
    cx = prop["observed"]["property"]["counterexample"]
    assert cx is not None and len(cx["workers"]) == 3
    # The per-worker observations carry the racy counter output (control-plane).
    worker_outputs = json.dumps(cx["workers"])

    workspace = None
    for e in entries:
        if e["state"] == "SNAPSHOT":
            workspace = e["data"]["workspace"]
    assert workspace is not None
    # The counterexample DETAIL must not have leaked into the workspace or any
    # builder-visible file.
    for dirpath, _, filenames in os.walk(workspace):
        for name in filenames:
            blob = open(os.path.join(dirpath, name), "rb").read()
            assert cx["detail"].encode() not in blob
    for name in os.listdir(run_dir):
        if name.startswith(("prompt_iter_", "feedback_iter_")):
            text = (run_dir / name).read_text(encoding="utf-8")
            assert cx["detail"] not in text
            assert "attempt_index" not in text  # no per-worker structure crosses

    # 5. Manifest: reproducibility metadata + workers x attempts (audited effort).
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["property"]["scenarios"]["BHV-CTR-P1"] == {
        "cases": 2, "seed": 99, "invariant": "serializable_counter",
        "workers": 3, "attempts": 3}
    assert manifest["property"]["violations"] == [data]

    # 6. Iteration 2: the locked build passes the same concurrency property.
    report2 = json.loads(
        (run_dir / "verifier_report_iter_2.json").read_text(encoding="utf-8"))
    assert report2["all_pass"]
    p2 = [r for r in report2["results"] if r["id"] == "BHV-CTR-P1"][0]
    assert p2["observed"]["property"]["counterexample"] is None
    assert p2["observed"]["property"]["workers"] == 3


def test_e2e_locked_builder_converges_without_violation(tmp_path):
    """A builder that is race-free from the start converges with zero
    PROPERTY_VIOLATED events — the concurrency property is not a tax on correct
    code."""
    cr = setup_control(tmp_path)
    locked_adapter = tmp_path / "locked_adapter"
    src = open(FAKE_CONC, encoding="utf-8").read()
    locked_adapter.write_text(
        src.replace(
            'body = LOCKED if os.path.exists(os.path.join(wd, "feedback.json")) '
            'else RACY',
            "body = LOCKED"),
        encoding="utf-8")
    locked_adapter.chmod(0o755)
    cfg = json.loads((cr / "config.json").read_text(encoding="utf-8"))
    cfg["roles"]["builder"]["adapter"] = str(locked_adapter)
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    run_id = os.listdir(cr / "runs")[0]
    entries = journal_entries(cr / "runs" / run_id)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 1 and "CONVERGED" in states
    assert not any(e["state"] == "PROPERTY_VIOLATED" for e in entries)
