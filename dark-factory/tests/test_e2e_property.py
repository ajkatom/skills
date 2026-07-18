"""M43a Task 6: full-run e2e — a dev cohort with a fuzz property.

A deliberately non-robust builder (raises a traceback on non-alnum input)
fails the `robust` property with `property_violated`; the impoverished
feedback drives it to a hardened version and the run converges. THE BARRIER,
end to end: no generated input value ever appears in the workspace, any
builder prompt, or any feedback file — while the counterexample IS recorded
in the control-plane verifier report and journaled value-free
(PROPERTY_VIOLATED: behavior-id + invariant + case index).
"""
import json
import os
import subprocess
import sys

import df_generate
import id_feedback

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_PROPERTY = os.path.join(HERE, "fixtures", "fake_builder_property")
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")

GENERATE = {
    "vars": {"x": {"kind": "string", "charset": "ascii_printable",
                   "min_len": 8, "max_len": 16}},
    "cases": 20,
    "seed": 99,
}

SPEC = """# Store CLI

Build `app.py`: invoked as `python3 app.py <value>`.

- A valid value is ALPHANUMERIC: print `stored <value>` and exit 0.
- Any other value must be REJECTED CLEANLY: print an error message to
  stderr and exit with a non-zero code. The program must never crash with
  an unhandled exception, whatever the argument contains.
"""


def setup_control(tmp_path):
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    config = {
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": 4, "checkpoint": "auto",
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": FAKE_PROPERTY, "timeout_s": 30}},
        "budget": {"billing": "subscription"},
    }
    (cr / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (cr / "spec.md").write_text(SPEC, encoding="utf-8")
    scenarios = [
        {
            "ir_version": "0.1", "id": "BHV-STORE-S1", "behavior_id": "BHV-STORE",
            "cohort": "dev", "class": "happy",
            "title": "stores a plain value", "given": "",
            "when": {"run": ["python3", "app.py", "plain123value"], "timeout_s": 10},
            "then": {"exit_code": 0, "stdout_equals": "stored plain123value"},
        },
        {
            "ir_version": "0.4", "id": "BHV-STORE-P1", "behavior_id": "BHV-STORE",
            "cohort": "dev", "class": "failure",
            "title": "never crashes on generated input", "given": "",
            "when": {"property": {
                "generate": GENERATE,
                "steps": [{"run": ["python3", "app.py", "{x}"]}],
                "timeout_s": 10,
            }},
            "then": {"invariant": {"name": "robust"}},
        },
    ]
    for i, sc in enumerate(scenarios):
        (cr / "scenarios" / f"s{i}.json").write_text(json.dumps(sc), encoding="utf-8")
    return cr


def walk_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def journal_entries(run_dir):
    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines]


def test_e2e_property_converges_and_counterexample_stays_control_plane(tmp_path):
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

    # 1. Convergence shape: fragile build -> property_violated feedback ->
    #    hardened build -> converged.
    assert states.count("BUILD") == 2
    assert "CONVERGED" in states

    # 2. PROPERTY_VIOLATED journaled, VALUE-FREE.
    pv = [e for e in entries if e["state"] == "PROPERTY_VIOLATED"]
    assert len(pv) == 1
    data = pv[0]["data"]
    assert data["behavior_id"] == "BHV-STORE"
    assert data["invariant"] == "robust"
    assert data["cohort"] == "dev"
    assert isinstance(data["case_index"], int)
    assert data["counterexample_recorded"] is True
    # value-free: exactly these keys, nothing that could carry an input
    assert set(data) == {"cohort", "iteration", "behavior_id", "invariant",
                         "case_index", "counterexample_recorded"}

    # 3. Feedback carried ONLY the taxonomy (schema-clean, in-vocabulary).
    fb1 = json.loads((run_dir / "feedback_iter_1.json").read_text(encoding="utf-8"))
    id_feedback.validate_feedback(fb1)
    assert fb1["failures"] == [{"behavior_id": "BHV-STORE",
                                "taxonomy": ["property_violated"]}]

    # 4. THE BARRIER: no generated input value anywhere the builder could
    #    look. Generation is deterministic (seed 99), so the test re-derives
    #    the exact secret values the verifier used.
    secrets = [c["x"] for c in df_generate.generate_cases(GENERATE)]
    assert all(len(s) >= 8 for s in secrets)  # distinctive enough to grep for

    workspace = None
    for e in entries:
        if e["state"] == "SNAPSHOT":
            workspace = e["data"]["workspace"]
    assert workspace is not None
    for path in walk_files(workspace):
        with open(path, "rb") as f:
            blob = f.read()
        for s in secrets:
            assert s.encode() not in blob, f"generated input leaked into {path}"
    for name in os.listdir(run_dir):
        if name.startswith(("prompt_iter_", "feedback_iter_")):
            text = (run_dir / name).read_text(encoding="utf-8")
            for s in secrets:
                assert s not in text, f"generated input leaked into {name}"
    for s in secrets:
        assert s not in proc.stdout and s not in proc.stderr

    # 5. ...while the CONTROL-PLANE verifier report DID record the
    #    counterexample (the operator can replay it) — the contrast that
    #    proves the information went to exactly one side of the barrier.
    report1 = json.loads(
        (run_dir / "verifier_report_iter_1.json").read_text(encoding="utf-8"))
    prop_results = [r for r in report1["results"] if r["id"] == "BHV-STORE-P1"]
    assert len(prop_results) == 1
    cx = prop_results[0]["observed"]["property"]["counterexample"]
    assert cx is not None and cx["vars"]["x"] in secrets
    assert not cx["vars"]["x"].isalnum()  # the input class that broke it

    # 6. Manifest: reproducibility metadata + the value-free violation record.
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["property"]["scenarios"]["BHV-STORE-P1"] == {
        "cases": 20, "seed": 99, "invariant": "robust"}
    assert manifest["property"]["violations"] == [data]

    # 7. Iteration 2: the hardened build passes the same property.
    report2 = json.loads(
        (run_dir / "verifier_report_iter_2.json").read_text(encoding="utf-8"))
    assert report2["all_pass"]
    p2 = [r for r in report2["results"] if r["id"] == "BHV-STORE-P1"][0]
    assert p2["observed"]["property"]["counterexample"] is None
    assert p2["observed"]["property"]["cases_run"] == 20


def test_e2e_robust_stub_converges_first_iteration(tmp_path):
    """A builder that is robust from the start converges with zero
    PROPERTY_VIOLATED events -- the property is not a tax on correct code."""
    cr = setup_control(tmp_path)
    # Pre-arm the adapter: HARDENED from iteration 1 by planting feedback.json
    # is not possible (workspace is fresh), so use a one-file wrapper adapter
    # that always writes the hardened app.
    hardened_adapter = tmp_path / "hardened_adapter"
    fragile = open(FAKE_PROPERTY, encoding="utf-8").read()
    hardened_adapter.write_text(
        fragile.replace('body = HARDENED if os.path.exists(os.path.join(wd, '
                        '"feedback.json")) else FRAGILE',
                        "body = HARDENED"),
        encoding="utf-8")
    hardened_adapter.chmod(0o755)
    cfg = json.loads((cr / "config.json").read_text(encoding="utf-8"))
    cfg["roles"]["builder"]["adapter"] = str(hardened_adapter)
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
    manifest = json.loads(
        (cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["property"]["violations"] == []
