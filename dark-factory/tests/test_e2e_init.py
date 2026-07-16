"""M19 Task 2 e2e: the `dark-factory init` CLI subcommand, driven as a real
subprocess (matching test_e2e_standard.py's pattern) -- this exercises the
actual CLI contract, not just the df_init library functions test_init.py
already covers.

Covers:
  - `init` with the shipped KV worked example (examples/kv-service/answers.json,
    paths substituted) -> exit 0, and the resulting control root is exactly
    what `supervisor.py run` accepts (df_config.load_config +
    run_scenarios.load_scenarios + df_gates.validate_oracle +
    df_gates.check_coverage all pass) -- proving init blesses a control root
    `run` would too, never a reimplementation. A subsequent `run` with a
    deterministic fake KV builder (fixtures/fake_builder_kv) actually
    converges (exit 0), proving init's scaffold is not just structurally
    valid but genuinely runnable end-to-end.
  - `init` with an inert scenario in the answers -> exit 2, the offending
    behavior named in the output, and no leftover control root.
  - `init` with a spec_leak in the answers (a scenario's exact expected
    output embedded in spec_text) -> exit 2, no leftover control root (the
    scaffold IS written by df_init.scaffold before validate_scaffold catches
    it, so this is the "remove the invalid tree on failed validate" path,
    distinct from the inert-scenario case above which never gets scaffolded
    at all).
  - `init` refuses a non-empty control root without --force, and proceeds
    with --force.
"""
import json
import os
import subprocess
import sys

import df_config
import df_gates
import run_scenarios

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
FAKE_KV = os.path.join(HERE, "fixtures", "fake_builder_kv")
EXAMPLE_ANSWERS = os.path.join(HERE, "..", "examples", "kv-service", "answers.json")


def _kv_answers(tmp_path, builder_adapter="/bin/true"):
    """The shipped worked example, with its placeholder workspace_root /
    control_root / builder_adapter substituted for real tmp_path-rooted
    values -- exactly what the docs tell a user to do before running init."""
    with open(EXAMPLE_ANSWERS, encoding="utf-8") as f:
        answers = json.load(f)
    answers["control_root"] = str(tmp_path / "control")
    answers["workspace_root"] = str(tmp_path / "workspace")
    answers["builder_adapter"] = builder_adapter
    return answers


def _write_answers(tmp_path, answers, name="answers.json"):
    path = tmp_path / name
    path.write_text(json.dumps(answers), encoding="utf-8")
    return str(path)


def _run_init(control_root, answers_path, extra_args=None):
    args = [sys.executable, SUP, "init", "--control-root", str(control_root),
            "--answers", str(answers_path)]
    if extra_args:
        args += extra_args
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


def test_init_kv_example_is_ok_and_run_accepts_the_control_root(tmp_path):
    answers = _kv_answers(tmp_path, builder_adapter=FAKE_KV)
    control_root = answers["control_root"]
    answers_path = _write_answers(tmp_path, answers)

    proc = _run_init(control_root, answers_path)
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "run --control-root" in proc.stdout
    assert control_root in proc.stdout

    # init blesses exactly what `run` would accept -- the REAL validators,
    # never a reimplementation.
    cfg = df_config.load_config(control_root)
    assert cfg["assurance"] == "cooperative"
    scenarios = run_scenarios.load_scenarios(os.path.join(control_root, "scenarios"))
    assert len(scenarios) == 12
    assert df_gates.validate_oracle(scenarios) == []
    behaviors = df_gates.load_behaviors(control_root)
    coverage = df_gates.check_coverage(behaviors, scenarios)
    assert coverage["uncovered_dev"] == []
    assert coverage["orphan_scenarios"] == []

    # A subsequent `run` with a deterministic fake KV builder converges --
    # proving init's scaffold isn't just structurally valid, it's runnable.
    run_proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", control_root],
        capture_output=True, text=True, timeout=120)
    assert run_proc.returncode == 0, f"stdout={run_proc.stdout!r} stderr={run_proc.stderr!r}"
    run_id = os.listdir(os.path.join(control_root, "runs"))[0]
    manifest = json.load(open(os.path.join(control_root, "runs", run_id, "manifest.json"), encoding="utf-8"))
    assert manifest["outcome"] in ("COMPLETE_UNQUALIFIED", "COMPLETE_QUALIFIED")


def test_init_inert_scenario_exits_2_names_behavior_and_leaves_no_tree(tmp_path):
    answers = _kv_answers(tmp_path)
    # Make BHV-HEALTH's first scenario tautological -- caught by
    # build_scenarios (df_gates.is_discriminating) before anything is
    # written, so the control root is never even created.
    answers["behaviors"][0]["scenarios"][0]["then"] = {"stdout_contains": ""}
    control_root = answers["control_root"]
    answers_path = _write_answers(tmp_path, answers)

    proc = _run_init(control_root, answers_path)
    assert proc.returncode == 2
    assert "BHV-HEALTH" in (proc.stdout + proc.stderr)
    assert not os.path.exists(control_root)


def test_init_spec_leak_exits_2_and_removes_the_scaffolded_tree(tmp_path):
    answers = _kv_answers(tmp_path)
    # Embed BHV-GET-S1's exact expected output verbatim into the
    # builder-visible spec -- discriminating (so build_scenarios accepts
    # it), but the barrier scaffold-check must catch the leak post-write and
    # this time the tree WAS scaffolded before validate_scaffold rejects it.
    answers["spec_text"] += (
        '\nNote: GET of an existing key prints `200\n{"key": "color", "value": "blue"}`.\n'
    )
    control_root = answers["control_root"]
    answers_path = _write_answers(tmp_path, answers)

    proc = _run_init(control_root, answers_path)
    assert proc.returncode == 2
    assert "spec_leak" in (proc.stdout + proc.stderr).lower() or "leak" in (proc.stdout + proc.stderr).lower()
    assert not os.path.exists(control_root)


def test_init_spec_leak_kept_with_force_keep(tmp_path):
    answers = _kv_answers(tmp_path)
    answers["spec_text"] += (
        '\nNote: GET of an existing key prints `200\n{"key": "color", "value": "blue"}`.\n'
    )
    control_root = answers["control_root"]
    answers_path = _write_answers(tmp_path, answers)

    proc = _run_init(control_root, answers_path, extra_args=["--force-keep"])
    assert proc.returncode == 2
    assert os.path.exists(control_root)
    assert os.path.exists(os.path.join(control_root, "config.json"))


def test_init_refuses_nonempty_dir_without_force_then_succeeds_with_force(tmp_path):
    answers = _kv_answers(tmp_path)
    control_root = answers["control_root"]
    os.makedirs(control_root)
    leftover = os.path.join(control_root, "leftover.txt")
    with open(leftover, "w", encoding="utf-8") as f:
        f.write("pre-existing content")
    answers_path = _write_answers(tmp_path, answers)

    proc = _run_init(control_root, answers_path)
    assert proc.returncode == 2
    assert os.path.exists(leftover)

    proc2 = _run_init(control_root, answers_path, extra_args=["--force"])
    assert proc2.returncode == 0, f"stdout={proc2.stdout!r} stderr={proc2.stderr!r}"
    assert os.path.exists(os.path.join(control_root, "config.json"))


def test_init_reads_answers_from_stdin(tmp_path):
    answers = _kv_answers(tmp_path)
    control_root = answers["control_root"]

    proc = subprocess.run(
        [sys.executable, SUP, "init", "--control-root", str(control_root), "--answers", "-"],
        input=json.dumps(answers), capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert os.path.exists(os.path.join(control_root, "config.json"))
