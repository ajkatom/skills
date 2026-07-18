"""M42 Task 1 tests for the scenario `class` taxonomy + the adequacy gate.

Covers:
  - class default (absent => happy) at the IR-validation level + df_gates helper;
  - check_adequacy under/over-cover reporting (barrier-safe shape);
  - policy DEFAULTS resolved by df_config (human vs agent-authored vs explicit);
  - validate_authored routes through the adequacy gate;
  - the supervisor pre-build ADEQUACY gate fails closed on an under-covered set.
"""
import json
import os
import subprocess
import sys

import pytest

import df_author
import df_config
import df_gates
import run_scenarios

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")


# --- class taxonomy default ------------------------------------------------

def test_class_defaults_to_happy():
    assert df_gates.scenario_class({"behavior_id": "BHV-001"}) == "happy"
    assert df_gates.scenario_class({"behavior_id": "BHV-001", "class": "boundary"}) == "boundary"


def test_ir_validate_accepts_absent_and_valid_class_rejects_bad():
    base = {"ir_version": "0.1", "id": "BHV-001-S1", "behavior_id": "BHV-001",
            "title": "", "given": "", "when": {"run": ["x"]},
            "then": {"exit_code": 0}}
    run_scenarios._validate(dict(base), "x.json")                 # absent -> ok
    run_scenarios._validate(dict(base, **{"class": "failure"}), "x.json")   # valid -> ok
    with pytest.raises(run_scenarios.OracleError, match="class must be one of"):
        run_scenarios._validate(dict(base, **{"class": "edge"}), "x.json")


# --- check_adequacy --------------------------------------------------------

BEH = [{"id": "BHV-001"}, {"id": "BHV-002"}]


def _sc(bid, cls=None):
    sc = {"behavior_id": bid}
    if cls is not None:
        sc["class"] = cls
    return sc


def test_adequacy_under_covered_reports_missing_classes():
    scs = [_sc("BHV-001", "happy"), _sc("BHV-001", "boundary"), _sc("BHV-001", "failure"),
           _sc("BHV-002")]  # BHV-002 happy only
    policy = {"required_classes": ["happy", "boundary", "failure"], "min_per_class": 1}
    rep = df_gates.check_adequacy(BEH, scs, policy)
    assert rep["checked"] is True
    assert rep["under_covered"] == [{"behavior": "BHV-002", "missing": ["boundary", "failure"]}]
    assert rep["per_behavior_class_coverage"]["BHV-001"] == {"happy": 1, "boundary": 1, "failure": 1}


def test_adequacy_fully_covered_passes():
    scs = []
    for bid in ("BHV-001", "BHV-002"):
        for cls in ("happy", "boundary", "failure"):
            scs.append(_sc(bid, cls))
    policy = {"required_classes": ["happy", "boundary", "failure"], "min_per_class": 1}
    assert df_gates.check_adequacy(BEH, scs, policy)["under_covered"] == []


def test_adequacy_default_policy_is_happy_only_noop():
    scs = [_sc("BHV-001"), _sc("BHV-002")]  # both implicitly happy
    assert df_gates.check_adequacy(BEH, scs, df_gates.default_adequacy_policy())["under_covered"] == []


def test_adequacy_min_per_class():
    scs = [_sc("BHV-001", "happy")]
    policy = {"required_classes": ["happy"], "min_per_class": 2}
    rep = df_gates.check_adequacy([{"id": "BHV-001"}], scs, policy)
    assert rep["under_covered"] == [{"behavior": "BHV-001", "missing": ["happy"]}]


def test_adequacy_orphan_scenarios_do_not_count():
    # A scenario naming an undeclared behavior contributes NOTHING (orphans are
    # the coverage gate's concern) -- it must not accidentally satisfy adequacy.
    scs = [_sc("BHV-999", "happy")]
    rep = df_gates.check_adequacy([{"id": "BHV-001"}], scs, df_gates.default_adequacy_policy())
    assert rep["under_covered"] == [{"behavior": "BHV-001", "missing": ["happy"]}]


# --- policy defaults resolved by df_config ---------------------------------

def _load(tmp_path, roles, adq=None):
    cr = tmp_path / "cr"
    cr.mkdir(parents=True)
    ws = tmp_path / "ws"
    cfg = {"config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
           "feedback": "ids", "max_iterations": 5, "workspace_root": str(ws),
           "roles": roles, "budget": {"billing": "subscription"}}
    if adq is not None:
        cfg["scenario_adequacy"] = adq
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return df_config.load_config(str(cr))


def test_default_policy_human_authored_is_happy_only(tmp_path):
    cfg = _load(tmp_path, {"builder": {"adapter": "/bin/echo"}})
    assert cfg["_adequacy"]["required_classes"] == ["happy"]
    assert cfg["_adequacy"]["critic"]["enabled"] is False


def test_default_policy_agent_authored_is_all_three(tmp_path):
    cfg = _load(tmp_path, {"builder": {"adapter": "/bin/echo"},
                           "author": {"adapter": "/bin/cat"}})
    assert cfg["_adequacy"]["required_classes"] == ["happy", "boundary", "failure"]
    assert cfg["_adequacy"]["critic"]["enabled"] is False  # no roles.critic


def test_default_policy_agent_with_critic_enables_loop(tmp_path):
    cfg = _load(tmp_path, {"builder": {"adapter": "/bin/echo"},
                           "author": {"adapter": "/bin/cat"},
                           "critic": {"adapter": "/bin/ls"}})
    assert cfg["_adequacy"]["critic"]["enabled"] is True


def test_explicit_policy_overrides_and_validates(tmp_path):
    cfg = _load(tmp_path, {"builder": {"adapter": "/bin/echo"}},
                {"required_classes": ["happy", "failure"], "min_per_class": 2})
    assert cfg["_adequacy"]["required_classes"] == ["happy", "failure"]
    assert cfg["_adequacy"]["min_per_class"] == 2
    with pytest.raises(df_config.ConfigError, match="unknown class"):
        _load(tmp_path / "x2", {"builder": {"adapter": "/bin/echo"}},
              {"required_classes": ["happy", "nope"]})


# --- validate_authored routes through adequacy -----------------------------

def test_validate_authored_flags_missing_class():
    spec = "Build greet.py that greets a name or errors."
    behaviors = [{"id": "BHV-001"}]
    raw = [{"behavior_id": "BHV-001", "class": "happy", "run": ["python3", "greet.py", "A"],
            "then": {"exit_code": 0, "stdout_equals": "Hi, A!"}, "title": "happy"}]
    policy = {"required_classes": ["happy", "boundary", "failure"], "min_per_class": 1}
    ok, report, _ = df_author.validate_authored(raw, spec, behaviors, policy)
    assert ok is False
    assert report["under_covered_classes"] == [
        {"behavior": "BHV-001", "missing": ["boundary", "failure"]}]
    # feedback is barrier-safe: behavior-id + class names only.
    fb = "\n".join(df_author._feedback_lines(report))
    assert "BHV-001" in fb and "boundary" in fb and "failure" in fb
    assert "Hi, A!" not in fb


# --- supervisor pre-build adequacy gate ------------------------------------

def _cli(*args):
    return subprocess.run([sys.executable, SUP, *args], capture_output=True, text=True, timeout=120)


def test_supervisor_adequacy_gate_fails_closed(tmp_path):
    # A human control root with happy-only scenarios but a config requiring
    # boundary+failure -> the M7 adequacy gate fails BEFORE any build.
    cr = tmp_path / "cr"
    (cr / "scenarios").mkdir(parents=True)
    ws = tmp_path / "ws"
    (cr / "config.json").write_text(json.dumps({
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": 5, "workspace_root": str(ws),
        "roles": {"builder": {"adapter": "/bin/true"}},
        "budget": {"billing": "subscription"},
        "scenario_adequacy": {"required_classes": ["happy", "boundary", "failure"]},
    }), encoding="utf-8")
    (cr / "spec.md").write_text("# Greet\nGreets.\n", encoding="utf-8")
    (cr / "behaviors.json").write_text(json.dumps({"behaviors": [{"id": "BHV-001"}]}), encoding="utf-8")
    sc = {"ir_version": "0.1", "id": "BHV-001-S1", "behavior_id": "BHV-001",
          "cohort": "dev", "class": "happy", "title": "h", "given": "",
          "when": {"run": ["python3", "greet.py", "X"]},
          "then": {"exit_code": 0, "stdout_equals": "Hi, X!"}}
    (cr / "scenarios" / "BHV-001-S1.json").write_text(json.dumps(sc), encoding="utf-8")

    r = _cli("run", "--control-root", str(cr))
    assert r.returncode == 2
    assert "adequacy" in r.stderr.lower()
    # fail-closed BEFORE any build: no workspace was created.
    assert not ws.exists() or os.listdir(ws) == []
    # the manifest records the adequacy gap.
    run_id = os.listdir(cr / "runs")[0]
    mf = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert mf["outcome"] == "GATE_FAILED"
    assert mf["adequacy"]["under_covered"] == [
        {"behavior": "BHV-001", "missing": ["boundary", "failure"]}]
