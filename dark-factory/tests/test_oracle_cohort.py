import json

import pytest

import run_scenarios


def write_scenario(d, name, **kw):
    sc = {
        "ir_version": "0.1",
        "id": "BHV-001-S1",
        "behavior_id": "BHV-001",
        "title": "prints ok",
        "given": "an ok.py exists",
        "when": {"run": ["python3", "ok.py"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_equals": "ok"},
    }
    sc.update(kw)
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(sc), encoding="utf-8")
    return sc


def make_workspace(tmp_path, body='print("ok")'):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    (ws / "ok.py").write_text(body + "\n", encoding="utf-8")
    return ws


def test_absent_cohort_defaults_to_dev(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json")
    scs = run_scenarios.load_scenarios(str(d))
    assert scs[0]["cohort"] == "dev"


def test_explicit_final_cohort_honored(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json", cohort="final")
    scs = run_scenarios.load_scenarios(str(d))
    assert scs[0]["cohort"] == "final"


def test_invalid_cohort_raises_oracle_error(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json", cohort="prod")
    with pytest.raises(run_scenarios.OracleError, match="cohort"):
        run_scenarios.load_scenarios(str(d))


def test_run_all_filters_to_dev_cohort(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json")  # defaults to dev
    write_scenario(
        d, "b.json", id="BHV-002-S1", behavior_id="BHV-002", cohort="final",
    )
    ws = make_workspace(tmp_path)
    rep = run_scenarios.run_all(str(d), str(ws), cohort="dev")
    assert rep["cohort"] == "dev"
    assert rep["count"] == 1
    assert len(rep["results"]) == 1
    assert rep["results"][0]["id"] == "BHV-001-S1"
    assert rep["all_pass"] is True


def test_run_all_final_cohort_empty_is_honest_no_exam(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json")  # only a dev scenario exists
    ws = make_workspace(tmp_path)
    rep = run_scenarios.run_all(str(d), str(ws), cohort="final")
    assert rep == {
        "report_version": "0.1",
        "cohort": "final",
        "results": [],
        "all_pass": True,
        "count": 0,
    }


def test_run_all_cohort_none_runs_all_back_compat(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json")
    write_scenario(
        d, "b.json", id="BHV-002-S1", behavior_id="BHV-002", cohort="final",
    )
    ws = make_workspace(tmp_path)
    rep = run_scenarios.run_all(str(d), str(ws))
    assert rep["cohort"] == "all"
    assert rep["count"] == 2
    assert len(rep["results"]) == 2
    assert rep["all_pass"] is True
