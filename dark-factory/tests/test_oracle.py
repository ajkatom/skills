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


def test_load_validates_and_sorts(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "b.json", id="BHV-001-S2")
    write_scenario(d, "a.json", id="BHV-001-S1")
    scs = run_scenarios.load_scenarios(str(d))
    assert [s["id"] for s in scs] == ["BHV-001-S1", "BHV-001-S2"]


def test_load_rejects_bad_ir_version(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json", ir_version="9.9")
    with pytest.raises(run_scenarios.OracleError, match="ir_version"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_bad_behavior_id(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json", behavior_id="oops!")
    with pytest.raises(run_scenarios.OracleError, match="behavior_id"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_empty_then(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json", then={})
    with pytest.raises(run_scenarios.OracleError, match="assertion"):
        run_scenarios.load_scenarios(str(d))


def test_passing_scenario(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(d, "a.json")
    ws = make_workspace(tmp_path)
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["pass"] is True and r["taxonomy"] is None
    assert r["observed"]["exit_code"] == 0


def test_wrong_output_taxonomy(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(d, "a.json")
    ws = make_workspace(tmp_path, body='print("wrong")')
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["pass"] is False and r["taxonomy"] == "wrong_output"


def test_wrong_exit_code_beats_wrong_output(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(d, "a.json")
    ws = make_workspace(tmp_path, body='import sys\nprint("wrong")\nsys.exit(3)')
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["taxonomy"] == "wrong_exit_code"


def test_timeout_taxonomy(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(
        d, "a.json", when={"run": ["python3", "ok.py"], "timeout_s": 1}
    )
    ws = make_workspace(tmp_path, body="import time\ntime.sleep(30)")
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["pass"] is False and r["taxonomy"] == "timeout"


def test_crash_taxonomy_when_command_cannot_start(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(
        d, "a.json", when={"run": ["./does-not-exist-xyz"], "timeout_s": 5}
    )
    ws = make_workspace(tmp_path)
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["pass"] is False and r["taxonomy"] == "crash"


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


def test_run_all_report_shape(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json")
    write_scenario(
        d, "b.json", id="BHV-002-S1", behavior_id="BHV-002",
        then={"exit_code": 0, "stdout_contains": "o"},
    )
    ws = make_workspace(tmp_path)
    rep = run_scenarios.run_all(str(d), str(ws))
    assert rep["report_version"] == "0.1"
    assert rep["all_pass"] is True
    assert len(rep["results"]) == 2
