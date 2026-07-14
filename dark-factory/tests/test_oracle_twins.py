import json
import os

import run_scenarios


def sc(tmp, **then):
    return {"ir_version": "0.1", "id": "BHV-001-S1", "behavior_id": "BHV-001",
            "title": "t", "given": "g",
            "when": {"run": ["python3", "readenv.py"], "timeout_s": 10},
            "then": then}


def ws_with_reader(tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    # prints the twin env var it was given
    (ws / "readenv.py").write_text(
        "import os; print(os.environ.get('DF_TWIN_GREETER', 'MISSING'))\n", encoding="utf-8")
    return ws


def test_env_extra_reaches_scenario(tmp_path):
    ws = ws_with_reader(tmp_path)
    r = run_scenarios.run_scenario(
        sc(tmp_path, exit_code=0, stdout_equals="127.0.0.1:9"),
        str(ws), env_extra={"DF_TWIN_GREETER": "127.0.0.1:9"})
    assert r["observed"]["stdout"].strip() == "127.0.0.1:9"


def test_no_env_extra_is_unchanged(tmp_path):
    ws = ws_with_reader(tmp_path)
    r = run_scenarios.run_scenario(sc(tmp_path, exit_code=0, stdout_equals="MISSING"), str(ws))
    assert r["observed"]["stdout"].strip() == "MISSING"
