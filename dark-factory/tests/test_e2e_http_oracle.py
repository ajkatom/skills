"""M20 Task 2 e2e acceptance: the first-class HTTP scenario type discriminates
end-to-end through a real subprocess supervisor run, and the load-time
validation of `when.http`/http `then` shape runs BEFORE any build.

Proves:
  1. A control whose spec asks for a tiny `/health`+`/echo` HTTP service,
     verified by an http scenario asserting `http_status`, `json_contains`,
     and a `json_path` -- built by a DETERMINISTIC correct reference builder
     -- CONVERGES (exit 0).
  2. A builder whose service returns the wrong status on `/echo` -> the http
     scenario fails `wrong_exit_code` and the run does NOT converge
     (CAP_REACHED, exit 3) -- the http oracle actually discriminates, not a
     vacuous pass regardless of what the service does.
  3. No orphan server process survives either run (pgrep -f the distinctive
     service basename is empty after the subprocess exits).
  4. `load_scenarios` rejects malformed `when.http`/`then` shapes (both/
     neither `run`|`http`, missing `start`/`request`, mismatched then/when)
     with an `OracleError`, BEFORE any scenario runs.
"""
import json
import os
import subprocess
import sys
import time

import pytest

import run_scenarios
from run_scenarios import OracleError

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
CORRECT_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_http_service")
WRONG_STATUS_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_http_wrong_status")
SERVICE_MARKER = "df_http_e2e_service.py"

HTTP_SPEC = """# tiny HTTP service
Create an executable python file `df_http_e2e_service.py` in the workspace
root that binds env `PORT` and serves:
- `GET /health` -> 200 "ok"
- `GET /echo` -> 200 JSON `{"status": "ok", "data": {"value": 42}}`
"""


def _http_scenario():
    return {
        "ir_version": "0.3",
        "id": "BHV-501-S1",
        "behavior_id": "BHV-501",
        "title": "echo service responds ok",
        "given": "workspace has df_http_e2e_service.py",
        "when": {
            "http": {
                "start": ["python3", "df_http_e2e_service.py"],
                "port_env": "PORT",
                "ready_path": "/health",
                "request": {"method": "GET", "path": "/echo"},
            },
            "timeout_s": 10,
        },
        "then": {
            "http_status": 200,
            "json_contains": {"status": "ok"},
            "json_path": {"data.value": 42},
        },
    }


def _setup_control(tmp_path, adapter, max_iterations=3):
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    config = {
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": max_iterations,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": adapter, "timeout_s": 30}},
        "budget": {"billing": "subscription"},
        "checkpoint": "auto",
    }
    (cr / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (cr / "spec.md").write_text(HTTP_SPEC, encoding="utf-8")
    (cr / "scenarios" / "s0.json").write_text(
        json.dumps(_http_scenario()), encoding="utf-8")
    return cr


def _no_orphans():
    out = subprocess.run(["pgrep", "-f", SERVICE_MARKER], capture_output=True, text=True)
    return out.stdout.strip() == ""


def _assert_no_orphans_eventually():
    for _ in range(30):
        if _no_orphans():
            return
        time.sleep(0.1)
    assert _no_orphans()


# ---------------------------------------------------------------------------
# 1 + 3: correct reference builder converges, no orphan server after
# ---------------------------------------------------------------------------

def test_correct_http_service_converges_and_leaves_no_orphan(tmp_path):
    cr = _setup_control(tmp_path, CORRECT_BUILDER)

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"

    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    states = [json.loads(l)["state"] for l in lines]
    assert "CONVERGED" in states

    _assert_no_orphans_eventually()


# ---------------------------------------------------------------------------
# 2 + 3: wrong-status builder never converges -- the oracle discriminates
# ---------------------------------------------------------------------------

def test_wrong_status_http_service_fails_wrong_exit_code_and_never_converges(tmp_path):
    cr = _setup_control(tmp_path, WRONG_STATUS_BUILDER)

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 3, proc.stdout + proc.stderr  # CAP_REACHED

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "CAP_REACHED"
    assert manifest["qualified"] is False

    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    entries = [json.loads(l) for l in lines]
    assert "CONVERGED" not in [e["state"] for e in entries]

    # At least one verifier report must show the SPECIFIC taxonomy the wrong
    # status produces -- proves this is a real, discriminating failure, not
    # an unrelated build error.
    report_files = [n for n in os.listdir(run_dir) if n.startswith("verifier_report_iter_")]
    assert report_files, "no verifier report found -- scan would be vacuous"
    taxonomies = set()
    for name in report_files:
        report = json.loads((run_dir / name).read_text(encoding="utf-8"))
        for r in report["results"]:
            if r["id"] == "BHV-501-S1":
                taxonomies.add(r["taxonomy"])
    assert "wrong_exit_code" in taxonomies

    _assert_no_orphans_eventually()


# ---------------------------------------------------------------------------
# 4: load-time validation, before any build
# ---------------------------------------------------------------------------

def _write_scenario(d, name, sc):
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(sc), encoding="utf-8")


def _base_sc(**over):
    sc = {
        "ir_version": "0.3", "id": "BHV-001-S1", "behavior_id": "BHV-001",
        "title": "t", "given": "g",
        "when": {"run": ["python3", "-c", "pass"], "timeout_s": 10},
        "then": {"exit_code": 0},
    }
    sc.update(over)
    return sc


def test_load_rejects_neither_run_nor_http(tmp_path):
    d = tmp_path / "scen"
    _write_scenario(d, "a.json", _base_sc(when={"timeout_s": 10}))
    with pytest.raises(OracleError, match="BHV-001-S1"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_both_run_and_http(tmp_path):
    d = tmp_path / "scen"
    sc = _base_sc(when={
        "run": ["python3", "-c", "pass"],
        "http": {"start": ["python3", "x.py"], "request": {"method": "GET", "path": "/"}},
    })
    _write_scenario(d, "a.json", sc)
    with pytest.raises(OracleError, match="BHV-001-S1"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_http_missing_start(tmp_path):
    d = tmp_path / "scen"
    sc = _base_sc(
        when={"http": {"request": {"method": "GET", "path": "/"}}},
        then={"http_status": 200},
    )
    _write_scenario(d, "a.json", sc)
    with pytest.raises(OracleError, match="start"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_http_missing_request(tmp_path):
    d = tmp_path / "scen"
    sc = _base_sc(
        when={"http": {"start": ["python3", "x.py"]}},
        then={"http_status": 200},
    )
    _write_scenario(d, "a.json", sc)
    with pytest.raises(OracleError, match="request"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_cli_then_on_http_scenario(tmp_path):
    d = tmp_path / "scen"
    sc = _base_sc(
        when={"http": {"start": ["python3", "x.py"], "request": {"method": "GET", "path": "/"}}},
        then={"exit_code": 0},
    )
    _write_scenario(d, "a.json", sc)
    with pytest.raises(OracleError, match="BHV-001-S1"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_http_then_on_cli_scenario(tmp_path):
    d = tmp_path / "scen"
    sc = _base_sc(
        when={"run": ["python3", "-c", "pass"], "timeout_s": 10},
        then={"http_status": 200},
    )
    _write_scenario(d, "a.json", sc)
    with pytest.raises(OracleError, match="BHV-001-S1"):
        run_scenarios.load_scenarios(str(d))
