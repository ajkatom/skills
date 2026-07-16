import json
import os
import subprocess

import supervisor
from test_supervisor import setup_control, terminal_state

HERE = os.path.dirname(os.path.abspath(__file__))
GREETER = os.path.join(HERE, "fixtures", "twin_greeter")
FAKE_TWIN_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_twin")

MARKER = "HOLDOUT-MARKER-93e1"

TWIN_SPEC = """# greet CLI (twin-backed)
Create an executable python file `greet.py` in the workspace root.
- `python3 greet.py <name>` reads the greeter twin's endpoint from env
  `DF_TWIN_GREETER` and prints the body of `GET http://$DF_TWIN_GREETER/greet/<name>`
  followed by a newline, exiting 0.
"""


def _twin_scenario():
    return {
        "ir_version": "0.1", "id": "BHV-001-S1", "behavior_id": "BHV-001",
        "title": f"{MARKER} greets World via twin",
        "given": f"{MARKER} workspace has greet.py backed by the greeter twin",
        "when": {"run": ["python3", "greet.py", "World"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_equals": "Hello, World!"},
    }


def _twin_control(tmp_path, adapter, **cfg_over):
    cr = setup_control(tmp_path, adapter, checkpoint="auto", **cfg_over)
    # Overwrite spec + scenarios with the twin-using toy (single behavior).
    (cr / "spec.md").write_text(TWIN_SPEC, encoding="utf-8")
    for old in (cr / "scenarios").glob("*.json"):
        old.unlink()
    (cr / "scenarios" / "s0.json").write_text(
        json.dumps(_twin_scenario()), encoding="utf-8")
    (cr / "twins").mkdir()
    (cr / "twins" / "greeter.json").write_text(json.dumps(
        {"twin_version": "0.1", "name": "greeter", "launch": ["python3", GREETER],
         "fidelity": "dev mock"}), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"] = {"enabled": True, "startup_timeout_s": 20}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def _no_twin_orphans():
    out = subprocess.run(["pgrep", "-f", "twin_greeter"], capture_output=True, text=True)
    return out.stdout.strip() == ""


def test_twin_enabled_run_converges_and_reaps(tmp_path):
    # FAKE_TWIN_BUILDER writes greet.py that GETs the twin and prints the greeting
    cr = _twin_control(tmp_path, FAKE_TWIN_BUILDER)
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    run_id = os.listdir(cr / "runs")[0]
    j = (cr / "runs" / run_id / "journal.jsonl").read_text()
    assert "TWIN_ERROR" not in j
    assert "CONVERGED" in j
    # no-orphans: the shared dev twin process must be reaped after the run
    assert _no_twin_orphans()


def test_twin_startup_failure_aborts_exit_2(tmp_path):
    cr = _twin_control(tmp_path, FAKE_TWIN_BUILDER)
    # break the twin: launch never writes endpoint
    (cr / "twins" / "greeter.json").write_text(json.dumps(
        {"twin_version": "0.1", "name": "greeter",
         "launch": ["python3", "-c", "import time;time.sleep(60)"]}), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"]["startup_timeout_s"] = 1
    (cr / "config.json").write_text(json.dumps(cfg))
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    j = (run_dir / "journal.jsonl").read_text()
    assert "TWIN_ERROR" in j
    entries = [json.loads(l) for l in j.strip().splitlines()]
    assert terminal_state(entries)["state"] == "TWIN_ERROR"
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] == "ABORTED_BUILD_ERROR"
    # no-orphans: the never-ready launch process must still be reaped
    assert _no_twin_orphans()
