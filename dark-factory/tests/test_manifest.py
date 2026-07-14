import json
import os
import subprocess
import sys

import supervisor
from test_supervisor import FAKE, setup_control  # reuse Task 7 helpers

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def run_and_get_run_dir(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    return str(cr / "runs" / run_id)


def test_manifest_written_on_completion(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    m = json.load(open(os.path.join(rd, "manifest.json"), encoding="utf-8"))
    assert m["manifest_version"] == "0.1"
    assert m["outcome"] == "COMPLETE_UNQUALIFIED"
    assert m["qualified"] is False and m["tier"] == "cooperative"
    assert m["iterations"] == 2
    for key in ("config_sha256", "spec_sha256", "scenario_set_sha256",
                "snapshot_sha256", "journal_sha256"):
        assert len(m[key]) == 64
    assert os.path.exists(os.path.join(rd, "manifest.sha256"))


def test_verify_manifest_ok(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    assert supervisor.verify_manifest(rd) is True


def test_verify_manifest_detects_manifest_edit(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    p = os.path.join(rd, "manifest.json")
    m = json.load(open(p, encoding="utf-8"))
    m["outcome"] = "QUALIFIED_SHIP_CANDIDATE"
    open(p, "w", encoding="utf-8").write(json.dumps(m))
    assert supervisor.verify_manifest(rd) is False


def test_verify_manifest_detects_journal_edit(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    jp = os.path.join(rd, "journal.jsonl")
    with open(jp, "a", encoding="utf-8") as f:
        f.write('{"ts":"later","state":"FORGED","data":{}}\n')
    assert supervisor.verify_manifest(rd) is False


def test_verify_manifest_cli_exit_codes(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    ok = subprocess.run([sys.executable, SUP, "verify-manifest", "--run-dir", rd],
                        capture_output=True, text=True)
    assert ok.returncode == 0 and "OK" in ok.stdout
    with open(os.path.join(rd, "journal.jsonl"), "a", encoding="utf-8") as f:
        f.write("tamper\n")
    bad = subprocess.run([sys.executable, SUP, "verify-manifest", "--run-dir", rd],
                         capture_output=True, text=True)
    assert bad.returncode == 4 and "TAMPERED" in bad.stdout
