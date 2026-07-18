"""M41 Task 6 e2e (deterministic — stub actions, NO real infra/Docker):

  (a) a REAL qualified standard-tier run auto-enters the ship phase after the
      seal and runs a reversible action UNATTENDED -> SHIPPED (the auto-after-seal
      wiring, end to end through `run()`); skipped where no OS sandbox exists.
  (b) the full DRIVEN-CLI release flow on a hand-sealed hardened run: `ship` ->
      SHIP_APPROVAL_PENDING -> `df-release keygen/sign` -> attach -> `ship` ->
      SHIPPED, via real `supervisor.py` subprocess calls.
"""
import json
import os
import subprocess
import sys

import pytest

import df_custody
import df_sandbox
import supervisor
from test_ship import STUB, build_sealed_run, _base_config
from test_supervisor import FAKE, setup_control

SUP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py")
_CRYPTO = df_custody._CRYPTOGRAPHY_IMPORT_ERROR is None


def _sandbox_ok():
    if sys.platform not in ("darwin", "linux"):
        return False
    try:
        b = df_sandbox.current_backend()
    except Exception:
        return False
    return b is not None and getattr(b, "available", lambda: False)()


@pytest.mark.skipif(not _sandbox_ok(), reason="needs a real OS sandbox backend")
def test_real_qualified_run_auto_ships_reversible_unattended(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # H3: unattended, no pause
    marker = tmp_path / "shipped_marker"
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "standard"
    cfg["ship"] = {"actions": [{"name": "merge",
                                "run": [sys.executable, STUB, "touch", str(marker)],
                                "reversible": True, "timeout_s": 30}]}
    (cr / "config.json").write_text(json.dumps(cfg))

    rc = supervisor.run(str(cr), None)
    assert rc == 0, "auto-ship of a reversible action after a qualified seal should exit 0"
    assert marker.exists(), "the reversible ship action ran unattended after the seal"

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] == "COMPLETE_QUALIFIED" and manifest["qualified"] is True
    record = json.loads((run_dir / "ship_result.json").read_text())
    assert record["outcome"] == "SHIPPED"
    # the ship phase used a SEPARATE journal; the sealed journal.jsonl is intact
    assert (run_dir / "ship_journal.jsonl").exists()
    assert supervisor.SHIP_JOURNAL_FILE == "ship_journal.jsonl"


def _cli(*args, cwd=None):
    return subprocess.run([sys.executable, SUP, *args], capture_output=True, text=True,
                          timeout=120, cwd=cwd)


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_cli_release_gate_pending_then_attach_then_shipped(tmp_path):
    # keygen an approver via the real CLI.
    kg = _cli("df-release", "keygen")
    assert kg.returncode == 0
    keys = json.loads(kg.stdout)
    priv_file = tmp_path / "approver.key"
    priv_file.write_text(keys["private"])
    pub = keys["public"]

    cr = tmp_path / "control"
    marker = tmp_path / "prod_deployed"
    ship = {
        "actions": [{"name": "deploy", "run": [sys.executable, STUB, "touch", str(marker)],
                     "reversible": False, "rollback": [sys.executable, STUB, "remove", str(marker)],
                     "timeout_s": 30}],
        "approval": {"approvers": [pub], "threshold": 1},
    }
    cfg, run_dir, object_id, run_id = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "hardened", ship), {"app.txt": "v1"})
    manifest_path = str(run_dir / "manifest.json")

    # 1) ship (CLI) -> SHIP_APPROVAL_PENDING (exit 3); nothing deployed.
    r1 = _cli("ship", str(cr), "--run-dir", str(run_dir))
    assert r1.returncode == 3 and not marker.exists()
    assert "SHIP APPROVAL PENDING" in r1.stdout

    # 2) df-release sign (CLI) -> {claim, signatures}; collect into the control root.
    sg = _cli("df-release", "sign", "--manifest", manifest_path, "--actions", "deploy",
              "--expires", "2099-01-01T00:00:00Z", "--key-file", str(priv_file))
    assert sg.returncode == 0, sg.stderr
    (cr / supervisor.RELEASE_APPROVAL_FILE).write_text(sg.stdout)

    # 3) df-release attach (CLI) -> release_attestation.json.
    at = _cli("df-release", "attach", str(cr), "--run-dir", str(run_dir))
    assert at.returncode == 0, at.stderr
    assert (run_dir / supervisor.RELEASE_ATTESTATION_FILE).exists()

    # 4) ship (CLI) again -> the irreversible action runs -> SHIPPED (exit 0).
    r2 = _cli("ship", str(cr), "--run-dir", str(run_dir))
    assert r2.returncode == 0, r2.stderr
    assert marker.exists()
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == "SHIPPED"

    # A stale release cannot be replayed: the nonce is now in the ledger, and a
    # second attach of the same approval is refused (idempotent seal already
    # terminal too).
    at2 = _cli("df-release", "attach", str(cr), "--run-dir", str(run_dir))
    # attach re-verifies with the ledger -> nonce replay -> PENDING (exit 3)
    assert at2.returncode == 3
