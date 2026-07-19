import json
import os
import subprocess
import sys

import pytest

import df_sandbox
from test_supervisor import FAKE, external_reachable, needs_network, setup_control

SUP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py")


@needs_network
@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_run_is_qualified_and_holdout_is_os_denied(tmp_path):
    b = df_sandbox.current_backend()
    if not (b and b.available()):
        pytest.skip("no OS sandbox primitive")
    if not external_reachable():
        pytest.skip("no external reachability for the candidate egress-denial probe")
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"
    # M47 RA-08(a): confine candidate egress so the run QUALIFIES.
    cfg["candidate_network"] = "deny"; p.write_text(json.dumps(cfg))

    proc = subprocess.run([sys.executable, SUP, "run", "--control-root", str(cr)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "COOPERATIVE MODE" not in proc.stderr        # not downgraded
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_QUALIFIED" and m["qualified"] is True
    assert m["denial_probe_passed"] is True

    # Independent OS-level proof: a process wrapped by the same backend cannot read
    # the real holdout scenarios living under the control root.
    secret = next((cr / "scenarios").glob("*.json"))
    pref = b.wrap_prefix(str(cr), str(tmp_path / "ws"))
    denied = subprocess.run(pref + ["cat", str(secret)], capture_output=True, text=True)
    assert denied.returncode != 0                        # OS denied the read
