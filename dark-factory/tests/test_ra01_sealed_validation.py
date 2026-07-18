"""M44 RA-01 regression: the final exam + security gates must examine the
SEALED, content-addressed object — NOT the mutable `workspace` — so a
final-cohort scenario side effect (or a hostile candidate) that scrubs a
planted secret from the workspace AFTER the freeze can no longer launder a
run to `security.failed: []`.

THE REPRODUCED ATTACK (Codex re-audit, RA-01):
  - the builder writes a working greet.py PLUS a config.py holding a hardcoded
    fake AWS key (`fake_builder_secret`),
  - a FINAL-cohort scenario's `run` deletes config.py from its cwd and reports
    success (so the final exam passes),
  - BEFORE M44 the gates ran over `workspace`, which the final scenario had
    already scrubbed, so the run sealed with `security.failed: []` while the
    SHIPPED frozen object still held the secret.

AFTER M44 the gates scan a pristine copy materialized from the sealed object
(`R_gates`), which still contains config.py, so the run seals
SECURITY_GATE_FAILED / qualified False. This test therefore FAILS before the
fix (the pre-M44 code returns 0 / COMPLETE_UNQUALIFIED) and PASSES after.
"""
import json
import os

import supervisor
from test_supervisor import setup_control
from test_e2e_security import FAKE_SECRET, PLANTED_SECRET, _set_security_gates
from test_final_exam import add_final_scenario


def test_final_scenario_scrubbing_workspace_cannot_launder_a_sealed_secret(tmp_path):
    cr = setup_control(tmp_path, FAKE_SECRET, checkpoint="auto")
    _set_security_gates(cr, {"enabled": True, "fail_on": ["secret_scan"]})

    # The RA-01 attack: a passing FINAL-cohort scenario whose side effect is to
    # remove the planted-secret file from its working directory. Under the old
    # code this working directory WAS `workspace`, so by the time the gates ran
    # the secret was gone; under M44 the final exam runs in a throwaway copy and
    # the gates scan a SEPARATE copy of the sealed bytes, so the scrub is inert.
    add_final_scenario(
        cr, "BHV-901-S1", "BHV-901",
        ["python3", "-c",
         "import os; os.path.exists('config.py') and os.remove('config.py'); print('scrubbed')"],
        {"exit_code": 0, "stdout_equals": "scrubbed"},
        "sealed exam scrub attempt",
    )

    rc = supervisor.run(str(cr), None)

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    m = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    # RA-01 fixed: gates scanned the sealed object copy, still found the secret.
    assert rc == 3, f"expected SECURITY_GATE_FAILED exit 3, got {rc} (m={m.get('outcome')})"
    assert m["outcome"] == "SECURITY_GATE_FAILED"
    assert m["qualified"] is False
    assert m["security"]["failed"] == ["secret_scan"]
    assert m["security"]["gates"]["secret_scan"]["status"] == "fail"
    # The final exam DID run and DID pass (proving the rejection is a gate
    # verdict over the sealed object, not a scenario failure).
    assert m["final_exam"]["ran"] is True and m["final_exam"]["passed"] is True

    # The planted secret value must never leak into any run artifact.
    for dirpath, _dirs, files in os.walk(run_dir):
        for name in files:
            with open(os.path.join(dirpath, name), "rb") as f:
                assert PLANTED_SECRET.encode() not in f.read(), \
                    f"planted secret leaked into {name}"
