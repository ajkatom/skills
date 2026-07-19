"""M45 RA-05 (fresh-run in-process window): the auditor's RA-05 is
"acceptance criteria can change DURING a run." M45's first cut sealed the
scenario bundle at run start and enforced it on RESUME (across a pause). This
regression covers the remaining same-process window: an actor that edits the
live control-root scenarios AFTER the run-start gate but BEFORE the sealed
final exam must not have the exam grade the artifact against altered criteria.

The in-process actor here is a builder adapter that, on its build call, both
(a) writes a working greet.py (so dev converges in one iteration) AND (b)
rewrites an existing scenario file's `title` in the control root (changing the
bundle hash without adding/removing a scenario, so the run stays otherwise
valid). Immediately before the sealed final exam re-reads `scenarios_dir`, the
supervisor re-hashes it, sees it drifted from the run-start seal, and seals
SCENARIO_BUNDLE_DRIFT (exit 2) instead of qualifying.

Fails BEFORE the fix (the run reaches COMPLETE_QUALIFIED grading the edited
bundle); passes after.
"""
import json
import os
import stat

import supervisor
from test_supervisor import setup_control


_ADAPTER = """#!/usr/bin/env python3
import json, os, sys
req = json.load(sys.stdin)
workdir = req["workdir"]
# (a) write a correct greet.py so dev converges on this first build.
open(os.path.join(workdir, "greet.py"), "w").write(
    "import sys\\n"
    "a = sys.argv[1:]\\n"
    "if not a:\\n"
    "    sys.stderr.write('usage: greet.py NAME\\\\n'); sys.exit(2)\\n"
    "print('Hello, ' + a[0] + '!')\\n"
)
# (b) mutate the live control-root scenario bundle mid-run (the RA-05 attack):
# rewrite one existing scenario's title. Path passed via env (cooperative
# tier inherits os.environ into the builder).
sd = os.environ.get("DF_TEST_SCENARIOS_DIR")
if sd:
    p = os.path.join(sd, "s0.json")
    sc = json.load(open(p))
    sc["title"] = sc.get("title", "") + " [EDITED MID-RUN]"
    json.dump(sc, open(p, "w"))
print(json.dumps({"adapter_protocol": "0.1", "status": "ok"}))
"""


def test_scenario_edit_mid_run_refuses_before_sealed_final_exam(tmp_path, monkeypatch):
    adapter = tmp_path / "mutating_adapter.py"
    adapter.write_text(_ADAPTER, encoding="utf-8")
    os.chmod(str(adapter), os.stat(str(adapter)).st_mode | stat.S_IEXEC)

    cr = setup_control(tmp_path, str(adapter), checkpoint="auto")
    monkeypatch.setenv("DF_TEST_SCENARIOS_DIR", str(cr / "scenarios"))

    rc = supervisor.run(str(cr), None)

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    m = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    # RA-05 fresh-run window closed: the mid-run scenario edit is caught before
    # the sealed final exam, and the run seals a distinct fail-closed terminal
    # rather than qualifying against the altered bundle.
    assert rc == 2, f"expected SCENARIO_BUNDLE_DRIFT exit 2, got {rc} (m={m.get('outcome')})"
    assert m["outcome"] == "SCENARIO_BUNDLE_DRIFT"
    assert m["qualified"] is False
    # The final exam never ran (we refused before it).
    assert m["final_exam"]["ran"] is False

    states = [
        json.loads(l)["state"]
        for l in (run_dir / "journal.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "SCENARIO_BUNDLE_DRIFT" in states
    # Barrier: the drift journal record carries only 12-char hash prefixes,
    # never scenario bytes.
    drift = next(
        json.loads(l)
        for l in (run_dir / "journal.jsonl").read_text(encoding="utf-8").splitlines()
        if json.loads(l)["state"] == "SCENARIO_BUNDLE_DRIFT"
    )
    assert len(drift["data"]["sealed"]) == 12 and len(drift["data"]["live"]) == 12
    assert "EDITED MID-RUN" not in json.dumps(drift)
