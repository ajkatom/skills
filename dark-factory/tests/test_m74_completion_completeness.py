"""M74 (Codex R9): DF-R9-01 — forward-completion chain→journal reverse-completeness.

M69 added the reverse-completeness check for ROLLBACK tokens but not COMPLETIONS,
and `_authenticate_ship_actions` short-circuited "nothing to authenticate" on empty
journal facts alone. So a same-user writer could delete a completed action's
journal attribution (SHIP_ACTION_INTENT + SHIP_ACTION_RESULT) while its genuine
signed completion token stayed anchored: recovery found no `already_done`, the
caller guard (`already_done or rollback`) skipped authentication entirely, and the
non-idempotent action RE-RAN (a duplicate). Now: authentication runs
unconditionally under signing, the short-circuit fires only when nothing is
anchored either, and every anchored completion token must map to a surviving
SHIP_ACTION_RESULT `ok`.
"""
import json

import supervisor
from test_ship import _base_config, build_sealed_run
from test_m49_ship_integrity import _counter_action


def _signed_shipped(tmp_path, name="deploy"):
    action, counter = _counter_action(tmp_path, name=name, reversible=True)
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [action]}, signed=True),
        {"a.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    return cr, run_dir, cfg, rid, counter


def _read(run_dir):
    return [json.loads(l) for l in
            (run_dir / "ship_journal.jsonl").read_text().splitlines()]


def _write(run_dir, events):
    (run_dir / "ship_journal.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")


def test_orphaned_completion_is_refused_no_duplicate(tmp_path):
    # THE R9-01 repro: delete the terminal + the completion's journal attribution,
    # keep the anchored completion token. Recovery must refuse (not re-run).
    cr, run_dir, cfg, rid, counter = _signed_shipped(tmp_path)
    assert counter.read_text() == "x"
    (run_dir / "ship_result.json").unlink()
    kept = [e for e in _read(run_dir)
            if e.get("state") not in ("SHIP_ACTION_INTENT", "SHIP_ACTION_RESULT")]
    _write(run_dir, kept)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "no surviving" in why
    assert supervisor.ship_cmd(str(cr), str(run_dir)) != 0
    assert counter.read_text() == "x"  # NO duplicate


def test_deleting_only_the_result_halts_on_unknown_intent(tmp_path):
    # Deleting ONLY the SHIP_ACTION_RESULT (keeping the intent) leaves an UNRESOLVED
    # intent → SHIP_UNKNOWN_OUTCOME halt (before authentication), never a re-run.
    cr, run_dir, cfg, rid, counter = _signed_shipped(tmp_path)
    (run_dir / "ship_result.json").unlink()
    kept = [e for e in _read(run_dir) if e.get("state") != "SHIP_ACTION_RESULT"]
    _write(run_dir, kept)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    assert counter.read_text() == "x"  # not re-run


def test_commit_window_crash_reconcile_not_bricked(tmp_path):
    # Opus review F1: a genuine crash AFTER the completion anchor but BEFORE its
    # RESULT (intent journaled, completion anchored, no ok-result, no terminal) is
    # the SAME shape as the R9-01 deletion — but the operator is told to run
    # `--decision reconcile`. That must NOT be refused as a false orphan (which
    # would permanently brick the run); reconcile re-runs it (a consented duplicate).
    cr, run_dir, cfg, rid, counter = _signed_shipped(tmp_path)
    (run_dir / "ship_result.json").unlink()
    kept = [e for e in _read(run_dir) if e.get("state") != "SHIP_ACTION_RESULT"]
    _write(run_dir, kept)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    rc = supervisor.ship_cmd(str(cr), str(run_dir), decision="reconcile")
    assert rc != supervisor.SHIP_STATE_UNAUTHENTICATED  # not bricked
    assert counter.read_text() == "xx"  # re-ran under explicit consent


def test_commit_window_crash_abort_not_bricked(tmp_path):
    # The abort variant: `--decision abort` must be able to seal SHIP_FAILED at the
    # unresolved commit-window action, not be routed into an orphan refusal.
    cr, run_dir, cfg, rid, counter = _signed_shipped(tmp_path)
    (run_dir / "ship_result.json").unlink()
    kept = [e for e in _read(run_dir) if e.get("state") != "SHIP_ACTION_RESULT"]
    _write(run_dir, kept)
    rc = supervisor.ship_cmd(str(cr), str(run_dir), decision="abort")
    assert rc != supervisor.SHIP_STATE_UNAUTHENTICATED  # not bricked


def test_genuine_shipped_reentry_still_authenticates(tmp_path):
    # No false positive: an untampered SHIPPED run re-authenticates cleanly.
    cr, run_dir, cfg, rid, counter = _signed_shipped(tmp_path)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok, why
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0  # idempotent re-entry
    assert counter.read_text() == "x"


def test_tampered_toolchain_orphans_the_completion(tmp_path):
    # Editing the intent's toolchain makes the recomputed completion token differ
    # from the anchored one → the anchored completion is orphaned → refuse.
    cr, run_dir, cfg, rid, counter = _signed_shipped(tmp_path)
    (run_dir / "ship_result.json").unlink()
    events = _read(run_dir)
    for e in events:
        if e.get("state") == "SHIP_ACTION_INTENT":
            e["data"]["toolchain"] = {"path": "/evil", "sha256": "e" * 64}
    _write(run_dir, events)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok
    assert supervisor.ship_cmd(str(cr), str(run_dir)) != 0
    assert counter.read_text() == "x"


def test_first_ship_authenticates_empty(tmp_path):
    # A genuine first ship (nothing anchored yet) authenticates trivially — the
    # short-circuit still fires when there is truly nothing anchored.
    action, counter = _counter_action(tmp_path, name="deploy", reversible=True)
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [action]}, signed=True),
        {"a.txt": "v1"})
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok and "no completed ship actions" in why
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert counter.read_text() == "x"
