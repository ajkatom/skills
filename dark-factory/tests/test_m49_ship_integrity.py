"""M49 ship-phase audit integrity (Codex re-audit #06): DF-R3-02 / -03 / -06.

All deterministic — stub actions, a controllable in-process http-append sink, NO
real infra. Builds on the M41 hand-sealed-qualified-run harness in test_ship.

DF-R3-02: a REQUIRED off-box sink failure during a SHIPPED ship must seal a
  DISTINCT outcome (SHIPPED_AUDIT_PENDING, exit 12), never a silent exit-0; a
  re-entry with the sink now reachable runs an IDEMPOTENT audit-only retry that
  re-anchors off-box and flips to SHIPPED (exit 0) WITHOUT re-running the actions.
DF-R3-03: on re-entry, a planted terminal ship_result.json (no signature-valid
  chain entry) is REFUSED (exit 2); a post-seal-tampered ship journal that would
  skip a real action via `already_done` is REFUSED.
DF-R3-06: the materialized sealed-artifact workspace is cleaned up on EVERY exit
  path (success / fail / approval-pending / materialize-failure); the ship record
  carries the per-action toolchain identity.
"""
import http.server
import json
import os
import sys
import tempfile
import threading

import pytest

import df_audit_receiver
import df_custody
import df_ship
import supervisor
from test_ship import STUB, build_sealed_run, _base_config

_CRYPTO = df_custody._CRYPTOGRAPHY_IMPORT_ERROR is None


# --------------------------------------------------------------------------
# A controllable in-process http-append sink: append-only WORM semantics (like
# df_audit_receiver) but with a `fail` toggle so ONE stable URL can fail (503)
# then succeed (201) across a crash+resume — the sealed config's sink URL is
# policy-bound to config_sha256, so it cannot be swapped between attempts.
# --------------------------------------------------------------------------
class _ToggleHandler(df_audit_receiver._Handler):
    def do_PUT(self):
        if getattr(self.server, "fail", False):
            self._send_json(503, {"error": "sink down (test toggle)"})
            return
        super().do_PUT()


class _ToggleServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, store_dir):
        self.store_dir = store_dir
        self.fail = True
        super().__init__(addr, _ToggleHandler)


def _toggle_sink(tmp_path):
    store = tmp_path / "sink-store"
    store.mkdir()
    httpd = _ToggleServer(("127.0.0.1", 0), str(store))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}", store


def _counter_action(tmp_path, name="deploy", reversible=True):
    """A ship action that APPENDS one byte per run to a counter file, so a test
    can prove it ran EXACTLY once across a failed-then-succeeding attempt."""
    counter = tmp_path / "run_count"
    script = tmp_path / "count.py"
    script.write_text(
        "import sys\n"
        "with open(sys.argv[1], 'a') as f:\n"
        "    f.write('x')\n",
        encoding="utf-8")
    action = {"name": name, "run": [sys.executable, str(script), str(counter)],
              "reversible": reversible, "timeout_s": 30}
    return action, counter


def _sink_config(tmp_path, ship_block, sink_url, *, required=True, tier="standard"):
    cfg = _base_config(tmp_path, tier, ship_block, signed=True)
    cfg["audit"]["sink"] = {"kind": "http-append", "url": sink_url, "required": required}
    return cfg


# --------------------------------------------------------------------------
# DF-R3-02: required off-box sink failure -> SHIPPED_AUDIT_PENDING(12); retry -> 0
# --------------------------------------------------------------------------
def test_required_sink_failure_seals_audit_pending_then_idempotent_retry(tmp_path):
    httpd, sink_url, store = _toggle_sink(tmp_path)
    try:
        cr = tmp_path / "control"
        action, counter = _counter_action(tmp_path)
        cfg_dict = _sink_config(tmp_path, {"actions": [action]}, sink_url)
        cfg, run_dir, _oid, _rid = build_sealed_run(tmp_path, cr, cfg_dict, {"app.txt": "v1"})

        # Phase 1: sink is DOWN. The action RUNS (real-world effect applied) but
        # the REQUIRED off-box push fails -> DISTINCT outcome + distinct exit 12.
        httpd.fail = True
        rc = supervisor.ship_cmd(str(cr), str(run_dir))
        assert rc == supervisor.SHIP_AUDIT_PENDING == 12
        assert counter.read_text() == "x"  # the action ran exactly once
        record = json.loads((run_dir / "ship_result.json").read_text())
        assert record["outcome"] == df_ship.SHIPPED_AUDIT_PENDING
        # the action is recorded ok — NOT failed (it really ran)
        assert [a["status"] for a in record["actions"]] == ["ok"]
        # no bound off-box receipt yet (the required push never landed)
        assert not (run_dir / "ship_sink_receipt.json").exists()
        # qualified is NOT re-opened by an audit-pending ship
        assert json.loads((run_dir / "manifest.json").read_text())["qualified"] is True

        # Phase 2: sink is UP. Re-entry runs the IDEMPOTENT audit-only retry:
        # off-box re-anchored, outcome flipped to SHIPPED, action NOT re-run.
        httpd.fail = False
        rc2 = supervisor.ship_cmd(str(cr), str(run_dir))
        assert rc2 == 0
        assert counter.read_text() == "x"  # STILL one run — never re-executed
        record2 = json.loads((run_dir / "ship_result.json").read_text())
        assert record2["outcome"] == df_ship.SHIPPED
        # the bound receipt now exists and binds THESE ship-record bytes
        ok_bound, why = supervisor._sink_receipt_bound(
            str(run_dir), "ship_sink_receipt.json",
            (run_dir / "ship_result.json").read_text())
        assert ok_bound, why
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_shipped_with_required_sink_but_missing_receipt_is_not_fully_shipped(tmp_path):
    """Verify-path guard: a SHIPPED record under a required sink whose bound
    receipt is absent is NOT treated as a silent fully-shipped on re-entry — it
    re-runs the audit-only retry (here the sink is up, so it finalizes)."""
    httpd, sink_url, store = _toggle_sink(tmp_path)
    try:
        cr = tmp_path / "control"
        action, counter = _counter_action(tmp_path)
        cfg_dict = _sink_config(tmp_path, {"actions": [action]}, sink_url)
        cfg, run_dir, _oid, _rid = build_sealed_run(tmp_path, cr, cfg_dict, {"app.txt": "v1"})

        httpd.fail = False
        assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
        assert (run_dir / "ship_sink_receipt.json").exists()

        # Simulate the receipt going missing (a SHIPPED record with no off-box
        # evidence). Re-entry must NOT report fully-shipped silently; it re-anchors.
        (run_dir / "ship_sink_receipt.json").unlink()
        assert counter.read_text() == "x"
        assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
        assert counter.read_text() == "x"  # not re-run
        assert (run_dir / "ship_sink_receipt.json").exists()  # re-anchored
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# DF-R3-03: local ship terminal state trusted only under the signed audit chain
# --------------------------------------------------------------------------
def test_planted_shipped_result_without_chain_entry_is_refused(tmp_path):
    cr = tmp_path / "control"
    marker = tmp_path / "merged"
    # signed standard run, no sink
    cfg_dict = _base_config(tmp_path, "standard", _rev(marker), signed=True)
    cfg, run_dir, _oid, _rid = build_sealed_run(tmp_path, cr, cfg_dict, {"app.txt": "v1"})

    # An attacker with control-root write PLANTS a terminal SHIPPED result to
    # SUPPRESS a real ship (make automation believe it already shipped).
    (run_dir / "ship_result.json").write_text(json.dumps({
        "ship_version": "1", "outcome": "SHIPPED", "actions": [],
        "rollbacks": [], "rollback_failed": False, "pending_action": None,
        "failed_action": None, "ship_workspace_object_id": _oid, "ts": "t"}),
        encoding="utf-8")

    # Signing is on -> the planted result has no signature-valid chain entry ->
    # REFUSE (fail-closed), never trust the terminal outcome.
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_STATE_UNAUTHENTICATED == 2
    assert not marker.exists()

    # And the action is genuinely still runnable — removing the plant lets the
    # real, authenticated ship proceed to SHIPPED.
    (run_dir / "ship_result.json").unlink()
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert marker.exists()


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_planted_ok_result_to_skip_a_real_action_is_refused(tmp_path):
    """The per-action-anchoring attack (DF-R3-03): a same-user control-root writer
    plants a fake SHIP_ACTION_RESULT `ok` for the irreversible `deploy` action so
    that `already_done` skips it — bypassing the signed-approval gate entirely.
    The planted `ok` has no individually-anchored, signature-valid chain token, so
    re-entry REFUSES (exit 2) and the irreversible action never runs."""
    priv, pub = df_custody.generate_keypair()
    cr = tmp_path / "control"
    m1, m2 = tmp_path / "reversible_ran", tmp_path / "deployed"
    ship = {
        "actions": [
            {"name": "prep", "run": [sys.executable, STUB, "touch", str(m1)],
             "reversible": True, "timeout_s": 30},
            {"name": "deploy", "run": [sys.executable, STUB, "touch", str(m2)],
             "reversible": False, "timeout_s": 30},
        ],
        "approval": {"approvers": [pub], "threshold": 1},
    }
    cfg, run_dir, _oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "hardened", ship), {"app.txt": "v1"})

    # First ship: the reversible `prep` runs (ok, individually anchored), the
    # irreversible `deploy` is gated -> SHIP_APPROVAL_PENDING.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    assert m1.exists() and not m2.exists()

    # Control: an HONEST re-entry authenticates prep's per-action anchor fine and
    # re-reaches SHIP_APPROVAL_PENDING (prep skipped via already_done).
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    assert not m2.exists()

    # Attack: plant a fake `ok` RESULT for `deploy` (never ran) to skip the gated
    # action. The idempotency_key is deterministic, so the attacker can compute it
    # — but they cannot forge the SIGNED per-action chain token.
    dk = df_ship.idempotency_key(rid, "deploy", 1)
    with open(run_dir / supervisor.SHIP_JOURNAL_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "t", "state": "SHIP_ACTION_RESULT",
                            "data": {"action": "deploy", "index": 1,
                                     "idempotency_key": dk, "status": "ok", "exit": 0}}) + "\n")

    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_STATE_UNAUTHENTICATED == 2
    assert not m2.exists()  # the irreversible action never ran


def test_honest_crash_before_seal_recovers_under_signing(tmp_path, monkeypatch):
    """DF-R3-03 crash-recovery (the M49 re-audit fix): a signed multi-action ship
    that runs its actions then crashes BEFORE the seal must, on honest re-entry,
    authenticate and finish sealing SHIPPED — NOT be refused as tampered. Each
    completed action is individually anchored as it commits, so `already_done` is
    chain-backed even with no seal-time digest."""
    cr = tmp_path / "control"
    a1, c1 = _counter_action(tmp_path, name="a1")
    a2, c2 = _counter_action(tmp_path, name="a2")
    # distinct counter files
    a2["run"][2] = str(tmp_path / "c2")
    ship = {"actions": [a1, a2]}
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", ship, signed=True), {"app.txt": "v1"})

    # Crash right before the seal (both actions ran + committed their anchors).
    orig_seal = supervisor._seal_ship_result
    monkeypatch.setattr(supervisor, "_seal_ship_result",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash before seal")))
    try:
        supervisor.ship_cmd(str(cr), str(run_dir))
    except RuntimeError:
        pass
    monkeypatch.setattr(supervisor, "_seal_ship_result", orig_seal)
    assert sorted(supervisor._ship_completed_actions(str(run_dir))) == ["a1", "a2"]

    # Honest re-entry: authenticates + seals SHIPPED, actions NOT re-run.
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 0
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == "SHIPPED"
    assert (tmp_path / "run_count").read_text() == "x"  # a1 ran exactly once
    assert (tmp_path / "c2").read_text() == "x"          # a2 ran exactly once


def test_audit_key_load_failure_does_not_poison_the_signed_chain(tmp_path, monkeypatch):
    """DF-R3 Finding 2: when signing is on but the audit key cannot be loaded,
    `_anchor_ship_record` must NOT append an UNSIGNED entry (which would make
    verify_chain fail the ENTIRE control-root chain, breaking custody/qualification
    verify too). It skips the local anchor and surfaces the failure honestly."""
    import df_audit
    cr = tmp_path / "control"
    marker = tmp_path / "merged"
    cfg, run_dir, _oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", _rev(marker), signed=True),
        {"app.txt": "v1"})
    # A real signed ship establishes a signed chain (ship record + per-action tokens).
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    chain = cr / "audit-chain.jsonl"
    lines_before = chain.read_text().count("\n")
    assert lines_before >= 1
    key = df_audit.load_key(cfg["_audit"]["key_path"])
    assert supervisor.df_audit_chain.verify_chain(str(chain), key)[0]

    # Force the audit key load to fail, then anchor another ship record: it must
    # NOT append an unsigned entry into the signed chain.
    monkeypatch.setattr(df_audit, "load_or_create_key",
                        lambda *a, **k: (_ for _ in ()).throw(df_audit.AuditKeyError("boom")))
    status = supervisor._anchor_ship_record(
        cfg, str(cr), str(run_dir), rid, "another ship record", "ship", push_offbox=False)
    assert status == "skip"
    # No new (unsigned) entry, and the signed chain still verifies with the real key.
    assert chain.read_text().count("\n") == lines_before
    ok, why = supervisor.df_audit_chain.verify_chain(str(chain), key)
    assert ok, why


# --------------------------------------------------------------------------
# DF-R3-06: ship-workspace cleanup on every path + toolchain identity recorded
# --------------------------------------------------------------------------
def _rev(marker):
    return {"actions": [{"name": "merge", "run": [sys.executable, STUB, "touch", str(marker)],
                         "reversible": True, "timeout_s": 30}]}


def _no_ship_ws_leak(controlled_tmp):
    return [p for p in os.listdir(controlled_tmp) if p.startswith("df-ship-ws-")]


@pytest.mark.parametrize("scenario", ["success", "fail", "materialize"])
def test_ship_workspace_is_cleaned_up_on_every_path(tmp_path, monkeypatch, scenario):
    controlled = tmp_path / "systmp"
    controlled.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(controlled))

    cr = tmp_path / "control"
    if scenario == "success":
        ship = _rev(tmp_path / "m")
    else:  # fail path: the single action exits nonzero -> SHIP_FAILED
        ship = {"actions": [{"name": "boom", "run": [sys.executable, STUB, "fail"],
                             "reversible": True, "timeout_s": 30}]}
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", ship), {"app.txt": "v1"})

    if scenario == "materialize":
        def _boom(*a, **k):
            raise df_ship.ShipError("materialize failed (test)")
        monkeypatch.setattr(df_ship, "materialize_ship_workspace", _boom)

    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc in (0, 3)
    # DF-R3-06: no fresh copy of the sealed artifact is left behind, on ANY path.
    assert _no_ship_ws_leak(controlled) == []


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_ship_workspace_cleaned_on_approval_pending_path(tmp_path, monkeypatch):
    controlled = tmp_path / "systmp"
    controlled.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(controlled))

    _priv, pub = df_custody.generate_keypair()
    cr = tmp_path / "control"
    ship = {"actions": [{"name": "deploy", "run": [sys.executable, STUB, "touch", str(tmp_path / "d")],
                         "reversible": False, "timeout_s": 30}],
            "approval": {"approvers": [pub], "threshold": 1}}
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "hardened", ship), {"app.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3  # SHIP_APPROVAL_PENDING
    assert _no_ship_ws_leak(controlled) == []


def test_ship_record_carries_per_action_toolchain_identity(tmp_path):
    cr = tmp_path / "control"
    marker = tmp_path / "merged"
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", _rev(marker)), {"app.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0

    record = json.loads((run_dir / "ship_result.json").read_text())
    tc = record["toolchain"]
    assert isinstance(tc, list) and len(tc) == 1
    entry = tc[0]
    assert entry["action"] == "merge"
    assert entry["argv0"] == sys.executable
    # sys.executable is a regular readable file -> resolved + hashed honestly
    assert entry["resolved_path"]
    assert isinstance(entry["sha256"], str) and len(entry["sha256"]) == 64
