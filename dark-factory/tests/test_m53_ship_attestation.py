"""M53 signed-ship attestation integrity (R4 re-audit): DF-R4-03 / DF-R4-04.

The two deepest remaining ship-security findings. Both are: a SHIPPED result can
be locally authoritative WITHOUT the required off-box/signed evidence actually
existing. Principle enforced here: a local SHIPPED must NEVER be authoritative
before the required off-box evidence succeeds, and the receipt proving it must not
be locally forgeable.

DF-R4-04 (crash window + forgeable receipt):
  - the ship seal pushes the FINAL SHIPPED bytes off-box FIRST and writes/anchors
    an authoritative local SHIPPED only on a SERVER-authentic receipt; a failed
    required-sink push seals SHIPPED_AUDIT_PENDING DIRECTLY, so there is no crash
    window in which a signature-valid local SHIPPED exists with no successful sink;
  - a required sink demands server_issued=True (a value only df_audit_sink.push
    sets, and only when the SERVER returned a receipt/version): a hand-written
    receipt with a correct LOCAL body_sha256 but no server value is REFUSED.

DF-R4-03 (local signed-anchor failure):
  - when signing is on and the local signed anchor cannot commit after an action
    ran, the run seals SHIPPED_AUDIT_PENDING/12 (never SHIPPED/0) and NEVER mints a
    replacement key (load_key, not load_or_create_key); the idempotent retry
    finalizes SHIPPED once the anchor + receipt both land, and the action runs
    EXACTLY once across the whole sequence.

All deterministic — stub/counter actions + an in-process toggle http-append sink
that can withhold/return a server receipt on demand; no real infra/paid. Reuses
the M49 sink + counter-action harness.
"""
import json
import os
import shutil
import socket
import sys

import df_audit
import df_ship
import supervisor
from test_ship import build_sealed_run, _base_config
from test_m49_ship_integrity import _toggle_sink, _counter_action, _sink_config


def _dead_sink_url():
    """A URL whose port has NOTHING listening → connection refused (URLError), so a
    readback against it is genuinely inconclusive/unreachable (the real audit-pending
    sink-outage condition), unlike a paused-but-still-GETtable in-process server."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


# --------------------------------------------------------------------------
# DF-R4-04 crash window: a failed REQUIRED-sink push never leaves an
# authoritative local SHIPPED; re-entry does not return 0 until the sink lands.
# --------------------------------------------------------------------------
def test_crash_window_required_sink_never_finalizes_local_shipped(tmp_path):
    httpd, sink_url, _store = _toggle_sink(tmp_path)
    try:
        cr = tmp_path / "control"
        action, counter = _counter_action(tmp_path)
        cfg_dict = _sink_config(tmp_path, {"actions": [action]}, sink_url)  # signed + required
        cfg, run_dir, _oid, rid = build_sealed_run(tmp_path, cr, cfg_dict, {"app.txt": "v1"})

        # Phase 1: sink DOWN. The action RUNS but the REQUIRED off-box push fails.
        # Push-first means NO authoritative local SHIPPED is ever written/anchored.
        httpd.fail = True
        rc = supervisor.ship_cmd(str(cr), str(run_dir))
        assert rc == supervisor.SHIP_AUDIT_PENDING == 12
        assert counter.read_text() == "x"  # action ran exactly once

        pending_text = (run_dir / "ship_result.json").read_text()
        rec = json.loads(pending_text)
        # On-disk record is SHIPPED_AUDIT_PENDING — NOT a finalized SHIPPED.
        assert rec["outcome"] == df_ship.SHIPPED_AUDIT_PENDING
        # The action really ran (recorded ok, not failed).
        assert [a["status"] for a in rec["actions"]] == ["ok"]
        # No off-box receipt yet — the required push never landed.
        assert not (run_dir / "ship_sink_receipt.json").exists()
        # The ONLY signature-valid "ship" chain entry anchors the PENDING record;
        # nothing anchors a finalized SHIPPED record.
        ok_c, why = supervisor._authenticate_ship_chain(
            cfg, str(cr), rid, supervisor.sha256_str(pending_text), "ship")
        assert ok_c, why
        # A required-sink verify of the on-disk record refuses fully-shipped.
        ok_r, _why = supervisor._sink_receipt_bound(
            str(run_dir), "ship_sink_receipt.json", pending_text,
            require_server_issued=True, sink=cfg["_audit"]["sink"])
        assert not ok_r

        # Re-entry with the sink STILL down does NOT return 0 (still pending),
        # and never re-runs the action.
        httpd.fail = True
        assert supervisor.ship_cmd(str(cr), str(run_dir)) == 12
        assert counter.read_text() == "x"

        # Sink UP: re-entry finalizes SHIPPED with a server-authentic receipt.
        httpd.fail = False
        assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
        assert counter.read_text() == "x"
        shipped_text = (run_dir / "ship_result.json").read_text()
        assert json.loads(shipped_text)["outcome"] == df_ship.SHIPPED
        rcpt = json.loads((run_dir / "ship_sink_receipt.json").read_text())
        assert rcpt["server_issued"] is True
        ok_r2, why2 = supervisor._sink_receipt_bound(
            str(run_dir), "ship_sink_receipt.json", shipped_text,
            require_server_issued=True, sink=cfg["_audit"]["sink"])
        assert ok_r2, why2
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# DF-R4-04 forgeable receipt: a correct-body_sha256 receipt with NO server value
# cannot make a run report fully-shipped; a server-issued receipt finalizes it.
# --------------------------------------------------------------------------
def test_forged_receipt_without_server_issued_is_refused(tmp_path):
    httpd, sink_url, _store = _toggle_sink(tmp_path)
    try:
        cr = tmp_path / "control"
        action, counter = _counter_action(tmp_path)
        # signing OFF, required sink — isolates the receipt-authentication logic.
        cfg_dict = _base_config(tmp_path, "standard", {"actions": [action]}, signed=False)
        cfg_dict["audit"] = {"signing": False,
                             "sink": {"kind": "http-append", "url": sink_url, "required": True}}
        cfg, run_dir, _oid, rid = build_sealed_run(tmp_path, cr, cfg_dict, {"app.txt": "v1"})

        # Phase 1: sink DOWN -> the required push fails -> SHIPPED_AUDIT_PENDING.
        httpd.fail = True
        assert supervisor.ship_cmd(str(cr), str(run_dir)) == 12
        assert counter.read_text() == "x"

        # Attacker (control-root write) FLIPS the on-disk record to SHIPPED and
        # fabricates a receipt with a correct LOCAL body_sha256 but no server value —
        # exactly the auditor's forgery (body_sha256 is locally computable).
        shipped = dict(json.loads((run_dir / "ship_result.json").read_text()))
        shipped["outcome"] = "SHIPPED"
        shipped_text = supervisor.canonical_json(shipped)
        (run_dir / "ship_result.json").write_text(shipped_text, encoding="utf-8")
        (run_dir / "ship_sink_receipt.json").write_text(supervisor.canonical_json({
            "kind": "http-append", "status": 201,
            "receipt": supervisor.sha256_str(shipped_text),   # locally computed
            "body_sha256": supervisor.sha256_str(shipped_text),
            "sink_key": f"{rid}.ship.forged"}), encoding="utf-8")

        # The auditor repro: re-entry with the sink STILL down must NOT accept the
        # forged receipt as fully-shipped.
        httpd.fail = True
        forged_receipt_accepted_rc = supervisor.ship_cmd(str(cr), str(run_dir))
        assert forged_receipt_accepted_rc != 0
        assert counter.read_text() == "x"  # actions never re-run

        # The forged receipt is rejected by the verify primitive itself.
        ok_r, why = supervisor._sink_receipt_bound(
            str(run_dir), "ship_sink_receipt.json", shipped_text,
            require_server_issued=True, sink=cfg["_audit"]["sink"])
        assert not ok_r
        assert "server-issued" in why

        # Genuine path: sink UP -> the retry pushes and gets a SERVER-issued receipt
        # -> finalizes SHIPPED/0 with server_issued=True (overwrites the forgery).
        httpd.fail = False
        assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
        final_text = (run_dir / "ship_result.json").read_text()
        assert json.loads(final_text)["outcome"] == "SHIPPED"
        rcpt = json.loads((run_dir / "ship_sink_receipt.json").read_text())
        assert rcpt["server_issued"] is True
        ok_r2, why2 = supervisor._sink_receipt_bound(
            str(run_dir), "ship_sink_receipt.json", final_text,
            require_server_issued=True, sink=cfg["_audit"]["sink"])
        assert ok_r2, why2
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------
# DF-R4-03 local signed-anchor failure: seal PENDING/12 (never SHIPPED/0), never
# mint a replacement key; retry finalizes SHIPPED once the key is restored.
# --------------------------------------------------------------------------
def test_local_anchor_failure_seals_pending_and_never_mints_key(tmp_path, monkeypatch):
    cr = tmp_path / "control"
    action, counter = _counter_action(tmp_path)
    cfg, run_dir, _oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [action]}, signed=True),
        {"app.txt": "v1"})
    key_path = cfg["_audit"]["key_path"]
    key_bak = key_path + ".bak"

    # Make the audit key VANISH after the action has run and its per-action token
    # was anchored (run_actions returns), so ONLY the seal-time ship-record anchor
    # fails. This is the DF-R4-03 window: load_key made to fail after an action ran.
    orig_run = df_ship.run_actions

    def _run_then_drop_key(*a, **k):
        res = orig_run(*a, **k)
        shutil.move(key_path, key_bak)  # key gone -> the seal-time load_key fails
        return res
    monkeypatch.setattr(df_ship, "run_actions", _run_then_drop_key)

    # Phase 1: the action runs once; the seal-time signed anchor cannot commit ->
    # SHIPPED_AUDIT_PENDING/12, NOT SHIPPED/0.
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_AUDIT_PENDING == 12
    assert counter.read_text() == "x"
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == \
        df_ship.SHIPPED_AUDIT_PENDING
    # DF-R4-03: NO replacement key was minted — the code uses load_key, not
    # load_or_create_key, so a missing key stays missing (fail-closed).
    assert not os.path.exists(key_path)
    assert os.path.exists(key_bak)
    # qualified is never re-opened by an audit-pending ship.
    assert json.loads((run_dir / "manifest.json").read_text())["qualified"] is True

    # Stop dropping the key and RESTORE it, then retry: the anchor now commits ->
    # SHIPPED/0, and the action is NOT re-run (exactly once across the sequence).
    monkeypatch.setattr(df_ship, "run_actions", orig_run)
    shutil.move(key_bak, key_path)
    rc2 = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc2 == 0
    assert counter.read_text() == "x"  # exactly ONE run across phase 1 + retry
    final_text = (run_dir / "ship_result.json").read_text()
    assert json.loads(final_text)["outcome"] == df_ship.SHIPPED
    # The finalized SHIPPED authenticates against the signed chain (anchor committed).
    ok_c, why = supervisor._authenticate_ship_chain(
        cfg, str(cr), rid, supervisor.sha256_str(final_text), "ship")
    assert ok_c, why


# --------------------------------------------------------------------------
# R4 re-audit FINDING 1: a terminal SHIP_FAILED must NOT be launderable into
# SHIPPED by flipping the on-disk outcome to SHIPPED_AUDIT_PENDING. The unanchored
# pending path must bind the record to COMPLETE signed per-action evidence.
# --------------------------------------------------------------------------
def test_laundered_ship_failed_pending_is_refused(tmp_path):
    cr = tmp_path / "control"
    ok_marker = tmp_path / "ok_ran"
    # a1 succeeds (reversible -> anchored per-action ok-token + ok journaled); a2
    # FAILS -> rollback -> SHIP_FAILED terminal.
    a1 = {"name": "deploy",
          "run": [sys.executable, "-c", f"open(r'{ok_marker}','w').write('x')"],
          "reversible": True, "rollback": [sys.executable, "-c", "pass"], "timeout_s": 30}
    a2 = {"name": "notify", "run": [sys.executable, "-c", "import sys; sys.exit(1)"],
          "reversible": True, "timeout_s": 30}
    cfg_dict = _base_config(tmp_path, "standard", {"actions": [a1, a2]}, signed=True)
    cfg, run_dir, _oid, rid = build_sealed_run(tmp_path, cr, cfg_dict, {"app.txt": "v1"})

    # Real ship: a1 succeeds, a2 fails -> SHIP_FAILED (exit 3), and a re-entry is
    # terminal (exit 3), never re-shipped.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    rec = json.loads((run_dir / "ship_result.json").read_text())
    assert rec["outcome"] == df_ship.SHIP_FAILED
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3

    # ATTACK: control-root writer flips the terminal SHIP_FAILED record to
    # SHIPPED_AUDIT_PENDING (unanchored — the tampered bytes were never anchored; no
    # signature is forged) to ride a1's REAL ok-token into a finalized SHIPPED.
    laundered = dict(rec)
    laundered["outcome"] = df_ship.SHIPPED_AUDIT_PENDING
    (run_dir / "ship_result.json").write_text(
        supervisor.canonical_json(laundered), encoding="utf-8")

    # Re-entry REFUSES (fail-closed): the failed action `notify` has no anchored
    # ok-token, so the pending record is not bound to a complete run -> exit 2,
    # NEVER SHIPPED/0.
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_STATE_UNAUTHENTICATED == 2
    final = json.loads((run_dir / "ship_result.json").read_text())
    assert final["outcome"] != df_ship.SHIPPED


# --------------------------------------------------------------------------
# R4 re-audit FINDING 2: server_issued lives in the same-user-writable receipt
# file, so it is not trusted on its own — an INCONCLUSIVE readback (unreachable
# sink) must NOT satisfy a required-sink verification.
# --------------------------------------------------------------------------
def test_forged_server_issued_receipt_with_unreachable_sink_is_refused(tmp_path):
    cr = tmp_path / "control"
    action = {"name": "deploy", "run": [sys.executable, "-c", "pass"],
              "reversible": True, "timeout_s": 30}
    # signing OFF, required sink pointed at a DEAD port (a genuine outage → readback
    # is unreachable/None, exactly the audit-pending condition).
    sink_url = _dead_sink_url()
    cfg_dict = _base_config(tmp_path, "standard", {"actions": [action]}, signed=False)
    cfg_dict["audit"] = {"signing": False,
                         "sink": {"kind": "http-append", "url": sink_url, "required": True}}
    cfg, run_dir, _oid, rid = build_sealed_run(tmp_path, cr, cfg_dict, {"app.txt": "v1"})

    # Phase 1: required push fails (sink dead) -> SHIPPED_AUDIT_PENDING/12.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 12

    # ATTACK: flip to SHIPPED + hand-write a receipt with server_issued:true and a
    # correct LOCAL body_sha256 (both locally computable; no server ever issued it).
    shipped = dict(json.loads((run_dir / "ship_result.json").read_text()))
    shipped["outcome"] = "SHIPPED"
    shipped_text = supervisor.canonical_json(shipped)
    (run_dir / "ship_result.json").write_text(shipped_text, encoding="utf-8")
    (run_dir / "ship_sink_receipt.json").write_text(supervisor.canonical_json({
        "kind": "http-append", "status": 201,
        "receipt": supervisor.sha256_str(shipped_text),
        "server_issued": True,  # attacker-authored flag
        "body_sha256": supervisor.sha256_str(shipped_text),
        "sink_key": f"{rid}.ship.forged"}), encoding="utf-8")

    # The verify primitive REJECTS the forged receipt: an unreachable sink cannot be
    # POSITIVELY confirmed, so server_issued alone is not off-box evidence.
    ok_r, why = supervisor._sink_receipt_bound(
        str(run_dir), "ship_sink_receipt.json", shipped_text,
        require_server_issued=True, sink=cfg["_audit"]["sink"])
    assert not ok_r
    assert "POSITIVELY" in why or "not off-box evidence" in why

    # End-to-end: re-entry does NOT report fully-shipped (still audit-pending).
    rc2 = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc2 != 0


def test_anchor_ship_local_uses_load_key_never_creates(tmp_path):
    """DF-R4-03 unit guard: _anchor_ship_local with signing on and an ABSENT key
    returns 'anchor_failed' and does NOT create a replacement key file (proving it
    calls load_key, never load_or_create_key)."""
    key_path = str(tmp_path / "nokey" / "audit.key")
    cfg = {"_audit": {"signing": True, "key_path": key_path,
                      "sink": {"kind": "none", "required": False}}}
    status = supervisor._anchor_ship_local(cfg, str(tmp_path), "rid", "some bytes", "ship")
    assert status == "anchor_failed"
    assert not os.path.exists(key_path)  # NEVER minted a replacement key
