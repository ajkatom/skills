"""M56 (Codex R5): ship-evidence integrity.

DF-R5-01 — an editable, UNANCHORED SHIPPED_AUDIT_PENDING record must NOT be
convertible into a signed SHIPPED whose evidence fields (artifact id, action
exit, toolchain) were tampered. The audit-only retry must RECONSTRUCT the final
record from AUTHENTICATED facts (sealed manifest id + chain-authenticated
per-action facts), never copy the writable pending blob.

Deterministic; reuses the M53/M49 sealed-run + counter-action + key-vanish
harness (no real infra/paid).
"""
import json
import os
import shutil

import df_ship
import supervisor
from test_ship import build_sealed_run, _base_config
from test_m49_ship_integrity import _counter_action


def _make_unanchored_pending(tmp_path, monkeypatch):
    """Drive a signed standard run to a legitimately-UNANCHORED
    SHIPPED_AUDIT_PENDING: the action runs (its per-action token anchors), then the
    audit key vanishes so ONLY the seal-time ship-record anchor fails."""
    cr = tmp_path / "control"
    action, counter = _counter_action(tmp_path)
    cfg, run_dir, real_oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [action]}, signed=True),
        {"app.txt": "v1"})
    key_path = cfg["_audit"]["key_path"]
    key_bak = key_path + ".bak"
    orig_run = df_ship.run_actions

    def _run_then_drop_key(*a, **k):
        res = orig_run(*a, **k)
        shutil.move(key_path, key_bak)
        return res
    monkeypatch.setattr(df_ship, "run_actions", _run_then_drop_key)
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_AUDIT_PENDING
    assert counter.read_text() == "x"
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == \
        df_ship.SHIPPED_AUDIT_PENDING
    # restore the key + un-monkeypatch so the retry can commit.
    monkeypatch.setattr(df_ship, "run_actions", orig_run)
    shutil.move(key_bak, key_path)
    return cr, run_dir, cfg, rid, real_oid, counter


def test_forged_pending_fields_never_reach_signed_shipped(tmp_path, monkeypatch):
    cr, run_dir, cfg, rid, real_oid, counter = _make_unanchored_pending(tmp_path, monkeypatch)

    # ATTACK (the auditor's exact repro): a control-root writer edits the writable
    # unanchored pending record — artifact id, the action's exit, and the toolchain
    # path/hash — while keeping the AUTHENTICATED action name + status:"ok".
    rec = json.loads((run_dir / "ship_result.json").read_text())
    forged_oid = "f" * 64
    rec["ship_workspace_object_id"] = forged_oid
    for a in rec.get("actions", []):
        a["exit"] = 999                      # keep a["status"] == "ok"
        a["reversible"] = False              # forge the reversibility-gate claim
        a["approval_ref"] = "FORGED-APPROVAL-9999"   # forge the authorizing approval
    rec["toolchain"] = [{"action": (rec["actions"][0]["name"] if rec.get("actions") else "x"),
                         "argv0": "/evil", "resolved_path": "/evil",
                         "sha256": "e" * 64, "note": "forged"}]
    (run_dir / "ship_result.json").write_text(json.dumps(rec), encoding="utf-8")

    # RETRY: the audit-only retry reconstructs from authenticated facts.
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 0, "a legitimate completed ship must still finalize"
    assert counter.read_text() == "x", "the action is NEVER re-run"

    final = json.loads((run_dir / "ship_result.json").read_text())
    assert final["outcome"] == df_ship.SHIPPED
    # The forged values are DISCARDED — every evidence field derives from an
    # authenticated source, not the writable pending blob:
    assert final["ship_workspace_object_id"] == real_oid, "artifact id from the sealed manifest"
    assert final["ship_workspace_object_id"] != forged_oid
    for a in final["actions"]:
        assert a["exit"] == 0, "authenticated-ok action is exit 0 by definition"
        assert a["status"] == "ok"
        # DF-R5-01 (review residual): reversibility + approval evidence are the
        # AUTHENTICATED (chain-token-bound) values, not the forged pending ones.
        assert a["reversible"] is True, "authenticated reversibility, not forged false"
        assert a["approval_ref"] != "FORGED-APPROVAL-9999", "authenticated approval, not forged"
    dumped = json.dumps(final)
    assert "/evil" not in dumped and "e" * 64 not in dumped, "forged toolchain discarded"
    assert "FORGED-APPROVAL-9999" not in dumped, "forged approval_ref discarded"

    # And the finalized SHIPPED authenticates against the signed chain (the
    # reconstructed bytes were push+anchored, not the forged blob).
    ok_c, why = supervisor._authenticate_ship_chain(
        cfg, str(cr), rid, supervisor.sha256_str((run_dir / "ship_result.json").read_text()),
        "ship")
    assert ok_c, why


def test_every_field_of_the_pending_record_is_reconstructed_not_trusted(tmp_path, monkeypatch):
    # M60 (R5 arbitration M56.7): mutate EVERY field of the writable pending
    # record, not only the three in the R5 repro. Because the final SHIPPED is
    # RECONSTRUCTED from authenticated facts (never dict(prior)), no forged field
    # — evidence or cosmetic — survives into the signed bytes.
    cr, run_dir, cfg, rid, real_oid, counter = _make_unanchored_pending(tmp_path, monkeypatch)
    rec = json.loads((run_dir / "ship_result.json").read_text())
    # Forge every field EXCEPT the two that DEFINE the record's authenticated
    # identity — outcome (the re-entry path) and each action's status:"ok" (the
    # M53 laundering guard binds the claimed ok-SET to the signed tokens, so
    # flipping it is a SEPARATE, already-refused attack; see the laundering
    # tests). Everything else — evidence and cosmetic — is mutated to a poison
    # sentinel; NONE may survive into the reconstructed signed bytes.
    rec["ship_version"] = "666"
    rec["ship_workspace_object_id"] = "f" * 64
    rec["pending_action"] = "POISON-PENDING"
    rec["failed_action"] = "POISON-FAILED"
    rec["rollbacks"] = [{"name": "POISON-ROLLBACK", "status": "rolled_back"}]
    rec["rollback_failed"] = True
    rec["ts"] = "1999-01-01T00:00:00Z"
    rec["toolchain"] = [{"action": "x", "argv0": "/evil", "resolved_path": "/evil",
                         "sha256": "e" * 64}]
    rec["rollback_toolchain"] = [{"action": "x", "argv0": "/evil-rb"}]
    rec["EXTRA_INJECTED_KEY"] = "POISON-EXTRA"
    for a in rec.get("actions", []):
        a["exit"] = 999
        a["reversible"] = False
        a["approval_ref"] = "POISON-APPROVAL"
        a["duration_s"] = 123456
        a["INJECTED"] = "POISON-ACTION-KEY"
    (run_dir / "ship_result.json").write_text(json.dumps(rec), encoding="utf-8")

    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 0, "the legitimately-completed ship still finalizes"
    assert counter.read_text() == "x", "the action is NEVER re-run"

    final = json.loads((run_dir / "ship_result.json").read_text())
    assert final["outcome"] == df_ship.SHIPPED
    assert final["ship_workspace_object_id"] == real_oid
    assert final["pending_action"] is None
    assert final["failed_action"] is None
    assert final["rollbacks"] == [] and final["rollback_failed"] is False
    for a in final["actions"]:
        assert a["status"] == "ok" and a["exit"] == 0
        assert a["reversible"] is True and a["approval_ref"] != "POISON-APPROVAL"
        assert "INJECTED" not in a
    dumped = json.dumps(final)
    for poison in ("POISON-PENDING", "POISON-FAILED", "POISON-ROLLBACK",
                   "POISON-APPROVAL", "POISON-EXTRA", "POISON-ACTION-KEY",
                   "/evil", "e" * 64, "1999-01-01"):
        assert poison not in dumped, f"forged field {poison!r} leaked into signed bytes"
    # The reconstructed bytes authenticate against the signed chain.
    ok_c, why = supervisor._authenticate_ship_chain(
        cfg, str(cr), rid, supervisor.sha256_str((run_dir / "ship_result.json").read_text()),
        "ship")
    assert ok_c, why


def test_tampered_toolchain_breaks_per_action_authentication(tmp_path, monkeypatch):
    # Independently: editing the recovered toolchain so the per-action token can't be
    # recomputed must FAIL authentication (not silently accept a forged tool).
    cr, run_dir, cfg, rid, real_oid, counter = _make_unanchored_pending(tmp_path, monkeypatch)
    # Tamper the SHIP_ACTION_INTENT toolchain in the ship journal (the source
    # _ship_completed_action_facts recovers the toolchain from).
    jp = run_dir / "ship_journal.jsonl"
    lines = jp.read_text().splitlines()
    out = []
    for ln in lines:
        e = json.loads(ln)
        if e.get("state") == "SHIP_ACTION_INTENT" and e.get("data", {}).get("toolchain"):
            e["data"]["toolchain"]["sha256"] = "e" * 64  # forge the tool hash
        out.append(json.dumps(e))
    jp.write_text("\n".join(out) + "\n", encoding="utf-8")

    ok_a, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok_a, "a tampered toolchain must break per-action authentication"
    assert "toolchain" in why or "not individually anchored" in why


# --- DF-R5-08: a torn/corrupt ship journal must never raise an uncaught exception -

import df_ship as _df_ship  # noqa: E402
import pytest  # noqa: E402


# --- DF-R5-07: S3 Object-Lock readback makes an S3 receipt idempotently verifiable -
import hashlib as _hashlib  # noqa: E402
import http.server as _hs  # noqa: E402
import threading as _threading  # noqa: E402

import df_audit_sink  # noqa: E402


class _StubS3:
    """Minimal in-process S3-GET stub: serves stored objects on GET (200+body),
    404 otherwise. Does NOT verify SigV4 (the signer is exercised for real; the
    stub only needs the signed request to arrive)."""
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        store = self.store

        class H(_hs.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = store.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = _hs.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.t = _threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _s3_sink(port):
    return {"kind": "s3-objectlock", "endpoint": f"http://127.0.0.1:{port}",
            "bucket": "audit", "region": "us-east-1", "prefix": "p/"}


def test_s3_readback_confirms_present_object(tmp_path, monkeypatch):
    monkeypatch.setenv("DF_AUDIT_S3_ACCESS_KEY", "AKIATEST")
    monkeypatch.setenv("DF_AUDIT_S3_SECRET_KEY", "secretTEST")
    body = b'{"outcome":"SHIPPED"}'
    key = "run.ship.abc123"
    # the stub stores it at the canonical S3 path the signer will GET:
    with _StubS3({f"/audit/p/{key}": body}) as s3:
        sink = _s3_sink(s3.port)
        status, got = df_audit_sink.signed_s3_get(sink, key)
        assert status == 200 and got == body
        receipt = {"kind": "s3-objectlock", "sink_key": key,
                   "body_sha256": _hashlib.sha256(body).hexdigest(),
                   "server_issued": True}
        # positive readback → True (idempotently re-verifiable, not a re-push/brick)
        assert supervisor._sink_readback(sink, receipt, body.decode()) is True


def test_s3_readback_absent_object_rejects(tmp_path, monkeypatch):
    monkeypatch.setenv("DF_AUDIT_S3_ACCESS_KEY", "AKIATEST")
    monkeypatch.setenv("DF_AUDIT_S3_SECRET_KEY", "secretTEST")
    with _StubS3({}) as s3:  # object NOT present → 404
        sink = _s3_sink(s3.port)
        status, _ = df_audit_sink.signed_s3_get(sink, "run.ship.missing")
        assert status == 404
        receipt = {"kind": "s3-objectlock", "sink_key": "run.ship.missing",
                   "body_sha256": "0" * 64, "server_issued": True}
        assert supervisor._sink_readback(sink, receipt, "x") is False  # absent → reject


def test_s3_readback_unreachable_is_inconclusive(monkeypatch):
    monkeypatch.setenv("DF_AUDIT_S3_ACCESS_KEY", "AKIATEST")
    monkeypatch.setenv("DF_AUDIT_S3_SECRET_KEY", "secretTEST")
    sink = {"kind": "s3-objectlock", "endpoint": "http://127.0.0.1:1", "bucket": "b",
            "region": "us-east-1"}
    status, _ = df_audit_sink.signed_s3_get(sink, "k")
    assert status == 0  # unreachable → inconclusive, never a false rejection
    receipt = {"kind": "s3-objectlock", "sink_key": "k", "body_sha256": "0" * 64}
    assert supervisor._sink_readback(sink, receipt, "x") is None


def _shipped_run(tmp_path):
    cr = tmp_path / "control"
    action, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [action]}, signed=True),
        {"app.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    return cr, run_dir


def test_torn_trailing_journal_line_is_tolerated(tmp_path):
    cr, run_dir = _shipped_run(tmp_path)
    jp = run_dir / "ship_journal.jsonl"
    with open(jp, "a", encoding="utf-8") as f:
        f.write('{"ts":')  # a torn append (crash mid-write, no fsync)
    # Unit: _ship_journal_events drops the torn tail, does not raise.
    events = supervisor._ship_journal_events(str(run_dir))
    assert events and all(isinstance(e, dict) for e in events)
    # Integration: re-entry does not crash — the already-terminal SHIPPED is seen.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0


def test_corrupt_interior_journal_line_refuses(tmp_path, monkeypatch):
    # Use an unanchored-pending run so re-entry actually READS the ship journal
    # (an already-terminal SHIPPED short-circuits before the journal is consulted).
    cr, run_dir, _cfg, _rid, _oid, _counter = _make_unanchored_pending(tmp_path, monkeypatch)
    jp = run_dir / "ship_journal.jsonl"
    lines = jp.read_text().splitlines()
    assert len(lines) >= 2
    lines.insert(len(lines) - 1, "{ this is not json")  # corrupt a NON-trailing line
    jp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(_df_ship.ShipError):
        supervisor._ship_journal_events(str(run_dir))
    # Integration: a controlled fail-closed refusal (exit 2), NOT an uncaught crash.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 2
