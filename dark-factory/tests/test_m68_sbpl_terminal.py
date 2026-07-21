"""M68 (Codex R7): DF-R7-06 SBPL path escaping.

DF-R7-06 — macOS SBPL (sandbox-profile) rules embedded operator-controlled path
values into double-quoted string literals with no escaping, so a path containing
a quote or backslash could terminate the string early or create a misleading
rule (a malformed profile). One centralized encoder (`_sbpl_str`) now escapes
the parser-significant characters and rejects a NUL/newline.
"""
import pytest

import df_sandbox


def test_sbpl_str_escapes_quote_and_backslash():
    assert df_sandbox._sbpl_str("/a/b") == "/a/b"
    assert df_sandbox._sbpl_str('/weird"dir') == '/weird\\"dir'
    assert df_sandbox._sbpl_str("/back\\slash") == "/back\\\\slash"
    # parentheses are NOT special inside a quoted SBPL string — left intact.
    assert df_sandbox._sbpl_str("/a(b)c") == "/a(b)c"


def test_sbpl_str_rejects_nul_and_newline():
    for bad in ("/a\x00b", "/a\nb", "/a\rb"):
        with pytest.raises(ValueError):
            df_sandbox._sbpl_str(bad)


def test_a_quote_in_the_deny_root_produces_a_wellformed_profile(tmp_path, monkeypatch):
    # A deny_root whose realpath contains a double quote must yield a profile
    # where the quote is ESCAPED inside the (subpath "...") literal, not a
    # string terminated early.
    import sys
    if sys.platform != "darwin":
        pytest.skip("macOS SBPL profile")
    b = df_sandbox.BACKENDS["darwin"]
    weird = tmp_path / 'has"quote'
    weird.mkdir()
    prof = b.wrap_prefix(str(weird), str(tmp_path / "ws"))
    # the escaped form appears; a bare `has"quote"` (unescaped, terminating) must not
    text = " ".join(prof)
    assert 'has\\"quote' in text


# ---------------------------------------------------------------------------
# DF-R7-05 (R6-10): governed reseal of a NO-ACTION terminal (materialize-failure
# / reconcile-abort) — replaces manual record deletion; never launders a record
# with a completed action, and reconstructs from authenticated facts.
# ---------------------------------------------------------------------------

import json as _json
import supervisor
from test_ship import build_sealed_run, _base_config
from test_m49_ship_integrity import _counter_action


def _no_action_pending_terminal(tmp_path):
    """A signed run with an UNANCHORED no-action SHIP_FAILED (materialize-failure
    shape) + a SHIP_TERMINAL_ANCHOR_PENDING marker — the signer-outage state
    M56b left recoverable only by manual deletion."""
    cr = tmp_path / "control"
    deploy, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"app.txt": "v1"})
    rec = {"ship_version": "1", "outcome": "SHIP_FAILED", "actions": [],
           "rollbacks": [], "rollback_failed": False, "pending_action": None,
           "failed_action": None, "ship_workspace_object_id": oid,
           "ts": "2026-07-20T00:00:00Z"}
    text = supervisor.canonical_json(rec)
    (run_dir / "ship_result.json").write_text(text, encoding="utf-8")
    (run_dir / "ship_journal.jsonl").write_text(
        _json.dumps({"ts": "2026-07-20T00:00:01Z", "state": "SHIP_TERMINAL_ANCHOR_PENDING",
                     "data": {"outcome": "SHIP_FAILED",
                              "record_sha256": supervisor.sha256_str(text)}}) + "\n",
        encoding="utf-8")
    return cr, run_dir, cfg, rid, oid, counter


def test_no_action_terminal_continue_refuses_and_points_to_governed_recovery(tmp_path):
    cr, run_dir, cfg, rid, oid, counter = _no_action_pending_terminal(tmp_path)
    rc = supervisor.ship_cmd(str(cr), str(run_dir))  # plain continue
    assert rc == 2, "still fail-closed under plain continue (no silent re-anchor)"
    assert not counter.exists()


def test_no_action_terminal_reseals_under_operator_consent(tmp_path):
    cr, run_dir, cfg, rid, oid, counter = _no_action_pending_terminal(tmp_path)
    rc = supervisor.ship_cmd(str(cr), str(run_dir), decision="abort")
    assert rc == 3, f"governed reseal (no action ran), got {rc}"
    assert not counter.exists(), "NO action runs during an evidence-only reseal"
    # the resealed record is now anchored + stays SHIP_FAILED (never SHIPPED).
    final = _json.loads((run_dir / "ship_result.json").read_text())
    assert final["outcome"] == "SHIP_FAILED" and final["actions"] == []
    assert final["ship_workspace_object_id"] == oid  # from the authenticated manifest
    ok_c, _ = supervisor._authenticate_ship_chain(
        cfg, str(cr), rid, supervisor.sha256_str((run_dir / "ship_result.json").read_text()),
        "ship")
    assert ok_c, "the resealed no-action terminal is now anchored"
    states = [_json.loads(l)["state"]
              for l in (run_dir / "ship_journal.jsonl").read_text().strip().splitlines()]
    assert "SHIP_TERMINAL_CAUSE_RESEALED" in states


def test_a_record_claiming_a_completed_action_is_not_reseal_eligible(tmp_path):
    # ATTACK / guard: the no-action reseal must NEVER apply to a record that
    # claims (or journals) a completed `ok` action — that must go through the
    # full _failed_ship_record_bound check and be refused if unbacked.
    cr, run_dir, cfg, rid, oid, counter = _no_action_pending_terminal(tmp_path)
    # Tamper the record to CLAIM a completed action (a laundering attempt).
    rec = _json.loads((run_dir / "ship_result.json").read_text())
    rec["actions"] = [{"name": "deploy", "status": "ok", "reversible": True, "exit": 0}]
    (run_dir / "ship_result.json").write_text(supervisor.canonical_json(rec), encoding="utf-8")
    # marker no longer matches (sha changed) so terminal recovery won't even try;
    # but _is_no_action_terminal must independently be False.
    assert supervisor._is_no_action_terminal(str(run_dir), rid, rec) is False
    rc = supervisor.ship_cmd(str(cr), str(run_dir), decision="abort")
    assert rc == 2, "a record claiming a completed action must not be resealed"


def test_reseal_is_refused_when_a_completed_ok_token_exists(tmp_path):
    # Even with an empty record, if the JOURNAL shows a completed ok action the
    # terminal is NOT no-action → not reseal-eligible.
    cr, run_dir, cfg, rid, oid, counter = _no_action_pending_terminal(tmp_path)
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(_json.dumps({"ts": "2026-07-20T00:00:02Z", "state": "SHIP_ACTION_RESULT",
                             "data": {"action": "deploy", "attempt_id": "x", "status": "ok"}})
                + "\n")
    rec = _json.loads((run_dir / "ship_result.json").read_text())
    assert supervisor._is_no_action_terminal(str(run_dir), rid, rec) is False


def test_reseal_refused_when_a_signed_ship_token_exists_even_if_journal_emptied(tmp_path):
    # opus F1: the "no action" claim is re-rooted on the SIGNED CHAIN. If a
    # signature-valid per-action ship token exists (the run really shipped
    # something), the terminal is NOT no-action even if the writable journal was
    # emptied to hide it → not reseal-eligible.
    cr, run_dir, cfg, rid, oid, counter = _no_action_pending_terminal(tmp_path)
    # Anchor a GENUINE signed per-action ok token (as if deploy shipped).
    payload = supervisor._ship_action_commit_payload(
        rid, "deploy", "idk", None, True, None, attempt_id="a1")
    assert supervisor._anchor_ship_local(cfg, str(cr), rid, payload, "ship-action") == "anchored"
    # Journal shows no ok result (emptied) — but the chain token exists.
    rec = _json.loads((run_dir / "ship_result.json").read_text())
    assert supervisor._is_no_action_terminal(
        str(run_dir), rid, rec, cfg=cfg, control_root=str(cr)) is False
    rc = supervisor.ship_cmd(str(cr), str(run_dir), decision="abort")
    assert rc == 2, "a chain-proven ship must not be resealed as no-action"


def test_non_string_failed_action_is_clean_refusal_not_a_crash(tmp_path):
    # opus F2: a planted non-string failed_action must fail closed, never a
    # TypeError traceback.
    cr, run_dir, cfg, rid, oid, counter = _no_action_pending_terminal(tmp_path)
    ok, why = supervisor._failed_ship_record_bound(
        cfg, str(cr), str(run_dir), rid,
        {"outcome": "SHIP_FAILED", "actions": [], "failed_action": {"evil": 1},
         "ship_workspace_object_id": oid},
        artifact_object_id=oid)
    assert ok is False and "failed_action" in why


def test_reseal_never_copies_prior_failed_action_into_signed_bytes(tmp_path):
    # opus F4: the resealed record reconstructs failed_action:None from facts.
    cr, run_dir, cfg, rid, oid, counter = _no_action_pending_terminal(tmp_path)
    # Give the prior a poison failed_action string.
    rec = _json.loads((run_dir / "ship_result.json").read_text())
    rec["failed_action"] = "POISON-CAUSE"
    text = supervisor.canonical_json(rec)
    (run_dir / "ship_result.json").write_text(text, encoding="utf-8")
    (run_dir / "ship_journal.jsonl").write_text(
        _json.dumps({"ts": "t", "state": "SHIP_TERMINAL_ANCHOR_PENDING",
                     "data": {"outcome": "SHIP_FAILED",
                              "record_sha256": supervisor.sha256_str(text)}}) + "\n",
        encoding="utf-8")
    assert supervisor.ship_cmd(str(cr), str(run_dir), decision="abort") == 3
    final = _json.loads((run_dir / "ship_result.json").read_text())
    assert final["failed_action"] is None
    assert "POISON-CAUSE" not in (run_dir / "ship_result.json").read_text()
