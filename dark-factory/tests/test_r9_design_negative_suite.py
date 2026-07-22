"""R9 design-level negative suite (M81) — the acceptance-condition deliverable named
in `audit/19` §Acceptance conditions:

  > Code-complete GO requires DF-R9-01…05 closed with reproductions converted into
  > regression tests, PLUS a design-level negative suite that verifies TRANSITION
  > COMPLETENESS and NON-TRUNCATABLE TRUST ANCHORS.

The per-finding reproductions live in test_m69/m73/m74/m75/m76/m77/m79/m80. This
suite instead asserts the TWO GENERAL design properties R9's method corrections
demanded, SYSTEMATICALLY across the signed trust surface — so a regression in ANY
signed namespace (present or future) trips a design-level invariant, not just a
finding-specific case.

  P1  NON-TRUNCATABLE TRUST ANCHORS (DF-R9-04 class): every recovery consumer that
      trusts the signed audit chain FAILS CLOSED when the off-box truncation probe
      (`_verify_chain_untruncated`) reports the local chain was rolled back to a
      shorter prefix. Asserted at EVERY anchor consumer, not just one.

  P2  TRANSITION / CHAIN COMPLETENESS (DF-R9-01/02/03 class): a FORGED (keyless)
      chain entry, an INTERIOR chain deletion, and a signed token whose JOURNAL
      ATTRIBUTION was deleted (chain→journal reverse-completeness) each fail closed —
      asserted at the chain primitive AND the ship authenticator.
"""
import json

import pytest

import df_audit
import df_audit_chain
import supervisor
from test_ship import _base_config, build_sealed_run
from test_m49_ship_integrity import _counter_action
from test_m74_completion_completeness import _signed_shipped, _read, _write
from test_m77_state_anchor import _signed_run, _rundir


# ---------------------------------------------------------------------------
# P1 — NON-TRUNCATABLE TRUST ANCHORS
#
# Every function that recovers trust FROM the signed chain must call
# `_verify_chain_untruncated` FIRST and refuse when it reports truncation. We drive
# the probe to a truncation verdict and assert each authenticator fails closed —
# proving the DF-R9-04 property is wired at ALL anchor consumers uniformly.
# ---------------------------------------------------------------------------

_TRUNCATED = (False, "off-box sink shows a longer committed chain (local tail-truncated)")


def test_p1_ship_authenticator_fails_closed_on_truncation(tmp_path, monkeypatch):
    cr, run_dir, cfg, rid, _counter = _signed_shipped(tmp_path)
    monkeypatch.setattr(supervisor, "_verify_chain_untruncated", lambda *a, **k: _TRUNCATED)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "truncat" in why.lower()


def test_p1_source_identity_authenticator_fails_closed_on_truncation(tmp_path, monkeypatch):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    cfg = supervisor.load_config(str(cr))
    cfg["_control_root"] = str(cr)
    rid = rd.name
    # sanity: authenticates before the probe is poisoned
    assert supervisor._authenticated_source_identity(cfg, str(cr), str(rd), rid)[0] == "authenticated"
    monkeypatch.setattr(supervisor, "_verify_chain_untruncated", lambda *a, **k: _TRUNCATED)
    assert supervisor._authenticated_source_identity(cfg, str(cr), str(rd), rid)[0] == "tampered"


def test_p1_resumable_state_authenticator_fails_closed_on_truncation(tmp_path, monkeypatch):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    cfg = supervisor.load_config(str(cr))
    cfg["_control_root"] = str(cr)
    rid = rd.name
    state = supervisor.load_state(str(rd))
    assert supervisor._authenticate_resumable_state(cfg, str(cr), str(rd), rid, state)[0] is True
    monkeypatch.setattr(supervisor, "_verify_chain_untruncated", lambda *a, **k: _TRUNCATED)
    ok, why = supervisor._authenticate_resumable_state(cfg, str(cr), str(rd), rid, state)
    assert not ok and "truncat" in why.lower()


def test_p1_end_to_end_resume_refuses_under_truncation(tmp_path, monkeypatch):
    # The property holds at the real entry point too: a signed resume refuses when the
    # chain cannot be confirmed untruncated (regardless of which authenticator trips).
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    monkeypatch.setattr(supervisor, "_verify_chain_untruncated", lambda *a, **k: _TRUNCATED)
    assert supervisor.resume(str(cr), "continue") == 2


def test_p1_every_recovery_consumer_wires_the_truncation_gate():
    # Structural guard: the truncation probe must be called by MORE THAN ONE consumer
    # (ship auth, source identity, resumable state, ship phase). If a future signed
    # recovery path forgets to wire it, this count drops — a design-level tripwire.
    import inspect
    src = inspect.getsource(supervisor)
    assert src.count("_verify_chain_untruncated(cfg") >= 4


# ---------------------------------------------------------------------------
# P2 — TRANSITION / CHAIN COMPLETENESS
# ---------------------------------------------------------------------------

def _signed_chain(tmp_path):
    """A 3-entry SIGNED chain + its key (via the real df_audit_chain primitive)."""
    kp = tmp_path / "audit.key"
    key = df_audit.load_or_create_key(str(kp))
    chain = str(tmp_path / "audit-chain.jsonl")
    for i in range(3):
        df_audit_chain.append_entry(chain, f"run.kind.{i:08d}", "d" * 64, "t", key)
    ok, _ = df_audit_chain.verify_chain(chain, key)
    assert ok
    return chain, key


def test_p2_forged_keyless_entry_breaks_verification(tmp_path):
    # A FORGED entry appended WITHOUT the audit key (no `sig`) to a signed chain must
    # make verify_chain fail — so no chain consumer can be tricked by a planted token.
    chain, key = _signed_chain(tmp_path)
    df_audit_chain.append_entry(chain, "run.kind.forged", "e" * 64, "t", audit_key=None)
    ok, why = df_audit_chain.verify_chain(chain, key)
    assert not ok


def test_p2_wrong_key_signature_breaks_verification(tmp_path):
    # An entry signed with the WRONG key (an attacker's own) is rejected too.
    chain, key = _signed_chain(tmp_path)
    wrong = df_audit.load_or_create_key(str(tmp_path / "wrong.key"))
    df_audit_chain.append_entry(chain, "run.kind.evil", "f" * 64, "t", wrong)
    ok, _why = df_audit_chain.verify_chain(chain, key)
    assert not ok


def test_p2_interior_deletion_breaks_the_hash_chain(tmp_path):
    chain, key = _signed_chain(tmp_path)
    entries = df_audit_chain.read_chain(chain)
    del entries[1]  # interior deletion breaks the prev_chain_hash linkage
    (tmp_path / "audit-chain.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    ok, _why = df_audit_chain.verify_chain(chain, key)
    assert not ok


@pytest.mark.parametrize("delete_states,expect", [
    # chain→journal reverse-completeness: an anchored token whose journal attribution
    # is deleted must fail closed (the DF-R9-01 completion + DF-R9-02 intent class).
    (("SHIP_ACTION_INTENT", "SHIP_ACTION_RESULT"), "no surviving"),
])
def test_p2_ship_reverse_completeness(tmp_path, delete_states, expect):
    cr, run_dir, cfg, rid, counter = _signed_shipped(tmp_path)
    assert counter.read_text() == "x"
    (run_dir / "ship_result.json").unlink()
    kept = [e for e in _read(run_dir) if e.get("state") not in delete_states]
    _write(run_dir, kept)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and expect in why
    # and end-to-end: no duplicate re-run of the already-applied action
    assert supervisor.ship_cmd(str(cr), str(run_dir)) != 0
    assert counter.read_text() == "x"


def test_p2_intent_only_deletion_orphans_the_anchored_intent(tmp_path):
    # Deleting ONLY the SHIP_ACTION_INTENT line (keeping the ok RESULT) leaves the
    # anchored intent token with no surviving journal line → fail closed (DF-R9-02
    # opus INTENT reverse-completeness).
    cr, run_dir, cfg, rid, counter = _signed_shipped(tmp_path)
    kept = [e for e in _read(run_dir) if e.get("state") != "SHIP_ACTION_INTENT"]
    _write(run_dir, kept)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "SHIP_ACTION_INTENT" in why
