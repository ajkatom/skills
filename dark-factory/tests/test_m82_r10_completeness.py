"""M82 (Codex R10): DF-R10-03 — a hardened-H4 (or enterprise) evidence bundle could
report production_ready with NO off-box chain-completeness proof.

Sink-less `_verify_chain_untruncated` returned (True, "...best-effort..."); the bundle
flattened that to `untruncated: true`; the production predicate checked only the
boolean. So a local valid PREFIX was labeled production-complete even though the code
itself says completeness is only best-effort — tail truncation could then erase
security anchors and enable duplicate/replayed production behavior.

Fix: completeness is now a tri(+)-state — `confirmed_offbox` / `unconfirmed` /
`truncated` / `unreachable` (supervisor._chain_completeness) — and BOTH production
profiles require `confirmed_offbox`. Recovery paths (`_verify_chain_untruncated`)
still proceed on sink-less `unconfirmed` (detection-grade best-effort), so a sink-less
signed run stays runnable; it simply cannot produce a production-ready bundle.
"""
import supervisor
import df_audit_sink
import df_evidence_bundle as EB
from test_m70_production_evidence import _full_bundle, _ready
from test_m73_chain_truncation import _FakeSink, _signed_chain


# --- the R10-03 repro, INVERTED into a fail-closed regression ---------------------

def _bundle_with_completeness(profile, state, msg="x"):
    def m(b, mf):
        b["audit_chain"] = {"verified": True, "untruncated": state != "truncated",
                            "completeness": state, "completeness_message": msg}
    return _ready(profile, m)


def test_sinkless_unconfirmed_is_not_production_ready_hardened():
    # THE R10-03 repro inverted: the real sink-less state is 'unconfirmed', which must
    # NOT read as production-complete on hardened-H4.
    ready, unmet = _bundle_with_completeness(
        "hardened-h4", "unconfirmed",
        "no off-box audit sink configured; local-chain completeness is "
        "detection-grade best-effort (sink-less tier)")
    assert not ready and any("NOT off-box confirmed" in u for u in unmet)


def test_sinkless_unconfirmed_is_not_production_ready_enterprise():
    ready, unmet = _bundle_with_completeness("enterprise", "unconfirmed")
    assert not ready and any("NOT off-box confirmed" in u for u in unmet)


def test_truncated_and_unreachable_are_not_production_ready():
    for profile in ("hardened-h4", "enterprise"):
        for state in ("truncated", "unreachable"):
            ready, unmet = _bundle_with_completeness(profile, state)
            assert not ready, (profile, state)
            assert any("NOT off-box confirmed" in u for u in unmet)


def test_confirmed_offbox_is_production_ready():
    # Positive: only genuine off-box confirmation reads production-complete.
    for profile in ("hardened-h4", "enterprise"):
        ready, unmet = _bundle_with_completeness(profile, "confirmed_offbox")
        assert ready, (profile, unmet)


def test_missing_completeness_field_fails_closed():
    # A bundle with no completeness state at all (legacy/forged) is not ready.
    ready, unmet = _ready("hardened-h4", lambda b, mf: b.update(
        {"audit_chain": {"verified": True, "untruncated": True}}))
    assert not ready and any("NOT off-box confirmed" in u for u in unmet)


# --- the state machine itself -----------------------------------------------------

def test_chain_completeness_states(tmp_path, monkeypatch):
    fake = _FakeSink()
    monkeypatch.setattr(df_audit_sink, "push", fake.push)
    monkeypatch.setattr(df_audit_sink, "probe", fake.probe)
    cr, cfg = _signed_chain(tmp_path, 3)
    cfg["_audit"]["sink"]["required"] = True

    # no sink configured -> unconfirmed (best-effort), and recovery still proceeds
    nosink = {"_audit": {"signing": True, "key_path": cfg["_audit"]["key_path"],
                         "sink": {"kind": "none"}}}
    assert supervisor._chain_completeness(nosink, str(cr))[0] == "unconfirmed"
    assert supervisor._verify_chain_untruncated(nosink, str(cr))[0] is True

    # sink committed to length 3, local length 3 -> confirmed_offbox
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True
    assert supervisor._chain_completeness(cfg, str(cr))[0] == "confirmed_offbox"
    assert supervisor._verify_chain_untruncated(cfg, str(cr))[0] is True

    # truncate local to 2 -> the length-3 checkpoint makes it 'truncated' (fail closed)
    chain = cr / "audit-chain.jsonl"
    chain.write_text("\n".join(chain.read_text().splitlines()[:2]) + "\n")
    assert supervisor._chain_completeness(cfg, str(cr))[0] == "truncated"
    assert supervisor._verify_chain_untruncated(cfg, str(cr))[0] is False


def test_required_sink_unreachable_is_unconfirmed_and_recovery_fails_closed(tmp_path, monkeypatch):
    # An unreachable REQUIRED sink → state 'unreachable' → NOT production-ready AND
    # recovery fails closed (the required-sink invariant is preserved).
    cr, cfg = _signed_chain(tmp_path, 2)
    cfg["_audit"]["sink"]["required"] = True
    monkeypatch.setattr(df_audit_sink, "probe", lambda *a, **k: (0, None))  # unreachable
    assert supervisor._chain_completeness(cfg, str(cr))[0] == "unreachable"
    assert supervisor._verify_chain_untruncated(cfg, str(cr))[0] is False
