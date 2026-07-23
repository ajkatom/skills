"""M89 (DF-R12-01): the off-box checkpoint density guarantee had two truncation
bypasses, and required-sink callers discarded the fail-closed checkpoint result.

1. Immediate hole: a required-sink checkpoint that transiently failed left a hole
   before the next backfill; callers ignored the False return, so the run looked
   clean and a same-user truncation to the hole passed completeness.
2. Legacy shortcut: `_checkpoint_chain_to_sink` trusted "checkpoint L exists ⇒
   1..L dense", but a pre-M84 store could hold L above a missing earlier checkpoint.

Fix:
- a WRITE-ONCE dense-baseline marker `dfchain.<ns>.dense.<L>` is written ONLY after
  1..L are confirmed committed; `_chain_completeness` requires THAT marker (not the
  bare tip checkpoint) for `confirmed_offbox`;
- the legacy shortcut is replaced by verify+backfill of every 1..L on a store that
  lacks a contiguous dense baseline;
- required-sink callers fail closed on a False checkpoint (`_anchor_audit` returns 3).

'Why it was missed' (per the audit): the M84 tests advanced to length 3 before
attacking and assumed the control-root lock healed the hole before an attacker
could act; they never seeded a pre-M84 tip-over-a-missing-middle store.
"""
import json
import os

import df_audit
import df_audit_sink
import supervisor
from test_m73_chain_truncation import _FakeSink, _signed_chain


def _use_sink(monkeypatch, fake):
    monkeypatch.setattr(df_audit_sink, "push", fake.push)
    monkeypatch.setattr(df_audit_sink, "probe", fake.probe)


def test_legacy_present_tip_over_missing_middle_is_backfilled_then_truncation_caught(
        tmp_path, monkeypatch):
    # Inverts r12 repro #2: a legacy store with checkpoint 3 present but 2 absent.
    fake = _FakeSink()
    _use_sink(monkeypatch, fake)
    cr, cfg = _signed_chain(tmp_path, 3)
    cfg["_audit"]["sink"]["required"] = True
    supervisor._control_root_identity(cfg, str(cr), allow_bootstrap=True)
    ns = supervisor._chain_sink_namespace(cfg, str(cr))
    fake.store[supervisor._chain_checkpoint_key(ns, 3)] = b'{"length":3}'  # 2 absent

    # The dense-baseline fix must NOT trust the bare tip — it backfills the missing 2.
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True
    assert supervisor._chain_checkpoint_key(ns, 2) in fake.store  # hole backfilled
    assert supervisor._chain_dense_marker_key(ns, 3) in fake.store  # baseline recorded

    # Now truncation to length 1 lands on the (now-present) checkpoint 2 → detected.
    chain_path = cr / "audit-chain.jsonl"
    chain_path.write_text(chain_path.read_text().splitlines()[0] + "\n")
    state, why = supervisor._chain_completeness(cfg, str(cr))
    assert state == "truncated", why
    assert supervisor._verify_chain_untruncated(cfg, str(cr))[0] is False


def test_tip_without_dense_marker_is_not_confirmed(tmp_path, monkeypatch):
    # A legacy store whose checkpoints exist but were never dense-marked must NOT read
    # confirmed_offbox — the marker is the proof of density.
    fake = _FakeSink()
    _use_sink(monkeypatch, fake)
    cr, cfg = _signed_chain(tmp_path, 2)
    cfg["_audit"]["sink"]["required"] = True
    supervisor._control_root_identity(cfg, str(cr), allow_bootstrap=True)
    ns = supervisor._chain_sink_namespace(cfg, str(cr))
    # Seed checkpoints 1..2 but NO dense marker (pre-M89 store).
    fake.store[supervisor._chain_checkpoint_key(ns, 1)] = b'{"length":1}'
    fake.store[supervisor._chain_checkpoint_key(ns, 2)] = b'{"length":2}'

    state, why = supervisor._chain_completeness(cfg, str(cr))
    assert state == "unconfirmed", why  # no dense marker → not off-box confirmed

    # After a real checkpoint establishes the baseline, it confirms.
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True
    state, why = supervisor._chain_completeness(cfg, str(cr))
    assert state == "confirmed_offbox", why


def test_required_sink_checkpoint_failure_fails_closed_in_anchor_audit(tmp_path, monkeypatch):
    # Inverts r12 repro #1 at the CALLER: a required-sink checkpoint that cannot land
    # must NOT return a clean anchor (0). `_anchor_audit` returns 3 (fail-closed), so a
    # run whose tip length is uncheckpointed is a pending terminal, not a false clean one.
    fake = _FakeSink()
    _use_sink(monkeypatch, fake)
    cr, cfg = _signed_chain(tmp_path, 1)
    cfg["_audit"]["sink"]["required"] = True
    # Establish identity + dense baseline with the sink healthy.
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True

    # Now fail EVERY checkpoint/dense push (the tip cannot be committed) but let the
    # ordinary invocation-record push through — the selective-checkpoint-drop case.
    healthy_push = fake.push

    def push_but_drop_checkpoints(sink_cfg, key, body, timeout_s=20):
        if key.startswith("dfchain.") and ".dense." not in key or ".dense." in key:
            raise df_audit_sink.SinkError("checkpoint drop")
        return healthy_push(sink_cfg, key, body, timeout_s)
    monkeypatch.setattr(df_audit_sink, "push", push_but_drop_checkpoints)

    run_dir = cr / "runs" / "r1"
    run_dir.mkdir(parents=True)
    key = df_audit.load_key(cfg["_audit"]["key_path"])

    class _J:
        redactor = None

    rc = supervisor._anchor_audit(cfg, str(cr), str(run_dir), "inv-xyz",
                                  "d" * 64, key, _J())
    assert rc == 3  # fail-closed, not a clean 0
    events = (run_dir / "audit_events.jsonl").read_text()
    assert "AUDIT_CHECKPOINT_FAILED" in events


def test_optional_sink_checkpoint_failure_is_not_fatal(tmp_path, monkeypatch):
    # An OPTIONAL sink stays best-effort: a checkpoint miss must not brick the anchor.
    fake = _FakeSink()
    _use_sink(monkeypatch, fake)
    cr, cfg = _signed_chain(tmp_path, 1)
    cfg["_audit"]["sink"]["required"] = False
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True

    healthy_push = fake.push

    def drop_checkpoints(sink_cfg, key, body, timeout_s=20):
        if key.startswith("dfchain."):
            raise df_audit_sink.SinkError("checkpoint drop")
        return healthy_push(sink_cfg, key, body, timeout_s)
    monkeypatch.setattr(df_audit_sink, "push", drop_checkpoints)

    run_dir = cr / "runs" / "r1"
    run_dir.mkdir(parents=True)
    key = df_audit.load_key(cfg["_audit"]["key_path"])

    class _J:
        redactor = None

    rc = supervisor._anchor_audit(cfg, str(cr), str(run_dir), "inv-abc",
                                  "e" * 64, key, _J())
    assert rc == 0  # optional sink → best-effort, anchor still clean
