"""M84 (Codex R10): DF-R10-04 — an ignored checkpoint failure created a permanent
truncation-detection HOLE.

`_checkpoint_chain_to_sink` accurately returned False when a checkpoint could not be
committed, but production callers ignored it and continued. A transient drop at
length h left `dfchain.<ns>.h` absent; a later truncation to h-1 then passed the
one-past `local+1` probe (it landed on the missing key → 404 → "complete") even with
a required, reachable sink holding a length-(h+1) checkpoint. The same density gap hit
a pre-sink / pre-M73 chain that later adopts a sink.

Fix: checkpoints are kept DENSE by BACKFILLING every missing length up to the current
one on each write, maintaining the invariant "dfchain.<ns>.L committed ⇒ 1..L all
committed" — so a transient hole self-heals on the next checkpoint (the run holds the
lock, so it heals before any between-runs attacker can act), a fresh-sink/migration
chain gets a dense baseline on its first checkpoint, and the one-past probe stays
sufficient.
"""
import supervisor
import df_audit_sink
import df_audit
import df_audit_chain
from test_m73_chain_truncation import _FakeSink, _signed_chain


def test_transient_checkpoint_hole_self_heals_and_truncation_is_caught(tmp_path, monkeypatch):
    # THE R10-04 repro, inverted. Commit length 1; a transient failure drops the
    # length-2 checkpoint; length 3 then BACKFILLS 2 → dense. A later truncation to 1
    # is caught (the length-2 checkpoint the backfill committed makes the one-past
    # probe land on a 200), even though the original length-2 write had failed.
    fake = _FakeSink()
    monkeypatch.setattr(df_audit_sink, "probe", fake.probe)
    cr, cfg = _signed_chain(tmp_path, 1)
    cfg["_audit"]["sink"]["required"] = True

    monkeypatch.setattr(df_audit_sink, "push", fake.push)
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True  # length 1 committed
    ns = supervisor._chain_sink_namespace(cfg, str(cr))

    k = df_audit.load_key(cfg["_audit"]["key_path"])
    chain = cr / "audit-chain.jsonl"
    df_audit_chain.append_entry(str(chain), "run.ship.2", "e" * 64, "2026-02-02T00:00:00Z", k)
    hole_key = supervisor._chain_checkpoint_key(ns, 2)

    def fail_only_len_two(sink_cfg, object_key, body, timeout_s=20):
        if object_key == hole_key:
            raise df_audit_sink.SinkError("one transient checkpoint failure")
        return fake.push(sink_cfg, object_key, body, timeout_s)

    monkeypatch.setattr(df_audit_sink, "push", fail_only_len_two)
    # the length-2 checkpoint transiently fails → False, and (required) leaves no
    # dense commitment: the hole at 2 must NOT be silently accepted.
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is False
    assert hole_key not in fake.store  # the hole really is absent

    # sink recovers; append length 3 and checkpoint → BACKFILLS the length-2 hole.
    monkeypatch.setattr(df_audit_sink, "push", fake.push)
    df_audit_chain.append_entry(str(chain), "run.ship.3", "f" * 64, "2026-02-03T00:00:00Z", k)
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True
    assert hole_key in fake.store  # the hole was backfilled — checkpoints are dense

    # a later attacker truncates to length 1; the one-past probe lands on the now-
    # present length-2 checkpoint → truncation is CAUGHT (was the R10-04 bypass).
    chain.write_text(chain.read_text().splitlines()[0] + "\n")
    ok, why = supervisor._verify_chain_untruncated(cfg, str(cr))
    assert not ok and "truncat" in why.lower()


def test_migration_first_checkpoint_backfills_dense_baseline(tmp_path, monkeypatch):
    # A chain that grew to length 3 with NO checkpoints (pre-sink / pre-M73) then
    # adopts a sink: the first checkpoint must backfill 1..3 (a dense baseline), so a
    # later truncation to 1 or 2 is caught rather than passing on a missing key.
    fake = _FakeSink()
    monkeypatch.setattr(df_audit_sink, "push", fake.push)
    monkeypatch.setattr(df_audit_sink, "probe", fake.probe)
    cr, cfg = _signed_chain(tmp_path, 3)  # 3 entries, no checkpoints yet
    cfg["_audit"]["sink"]["required"] = True
    ns = supervisor._chain_sink_namespace(cfg, str(cr))
    assert not any(k.startswith(f"dfchain.{ns}.") for k in fake.store)  # none yet

    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True
    for n in (1, 2, 3):
        assert supervisor._chain_checkpoint_key(ns, n) in fake.store  # dense 1..3

    chain = cr / "audit-chain.jsonl"
    chain.write_text("\n".join(chain.read_text().splitlines()[:1]) + "\n")  # truncate to 1
    ok, why = supervisor._verify_chain_untruncated(cfg, str(cr))
    assert not ok and "truncat" in why.lower()


def test_unreachable_sink_does_not_trigger_unbounded_scan(tmp_path, monkeypatch):
    # Independent-audit regression: an unreachable sink (mid-invocation, after the
    # identity was cached-confirmed) must NOT make backfill probe EVERY length
    # (O(L)×timeout hang). The scan aborts on the first unreachable probe.
    cr, cfg = _signed_chain(tmp_path, 50)
    fake = _FakeSink()
    monkeypatch.setattr(df_audit_sink, "push", fake.push)
    monkeypatch.setattr(df_audit_sink, "probe", fake.probe)
    supervisor._control_root_identity(cfg, str(cr), allow_bootstrap=True)  # confirm + cache

    probes = []

    def down_probe(sink_cfg, key, timeout_s=20):
        probes.append(key)
        return (0, None)  # unreachable

    def down_push(*a, **k):
        raise df_audit_sink.SinkError("down")

    monkeypatch.setattr(df_audit_sink, "probe", down_probe)
    monkeypatch.setattr(df_audit_sink, "push", down_push)
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is False
    assert len(probes) <= 2  # bounded (probe L → status 0 → abort), NOT ~50


def test_dense_steady_state_is_cheap(tmp_path, monkeypatch):
    # The common path: when a length is already committed the call returns True with a
    # single probe and no backfill scan (the dense invariant holds).
    fake = _FakeSink()
    probes = []
    real_probe = fake.probe

    def counting_probe(sink_cfg, key, timeout_s=20):
        probes.append(key)
        return real_probe(sink_cfg, key, timeout_s)

    monkeypatch.setattr(df_audit_sink, "push", fake.push)
    monkeypatch.setattr(df_audit_sink, "probe", counting_probe)
    cr, cfg = _signed_chain(tmp_path, 2)
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True  # dense 1..2
    probes.clear()
    # re-checkpoint the same length: the DENSE-BASELINE marker for L already exists
    # (DF-R12-01) → one probe of that marker, no checkpoint writes / no backfill scan.
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True
    ns = supervisor._chain_sink_namespace(cfg, str(cr))
    assert probes == [supervisor._chain_dense_marker_key(ns, 2)]
