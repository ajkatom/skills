"""M73 (Codex R9): DF-R9-04 — a same-user writer can tail-truncate the local
signed audit chain to a still-verifying prefix, erasing completion/rollback/
terminal/re-entry evidence, then re-ship a duplicate action. The fix commits each
new chain length to the off-box WORM/append-only sink under a MONOTONIC WRITE-ONCE
key; on re-entry the existence of a checkpoint one past the local length proves a
longer chain was committed off-box (the local chain was truncated).

These unit tests exercise the primitive against an in-memory fake sink (a real
WORM bucket is an operator live-exercise). A truncation-resistant sink is what
makes the chain-membership checks in M69/M70 trustworthy; without a sink, the
tier is documented detection-grade best-effort.
"""
import json

import df_audit
import df_audit_chain
import df_audit_sink
import supervisor
from test_ship import _base_config, build_sealed_run
from test_m49_ship_integrity import _counter_action


class _FakeSink:
    """A write-once (append-only) off-box sink: push refuses a duplicate key
    (like http-append 409 / an object-lock overwrite); probe reports existence."""
    def __init__(self):
        self.store = {}

    def push(self, sink_cfg, key, body, timeout_s=20):
        if key in self.store:
            raise df_audit_sink.SinkError(f"append-only duplicate: {key}")
        self.store[key] = body
        return {"kind": sink_cfg.get("kind"), "receipt": "r",
                "server_issued": True, "status": 200}

    def probe(self, sink_cfg, key, timeout_s=20):
        return (200, self.store[key]) if key in self.store else (404, None)


def _signed_chain(tmp_path, n):
    """A control root with a signed chain of n entries; returns (cr, cfg)."""
    cr = tmp_path / "control"
    cr.mkdir()
    keydir = tmp_path / "keys"
    keydir.mkdir()
    key_path = str(keydir / "audit.key")
    key = df_audit.load_or_create_key(key_path)
    chain_path = str(cr / "audit-chain.jsonl")
    for i in range(n):
        df_audit_chain.append_entry(chain_path, f"run.manifest.{i}", "d" * 64,
                                    f"2026-01-0{i+1}T00:00:00Z", key)
    cfg = {"_audit": {"signing": True, "key_path": key_path,
                      "sink": {"kind": "http-append", "url": "http://fake",
                               "required": False}}}
    return cr, cfg


def _use_fake_sink(monkeypatch):
    fake = _FakeSink()
    monkeypatch.setattr(df_audit_sink, "push", fake.push)
    monkeypatch.setattr(df_audit_sink, "probe", fake.probe)
    return fake


def test_checkpoint_then_untruncated_passes(tmp_path, monkeypatch):
    _use_fake_sink(monkeypatch)
    cr, cfg = _signed_chain(tmp_path, 3)
    supervisor._checkpoint_chain_to_sink(cfg, str(cr))
    ok, why = supervisor._verify_chain_untruncated(cfg, str(cr))
    assert ok, why


def test_tail_truncation_is_detected(tmp_path, monkeypatch):
    _use_fake_sink(monkeypatch)
    cr, cfg = _signed_chain(tmp_path, 3)
    supervisor._checkpoint_chain_to_sink(cfg, str(cr))  # commits length 3 off-box
    # attacker truncates the local chain to a still-verifying 2-entry prefix
    chain_path = cr / "audit-chain.jsonl"
    lines = chain_path.read_text().splitlines()
    chain_path.write_text("\n".join(lines[:2]) + "\n")
    key = df_audit.load_key(cfg["_audit"]["key_path"])
    assert df_audit_chain.verify_chain(str(chain_path), key)[0]  # prefix still verifies
    ok, why = supervisor._verify_chain_untruncated(cfg, str(cr))
    assert not ok and "tail-truncated" in why


def test_checkpoints_per_length_and_middle_truncation(tmp_path, monkeypatch):
    # Checkpoint at each length (as anchoring does), then truncate more than one
    # entry — the checkpoint at local_len+1 still exists off-box.
    _use_fake_sink(monkeypatch)
    cr, cfg = _signed_chain(tmp_path, 1)
    supervisor._checkpoint_chain_to_sink(cfg, str(cr))
    key = df_audit.load_key(cfg["_audit"]["key_path"])
    chain_path = cr / "audit-chain.jsonl"
    for i in range(1, 5):
        df_audit_chain.append_entry(str(chain_path), f"run.ship.{i}", "e" * 64,
                                    f"2026-02-0{i}T00:00:00Z", key)
        supervisor._checkpoint_chain_to_sink(cfg, str(cr))
    # truncate from 5 back to 2
    lines = chain_path.read_text().splitlines()
    chain_path.write_text("\n".join(lines[:2]) + "\n")
    ok, why = supervisor._verify_chain_untruncated(cfg, str(cr))
    assert not ok and "tail-truncated" in why


def test_no_sink_is_best_effort_pass(tmp_path, monkeypatch):
    _use_fake_sink(monkeypatch)
    cr, cfg = _signed_chain(tmp_path, 2)
    cfg["_audit"]["sink"] = {"kind": "none"}
    ok, why = supervisor._verify_chain_untruncated(cfg, str(cr))
    assert ok and "sink-less" in why


def test_required_sink_unreachable_fails_closed(tmp_path, monkeypatch):
    # probe inconclusive (0) on a REQUIRED sink → fail-closed.
    monkeypatch.setattr(df_audit_sink, "probe", lambda *a, **k: (0, None))
    cr, cfg = _signed_chain(tmp_path, 2)
    cfg["_audit"]["sink"]["required"] = True
    ok, why = supervisor._verify_chain_untruncated(cfg, str(cr))
    assert not ok and "REQUIRED" in why


def test_optional_sink_unreachable_is_best_effort_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(df_audit_sink, "probe", lambda *a, **k: (0, None))
    cr, cfg = _signed_chain(tmp_path, 2)
    ok, why = supervisor._verify_chain_untruncated(cfg, str(cr))
    # DF-R10-03: an OPTIONAL unreachable sink still proceeds (recovery best-effort);
    # the completeness STATE is 'unreachable' (not off-box confirmed), so it is the
    # production predicate — not this recovery gate — that withholds a prod verdict.
    assert ok and "unreachable" in why
    assert supervisor._chain_completeness(cfg, str(cr))[0] == "unreachable"


def test_r9_04_repro_tail_truncation_ship_refused(tmp_path, monkeypatch):
    # End-to-end: the exact R9-04 attack. A signed standard run with an off-box
    # sink ships a reversible action once (checkpointing each chain length), then a
    # same-user writer truncates the local chain to a still-verifying prefix and
    # deletes the ship_result + the action's journal lines. With the off-box
    # checkpoints in place, the re-ship must REFUSE (no duplicate action).
    _use_fake_sink(monkeypatch)
    action, counter = _counter_action(tmp_path, name="deploy", reversible=True)
    cr = tmp_path / "control"
    cfg_dict = _base_config(tmp_path, "standard", {"actions": [action]}, signed=True)
    cfg_dict["audit"]["sink"] = {"kind": "http-append", "url": "http://fake",
                                 "required": False}
    cfg, run_dir, _oid, rid = build_sealed_run(tmp_path, cr, cfg_dict, {"app.txt": "v1"})

    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert counter.read_text() == "x"  # ran once

    # Attacker truncates the chain at the first ship-action token and erases the
    # journal attribution + terminal.
    chain_path = cr / "audit-chain.jsonl"
    entries = [json.loads(l) for l in chain_path.read_text().splitlines()]
    cut = next(i for i, e in enumerate(entries)
               if str(e.get("invocation", "")).startswith(f"{rid}.ship-action"))
    chain_path.write_text(
        "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n"
                for e in entries[:cut]), encoding="utf-8")
    (run_dir / "ship_result.json").unlink()
    events = [json.loads(l) for l in (run_dir / "ship_journal.jsonl").read_text().splitlines()]
    kept = [e for e in events
            if e.get("state") not in ("SHIP_ACTION_INTENT", "SHIP_ACTION_RESULT")]
    (run_dir / "ship_journal.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in kept), encoding="utf-8")

    # The truncation is detected → recovery refuses → the action is NOT re-run.
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "tail-truncated" in why
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc != 0
    assert counter.read_text() == "x"  # NO duplicate action


def test_checkpoint_returns_false_when_push_fails_and_absent(tmp_path, monkeypatch):
    # Opus review F1: a checkpoint that can't be committed is reported False (a
    # site may act on it; kept best-effort at the current sites — see the docstring
    # residual note). Confirms the committed-bool is accurate.
    def _fail_push(*a, **k):
        raise df_audit_sink.SinkError("sink down")
    monkeypatch.setattr(df_audit_sink, "push", _fail_push)
    monkeypatch.setattr(df_audit_sink, "probe", lambda *a, **k: (0, None))  # absent/inconclusive
    cr, cfg = _signed_chain(tmp_path, 2)
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is False


def test_checkpoint_dup_409_counts_as_committed(tmp_path, monkeypatch):
    # A write-once duplicate (this length already committed) is SUCCESS, not a hole.
    fake = _use_fake_sink(monkeypatch)
    cr, cfg = _signed_chain(tmp_path, 2)
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True
    # push now raises (dup); probe still confirms present → True
    monkeypatch.setattr(df_audit_sink, "push",
                        lambda *a, **k: (_ for _ in ()).throw(df_audit_sink.SinkError("dup")))
    monkeypatch.setattr(df_audit_sink, "probe", fake.probe)
    assert supervisor._checkpoint_chain_to_sink(cfg, str(cr)) is True


def test_namespace_binds_control_root_no_cross_root_aliasing(tmp_path):
    # Opus review F2: two control roots that SHARE one signing key must get
    # DIFFERENT checkpoint namespaces, else one root's length reads as another's
    # truncation (false refusal) / a truncation reads as a shared length.
    keydir = tmp_path / "k"
    keydir.mkdir()
    key_path = str(keydir / "audit.key")
    df_audit.load_or_create_key(key_path)
    cfg = {"_audit": {"signing": True, "key_path": key_path,
                      "sink": {"kind": "http-append", "url": "u"}}}
    ns_a = supervisor._chain_sink_namespace(cfg, str(tmp_path / "rootA"))
    ns_b = supervisor._chain_sink_namespace(cfg, str(tmp_path / "rootB"))
    assert ns_a and ns_b and ns_a != ns_b
    # same root + same key is stable across calls
    assert ns_a == supervisor._chain_sink_namespace(cfg, str(tmp_path / "rootA"))


def test_checkpoint_key_is_monotonic_and_write_once(tmp_path, monkeypatch):
    fake = _use_fake_sink(monkeypatch)
    cr, cfg = _signed_chain(tmp_path, 2)
    supervisor._checkpoint_chain_to_sink(cfg, str(cr))
    supervisor._checkpoint_chain_to_sink(cfg, str(cr))  # duplicate length → 409, tolerated
    keys = [k for k in fake.store if k.startswith("dfchain.")]
    assert len(keys) == 1  # one checkpoint for length 2
    assert json.loads(fake.store[keys[0]])["length"] == 2
