"""M76 (Codex R9): DF-R9-03 — the source identity is chain-anchored, so deleting or
replacing the same-user-writable journal SOURCE_IDENTITY event no longer downgrades
resume to the legacy (no-enforcement) path.

M71 recovered the run's ORIGINAL source identity from the ordinary journal
SOURCE_IDENTITY event ALONE. That event is same-user writable, so DELETING it made
the resume drift check no-op and RESUME PROCEEDED under a drifted identity — one
logical run could then seal a NEWER source identity than it started under.

Fix:
  * SIGNED tiers — the identity is ANCHORED into the signed audit chain at first
    dispatch. Resume AUTHENTICATES the recovered journal event against the anchor:
    a deleted/replaced event (or a broken/truncated chain) fails closed, EVEN IF
    source_identity.json is also deleted (the chain is the trust root).
  * Tier-independent fallback — source_identity.json (written for every run) is
    cross-checked against the journal event, so the deletion is caught on UNSIGNED
    tiers too (best-effort: a thorough attacker who deletes BOTH files on an
    unsigned, non-detection-grade tier is undetectable, which that tier accepts).
"""
import json
import os

import supervisor
from test_supervisor import FAKE, setup_control


def _states(run_dir):
    return [json.loads(l)["state"]
            for l in (run_dir / "journal.jsonl").read_text().splitlines()]


def _rundir(cr):
    return cr / "runs" / os.listdir(cr / "runs")[0]


def _drift(monkeypatch):
    monkeypatch.setattr(supervisor, "_source_identity_field",
                        lambda: {"commit": "drifted", "clean": True,
                                 "dirty": False, "tree_digest": "f" * 64})


def _delete_event(run_dir):
    jp = run_dir / "journal.jsonl"
    keep = [l for l in jp.read_text().splitlines()
            if json.loads(l).get("state") != "SOURCE_IDENTITY"]
    jp.write_text("\n".join(keep) + "\n")


def _replace_event(run_dir):
    jp = run_dir / "journal.jsonl"
    out = []
    for l in jp.read_text().splitlines():
        e = json.loads(l)
        if e.get("state") == "SOURCE_IDENTITY":
            e["data"] = {"commit": "drifted", "clean": True,
                         "dirty": False, "tree_digest": "f" * 64}
        out.append(json.dumps(e))
    jp.write_text("\n".join(out) + "\n")


def _signed_run(tmp_path, checkpoint="pause"):
    # A SIGNED run (audit.signing on) — the tier is independent of signing; the
    # cooperative tier + signing exercises the chain-anchored source identity
    # without needing a stubbed isolation backend. The key MUST live outside both
    # the control root and workspace_root (df_config disjointness guard).
    cr = setup_control(tmp_path, FAKE, checkpoint=checkpoint)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["audit"] = {"signing": True, "key_path": str(tmp_path / "keys" / "audit.key")}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cr


# --- UNSIGNED (cooperative) tier: the file cross-check catches the deletion (the
#     R9-03 reproduction was run on the cooperative tier) --------------------------

def test_cooperative_deleted_event_refused(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _delete_event(rd)
    _drift(monkeypatch)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _states(rd)


def test_cooperative_replaced_event_refused(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _replace_event(rd)
    _drift(monkeypatch)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _states(rd)


# --- SIGNED (standard) tier: the chain anchor is the robust guarantee ------------

def test_signed_chain_anchor_created_at_first_dispatch(tmp_path, monkeypatch):
    import df_audit_chain
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rid = os.path.basename(str(rd))
    entries = df_audit_chain.read_chain(str(cr / "audit-chain.jsonl"))
    assert any(str(e.get("invocation", "")).startswith(f"{rid}.source-identity.")
               for e in entries)


def test_signed_deleted_event_refused_via_chain(tmp_path, monkeypatch):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _delete_event(rd)
    _drift(monkeypatch)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _states(rd)


def test_signed_deleted_event_and_file_still_refused(tmp_path, monkeypatch):
    # The key robustness improvement over the unsigned fallback: deleting BOTH the
    # journal event AND source_identity.json (defeating the file cross-check) STILL
    # fails closed on a signed run — the chain anchor cannot be forged or removed
    # without breaking verify_chain.
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    _delete_event(rd)
    (rd / supervisor.SOURCE_IDENTITY_FILE).unlink()
    _drift(monkeypatch)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _states(rd)


def test_signed_deleted_whole_chain_still_refused(tmp_path, monkeypatch):
    # Opus review of M76: verify_chain accepts a 0-entry chain as valid, so deleting
    # the ENTIRE audit-chain.jsonl (not just truncating) erases the source anchor
    # while the empty chain still "verifies". A signed run that DISPATCHED must have
    # anchored its source identity, so the missing anchor + surviving dispatch
    # evidence (source_identity.json / SNAPSHOT) is caught: fail closed.
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    (cr / "audit-chain.jsonl").unlink()
    _delete_event(rd)
    _drift(monkeypatch)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _states(rd)


def test_signed_deleted_chain_and_both_source_files_still_refused(tmp_path, monkeypatch):
    # The full opus reproduction: sink-less signed run, attacker deletes the whole
    # audit-chain.jsonl AND the journal SOURCE_IDENTITY event AND source_identity.json.
    # The journal's SNAPSHOT event still proves the run dispatched, so the missing
    # anchor is caught: fail closed (no silent downgrade under a drifted source).
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    (cr / "audit-chain.jsonl").unlink()
    _delete_event(rd)
    (rd / supervisor.SOURCE_IDENTITY_FILE).unlink()
    _drift(monkeypatch)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _states(rd)


def test_signed_stripped_all_dispatch_evidence_still_refused(tmp_path, monkeypatch):
    # Opus re-review variant A: the attacker deletes the whole audit-chain.jsonl AND
    # source_identity.json AND strips the SNAPSHOT + SOURCE_IDENTITY journal lines
    # (leaving DISPATCH_INTENT / BUILD / VERIFY / CHECKPOINT so the run still visibly
    # dispatched and resumes). A journal-evidence backstop would miss this. Because a
    # signed run FAILS CLOSED at first dispatch if it cannot anchor (so every paused
    # signed run HAS the anchor), an empty anchor set on resume is unconditionally
    # tampering — caught off the chain, not off strippable journal lines.
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    (cr / "audit-chain.jsonl").unlink()
    (rd / supervisor.SOURCE_IDENTITY_FILE).unlink()
    jp = rd / "journal.jsonl"
    keep = [l for l in jp.read_text().splitlines()
            if json.loads(l).get("state") not in ("SNAPSHOT", "SOURCE_IDENTITY")]
    jp.write_text("\n".join(keep) + "\n")
    _drift(monkeypatch)
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _states(rd)


def test_signed_anchor_failure_halts_at_first_dispatch(tmp_path, monkeypatch):
    # Opus re-review variant B: if the source anchor cannot be committed at first
    # dispatch, the run must FAIL CLOSED THERE (not proceed to a paused state a later
    # resume cannot tell apart from a deleted-anchor tamper). This both removes the
    # ambiguity and gives an accurate, benign "could not anchor — fix the key"
    # message instead of a misleading resume-time "tampered".
    cr = _signed_run(tmp_path)
    real = supervisor._anchor_ship_local

    def _fail_source_anchor(cfg, control_root, run_id, record_text, kind):
        if kind == "source-identity":
            return "anchor_failed"
        return real(cfg, control_root, run_id, record_text, kind)

    monkeypatch.setattr(supervisor, "_anchor_ship_local", _fail_source_anchor)
    assert supervisor.run(str(cr), None) == 2
    rd = _rundir(cr)
    assert "SOURCE_ANCHOR_FAILED" in _states(rd)


def test_signed_helper_authenticates_then_tampered(tmp_path, monkeypatch):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    cfg = supervisor.load_config(str(cr))
    cfg["_control_root"] = str(cr)
    rid = os.path.basename(str(rd))
    status, si = supervisor._authenticated_source_identity(cfg, str(cr), str(rd), rid)
    assert status == "authenticated" and si.get("tree_digest")
    _delete_event(rd)
    status2, _si2 = supervisor._authenticated_source_identity(cfg, str(cr), str(rd), rid)
    assert status2 == "tampered"


# --- no false positives ---------------------------------------------------------

def test_legit_signed_resume_not_refused(tmp_path, monkeypatch):
    cr = _signed_run(tmp_path)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rc = supervisor.resume(str(cr), "continue")
    assert rc != 2
    assert "SOURCE_DRIFT_REFUSED" not in _states(rd)


def test_legit_cooperative_resume_not_refused(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    rd = _rundir(cr)
    rc = supervisor.resume(str(cr), "continue")
    assert rc != 2
    assert "SOURCE_DRIFT_REFUSED" not in _states(rd)
