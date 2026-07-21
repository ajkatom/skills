"""M71 (Codex R8): DF-R8-04 source identity enforced fail-closed at every resume
AND recomputed before every builder dispatch.

  * Resume: the pre-M71 check refused only when the freshly computed digest was
    non-null AND different (`nd is not None and od != nd`), so an UNKNOWN current
    digest (a git failure) let the resume PROCEED under unverifiable
    control-plane/support bytes. Now resume requires the current digest to be BOTH
    non-null AND equal to the sealed run anchor.
  * Dispatch: `_source_identity_field()` was computed ONCE at run setup and never
    re-checked, so the source could change (or become unknown) between dispatches
    within one logical run and be restored before the final seal. Now the source
    identity is recomputed immediately before EVERY builder dispatch
    (`_source_identity_stable`) and a drift/unknown seals a fail-closed SOURCE_DRIFT
    terminal before any builder runs.
"""
import json
import os

import pytest

import supervisor
from test_supervisor import FAKE, setup_control


def _journal_states(run_dir):
    return [json.loads(l)["state"]
            for l in (run_dir / "journal.jsonl").read_text().splitlines()]


def _only_run_dir(cr):
    return cr / "runs" / os.listdir(cr / "runs")[0]


# ---------------------------------------------------------------------------
# Resume — fail-closed on unknown OR drifted current source
# ---------------------------------------------------------------------------

def test_resume_refused_when_current_source_unknown(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    real = supervisor._source_identity_field()
    monkeypatch.setattr(supervisor, "_source_identity_field",
                        lambda: {"commit": real.get("commit"), "clean": None,
                                 "dirty": None, "tree_digest": None})
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _journal_states(_only_run_dir(cr))


def test_resume_refused_when_journaled_anchor_digest_nulled(tmp_path):
    # Opus review F1: the journal is same-user writable (no per-line HMAC). Nulling
    # the journaled SOURCE_IDENTITY.tree_digest previously skipped BOTH the resume
    # drift check AND the per-dispatch guard (which no-ops when the anchor is
    # unset). Enforcement now triggers on the EVENT's presence: a NULL anchor on a
    # real git checkout (current digest non-null) is an emptied/tampered anchor.
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    run_dir = _only_run_dir(cr)
    jp = run_dir / "journal.jsonl"
    out = []
    for line in jp.read_text().splitlines():
        e = json.loads(line)
        if e.get("state") == "SOURCE_IDENTITY":
            e["data"]["tree_digest"] = None  # emptied anchor
        out.append(json.dumps(e))
    jp.write_text("\n".join(out) + "\n")
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _journal_states(run_dir)


def test_resume_refused_on_forged_clean_with_null_digest(tmp_path, monkeypatch):
    # Opus re-review (M71 residual): {clean:True, tree_digest:null} is an IMPOSSIBLE
    # honest combination (both computed together). An attacker forges clean=True +
    # nulls the digest AND suppresses the CURRENT git digest (so an nd-based check
    # would pass) to launder to a commit-only production match. The clean/digest
    # consistency check refuses it regardless of the current digest.
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    run_dir = _only_run_dir(cr)
    jp = run_dir / "journal.jsonl"
    out = []
    for line in jp.read_text().splitlines():
        e = json.loads(line)
        if e.get("state") == "SOURCE_IDENTITY":
            e["data"].update(tree_digest=None, clean=True, dirty=False)
        out.append(json.dumps(e))
    jp.write_text("\n".join(out) + "\n")
    # also suppress the CURRENT git digest (the nd-based branch would have passed)
    real = supervisor._source_identity_field()
    monkeypatch.setattr(supervisor, "_source_identity_field",
                        lambda: {"commit": real.get("commit"), "clean": None,
                                 "dirty": None, "tree_digest": None})
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _journal_states(run_dir)


def test_honest_unknown_source_resumes_without_refusal(tmp_path, monkeypatch):
    # The inverse: a run whose source was genuinely UNKNOWN at seal (a transient git
    # failure → clean=None, tree_digest=None) has nothing to enforce and must NOT be
    # refused on resume (no new false positive from the consistency check).
    monkeypatch.setattr(supervisor, "_source_identity_field",
                        lambda: {"commit": "c", "clean": None, "dirty": None,
                                 "tree_digest": None})
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    supervisor.resume(str(cr), "continue")
    assert "SOURCE_DRIFT_REFUSED" not in _journal_states(_only_run_dir(cr))


def test_null_sealed_tree_digest_is_not_production_ready():
    import df_evidence_bundle as EB
    bundle = {
        "source": {"sealed_commit": "a" * 40, "sealed_clean": True,
                   "sealed_tree_digest": None, "matches_sealed": True},
        "audit_chain": {"verified": True}, "config_sha256": "c" * 64,
        "effective_tier": "hardened", "qualified": True,
        "ship_result": {"outcome": "SHIPPED", "authenticated": True,
                        "actions": [{"name": "d", "status": "ok", "reversible": True}]},
        "reentry": {"no_duplicate_or_unknown_actions": True,
                    "reentry_verified": {"verified": True}},
        "release": {"present": False, "verified": None, "action_names": None},
        "custody": {"verified": True}, "denial_probe_passed": True,
        "image": {"pinned": True, "resolved_image_digest": "sha256:" + "b" * 64,
                  "image": "x@sha256:" + "b" * 64},
    }
    manifest = {"container": bundle["image"], "intervention_mode": "H4"}
    ready, unmet = EB._production_verdict(bundle, {"manifest_verified": True},
                                         manifest, "hardened-h4")
    assert not ready and any("sealed source-tree digest" in u for u in unmet)


def test_genuine_non_git_run_resumes_without_refusal(tmp_path, monkeypatch):
    # The inverse of the above: a genuine non-git checkout seals tree_digest=None
    # AND recomputes None on resume — there is nothing to enforce, so resume must
    # NOT refuse (no false positive from the F1 fix).
    monkeypatch.setattr(supervisor, "_source_identity_field",
                        lambda: {"commit": None, "clean": None, "dirty": None,
                                 "tree_digest": None})
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    supervisor.resume(str(cr), "continue")
    assert "SOURCE_DRIFT_REFUSED" not in _journal_states(_only_run_dir(cr))


def test_resume_refused_when_current_source_drifted(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    real = supervisor._source_identity_field()
    monkeypatch.setattr(supervisor, "_source_identity_field",
                        lambda: {"commit": "deadbeef", "clean": True, "dirty": False,
                                 "tree_digest": "f" * 64})
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SOURCE_DRIFT_REFUSED" in _journal_states(_only_run_dir(cr))


# ---------------------------------------------------------------------------
# Dispatch — recomputed before EVERY builder dispatch
# ---------------------------------------------------------------------------

def test_source_identity_recomputed_before_every_dispatch(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    calls = []
    orig = supervisor._source_identity_field

    def counted():
        calls.append(1)
        return orig()

    monkeypatch.setattr(supervisor, "_source_identity_field", counted)
    supervisor.run(str(cr), None)
    run_dir = _only_run_dir(cr)
    builds = sum(1 for s in _journal_states(run_dir) if s == "BUILD")
    # one computation at run setup + one guard before each of the `builds` dispatches
    assert builds >= 2 and len(calls) >= builds + 1


def test_dispatch_refused_on_mid_run_source_drift(tmp_path, monkeypatch):
    # The anchor is sealed at run setup (call #1) and the first dispatch guard
    # (call #2) matches it; make the SECOND dispatch guard see a different digest.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    orig = supervisor._source_identity_field
    state = {"n": 0}

    def drifting():
        state["n"] += 1
        base = orig()
        if state["n"] >= 3:  # setup=1, dispatch1=2, dispatch2+=drift
            return dict(base, tree_digest="d" * 64, commit="drifted")
        return base

    monkeypatch.setattr(supervisor, "_source_identity_field", drifting)
    rc = supervisor.run(str(cr), None)
    run_dir = _only_run_dir(cr)
    states = _journal_states(run_dir)
    assert "SOURCE_DRIFT_REFUSED" in states
    assert rc != 0  # never a clean converge under a drifted source
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] == "SOURCE_DRIFT"
    assert manifest["qualified"] is False


def test_dispatch_refused_when_source_unknown_mid_run(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    orig = supervisor._source_identity_field
    state = {"n": 0}

    def unknowing():
        state["n"] += 1
        base = orig()
        if state["n"] >= 3:
            return {"commit": base.get("commit"), "clean": None, "dirty": None,
                    "tree_digest": None}
        return base

    monkeypatch.setattr(supervisor, "_source_identity_field", unknowing)
    supervisor.run(str(cr), None)
    run_dir = _only_run_dir(cr)
    assert "SOURCE_DRIFT_REFUSED" in _journal_states(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] == "SOURCE_DRIFT"


def test_legacy_run_without_sealed_digest_still_dispatches(tmp_path, monkeypatch):
    # A non-git checkout seals tree_digest=None; there is no anchor to drift from,
    # so per-dispatch enforcement is a no-op and the run proceeds normally (no
    # over-constraint / false refusal).
    monkeypatch.setattr(supervisor, "_source_identity_field",
                        lambda: {"commit": None, "clean": None, "dirty": None,
                                 "tree_digest": None})
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    supervisor.run(str(cr), None)
    run_dir = _only_run_dir(cr)
    assert "SOURCE_DRIFT_REFUSED" not in _journal_states(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] != "SOURCE_DRIFT"
