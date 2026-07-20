"""M67 (Codex R7): DF-R7-03 production evidence profiles + DF-R7-04 run-stable
source identity.

  * DF-R7-04 — source identity now carries a deterministic tree/content digest
    and a TRI-STATE cleanliness (not just a commit + a dirty bool that read
    `false` on a git failure). It is persisted at the first dispatch and a
    resume under a DIFFERENT source (even the same commit, different bytes) is
    refused fail-closed.
  * DF-R7-03 — `--require-production` now requires a named profile
    (hardened-h4 / enterprise) and fails closed unless every fact that profile
    requires is present, bound, and cryptographically verified. A standard,
    unshipped, receipt-free run is never production-ready.
"""
import json
import os

import pytest

import df_evidence_bundle
import supervisor
from test_supervisor import FAKE, setup_control, stub_network_probe


# ---------------------------------------------------------------------------
# DF-R7-04 — source identity: digest + tri-state clean + resume drift refusal
# ---------------------------------------------------------------------------

def test_source_identity_has_tree_digest_and_tristate_clean():
    si = supervisor._source_identity_field()
    assert set(si) >= {"commit", "clean", "tree_digest", "dirty"}
    assert si["commit"] and si["tree_digest"]
    assert si["clean"] in (True, False)          # this repo is a real checkout
    assert si["dirty"] == (not si["clean"])


def _standard_run(tmp_path, monkeypatch, checkpoint="auto"):
    cr = setup_control(tmp_path, FAKE, checkpoint=checkpoint)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "standard"
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    stub_network_probe(monkeypatch)
    monkeypatch.setattr(supervisor, "resolve_isolation",
                        lambda *a, **k: ("standard", [], "fake-standard-backend", True))
    return cr


def test_first_dispatch_persists_the_source_anchor(tmp_path, monkeypatch):
    cr = _standard_run(tmp_path, monkeypatch)
    assert supervisor.run(str(cr), None) == 0
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    anchor = run_dir / supervisor.SOURCE_IDENTITY_FILE
    assert anchor.exists()
    si = json.loads(anchor.read_text())
    assert si["commit"] and si["tree_digest"]
    # and the manifest sealed the SAME identity.
    mf = json.loads((run_dir / "manifest.json").read_text())
    assert mf["source_identity"]["tree_digest"] == si["tree_digest"]


def test_resume_under_drifted_source_is_refused(tmp_path, monkeypatch):
    # A run that PAUSES (H2), then a resume computed under a different source
    # tree_digest must fail closed — a logical run must not seal an artifact
    # partly built under different supervisor bytes.
    cr = _standard_run(tmp_path, monkeypatch, checkpoint="pause")
    # H2 pauses after a non-converged verify; FAKE converges on iter 2, so force
    # a pause by capping iterations? Simpler: use the FAKE which pauses under
    # checkpoint=pause after the first non-converged verify.
    rc = supervisor.run(str(cr), None)
    assert rc == supervisor.PAUSED, f"expected a pause to resume from, got {rc}"

    # Now DRIFT the source: the resume-time _source_identity_field returns a
    # different tree_digest than the persisted anchor.
    real = supervisor._source_identity_field()
    drifted = dict(real, tree_digest="d" * 64, commit="deadbeef")
    monkeypatch.setattr(supervisor, "_source_identity_field", lambda: drifted)
    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == 2, f"resume under drifted source must refuse (exit 2), got {rc2}"
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    states = [json.loads(l)["state"]
              for l in (run_dir / "journal.jsonl").read_text().strip().splitlines()]
    assert "SOURCE_DRIFT_REFUSED" in states


def test_resume_under_same_source_is_not_drift_refused(tmp_path, monkeypatch):
    cr = _standard_run(tmp_path, monkeypatch, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    # No drift: the resume must NOT be the fail-closed exit-2 drift refusal (H2
    # legitimately pauses again before ship → exit 10; that's fine — the point
    # is it was not refused, and no SOURCE_DRIFT_REFUSED was journaled).
    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 != 2, f"a same-source resume must not be drift-refused, got {rc2}"
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    states = [json.loads(l)["state"]
              for l in (run_dir / "journal.jsonl").read_text().strip().splitlines()]
    assert "SOURCE_DRIFT_REFUSED" not in states


# ---------------------------------------------------------------------------
# DF-R7-03 — production profiles fail closed
# ---------------------------------------------------------------------------

def test_require_production_needs_a_recognized_profile(tmp_path, monkeypatch):
    cr = _standard_run(tmp_path, monkeypatch)
    assert supervisor.run(str(cr), None) == 0
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    bundle, err = df_evidence_bundle.assemble(
        str(cr), str(run_dir), require_production=True, profile=None)
    assert err is None
    assert bundle["production_ready"] is False
    assert any("profile" in u for u in bundle["production_unmet"])


@pytest.mark.parametrize("profile", ["hardened-h4", "enterprise"])
def test_standard_unshipped_run_is_never_production_ready(tmp_path, monkeypatch, profile):
    # The R7-03 repro: a qualified STANDARD run with no ship/release/receipt must
    # fail EVERY production profile.
    cr = _standard_run(tmp_path, monkeypatch)
    assert supervisor.run(str(cr), None) == 0
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    bundle, err = df_evidence_bundle.assemble(
        str(cr), str(run_dir), require_production=True, profile=profile)
    assert err is None
    assert bundle["production_ready"] is False
    unmet = " ".join(bundle["production_unmet"])
    assert "not hardened" in unmet or "not enterprise" in unmet
    assert "SHIPPED" in unmet or "re-entry" in unmet


def test_reentry_proof_requires_a_shipped_run(tmp_path, monkeypatch):
    # An unshipped run's reentry section must NOT read as "no duplicates".
    cr = _standard_run(tmp_path, monkeypatch)
    assert supervisor.run(str(cr), None) == 0
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    re = df_evidence_bundle._attempt_aware_reentry(str(cr), str(run_dir))
    assert re["shipped"] is False
    assert re["no_duplicate_or_unknown_actions"] is False


def test_resume_after_anchor_deletion_still_refuses_drift(tmp_path, monkeypatch):
    # opus F1: the ORIGINAL identity is journaled (SOURCE_IDENTITY), so DELETING
    # the same-user-writable anchor file cannot make a drifted resume fail OPEN —
    # the journal still carries the original for the drift comparison.
    cr = _standard_run(tmp_path, monkeypatch, checkpoint="pause")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    (run_dir / supervisor.SOURCE_IDENTITY_FILE).unlink()  # delete the anchor
    real = supervisor._source_identity_field()
    drifted = dict(real, tree_digest="d" * 64, commit="deadbeef")
    monkeypatch.setattr(supervisor, "_source_identity_field", lambda: drifted)
    rc = supervisor.resume(str(cr), "continue")
    assert rc == 2, f"drift must still refuse even with the anchor deleted, got {rc}"
    states = [json.loads(l)["state"]
              for l in (run_dir / "journal.jsonl").read_text().strip().splitlines()]
    assert "SOURCE_DRIFT_REFUSED" in states


def test_first_dispatch_journals_source_identity(tmp_path, monkeypatch):
    cr = _standard_run(tmp_path, monkeypatch)
    assert supervisor.run(str(cr), None) == 0
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    states = [json.loads(l) for l in (run_dir / "journal.jsonl").read_text().strip().splitlines()]
    si = [e for e in states if e["state"] == "SOURCE_IDENTITY"]
    assert len(si) == 1 and si[0]["data"]["tree_digest"]
