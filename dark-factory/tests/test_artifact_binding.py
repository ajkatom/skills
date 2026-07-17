"""DF-01/M28a Task 2: seal-first supervisor order-of-ops + manifest
`artifact` field.

Covers the supervisor-side wiring around dark-factory/scripts/df_seal.py
(Task 1, already merged): on the dev-loop CONVERGED path the converged
workspace is frozen into a content-addressed object BEFORE the final exam
runs, its identity is bound into the signed manifest as
`manifest["artifact"]`, and a hostile/unhashable workspace fails CLOSED
(ARTIFACT_UNHASHABLE, never qualified) instead of silently shipping.

Engineering note on the final-exam-vs-object question (see task-2-report.md
for the full writeup): this supervisor wiring runs the final exam +
security gates against `workspace` (byte-identical to before this change)
rather than redirecting them to read from the frozen copy at
objects/<object_id>/ -- because df_seal's object-store copies are not
filesystem-read-only against the SAME privilege level that published them
(a documented df_seal residual), so pointing an arbitrary candidate-
produced final-exam command's cwd at the object dir risks a scenario
incidentally writing into it and corrupting the very object whose identity
was just bound into the manifest. Nothing mutates `workspace` between
freeze() and the final exam (no builder call happens in between), so
testing `workspace` is equivalent to testing the frozen object's content
for this run. `test_post_final_exam_verify_object_runs_and_holds` below is
the fallback's other half: it proves the supervisor itself re-verifies the
already-frozen object against its own sidecar AFTER the final exam +
security gates have run, and fails closed if that ever doesn't hold.
"""
import json
import os

import pytest

import df_seal
import supervisor
from test_supervisor import FAKE, MARKER, read_journal, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
SYMLINK_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_symlink_artifact")


def _manifest(cr, run_id):
    return json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))


def _workspace_dir(cr, run_id):
    # setup_control points workspace_root at tmp_path/"ws"; the workspace for
    # a given run is workspace_root/<invocation>, and invocation == run_id
    # (see supervisor.run: workspace = os.path.join(cfg["workspace_root"], invocation)).
    cfg = json.loads((cr / "config.json").read_text(encoding="utf-8"))
    return os.path.join(cfg["workspace_root"], run_id)


def test_converged_run_binds_artifact_object_id(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, run_id = read_journal(cr)
    manifest = _manifest(cr, run_id)
    assert manifest["outcome"] in ("COMPLETE_QUALIFIED", "COMPLETE_UNQUALIFIED")

    artifact = manifest["artifact"]
    assert artifact is not None
    assert set(artifact) == {"object_id", "seal_version", "file_count", "dir_count"}

    workspace = _workspace_dir(cr, run_id)
    expected_id = df_seal.object_id_of(df_seal.object_manifest(workspace))
    assert artifact["object_id"] == expected_id
    assert artifact["seal_version"] == df_seal.SEAL_VERSION

    sidecar = df_seal.object_manifest(workspace)
    assert artifact["file_count"] == len(sidecar["files"])
    assert artifact["dir_count"] == len(sidecar["dirs"])

    # The object is genuinely published under <control_root>/objects and
    # independently verifies -- not just a hash computed and thrown away.
    object_store = supervisor._object_store_root(str(cr))
    assert df_seal.verify_object(object_store, artifact["object_id"]) is True

    # freeze() happened strictly before the final exam: the journal order
    # is BUILD -> VERIFY -> FINAL_EXAM -> CONVERGED, and nothing about
    # freezing is itself journaled as a scenario-content-bearing event.
    states = [e["state"] for e in entries]
    assert states.index("VERIFY") < states.index("FINAL_EXAM") < states.index("CONVERGED")


def test_post_final_exam_verify_object_runs_and_holds(tmp_path, monkeypatch):
    """Proves the supervisor itself re-verifies the frozen object AFTER the
    final exam + security gates have run (the fallback's belt-and-
    suspenders half — see module docstring), and that the run only reaches
    CONVERGED once that re-verification holds."""
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")

    calls = []
    real_verify_object = df_seal.verify_object

    def spy_verify_object(object_store, object_id):
        result = real_verify_object(object_store, object_id)
        calls.append((object_store, object_id, result))
        return result

    monkeypatch.setattr(supervisor.df_seal, "verify_object", spy_verify_object)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, run_id = read_journal(cr)
    manifest = _manifest(cr, run_id)
    object_id = manifest["artifact"]["object_id"]

    assert calls, "supervisor never called df_seal.verify_object post-final-exam"
    object_store, verified_id, result = calls[-1]
    assert verified_id == object_id
    assert object_store == supervisor._object_store_root(str(cr))
    assert result is True

    # The re-verify happened strictly after FINAL_EXAM and before CONVERGED.
    states = [e["state"] for e in entries]
    assert states.index("FINAL_EXAM") < states.index("CONVERGED")


def test_hostile_symlink_in_workspace_is_artifact_unhashable_not_qualified(tmp_path):
    cr = setup_control(tmp_path, SYMLINK_BUILDER, checkpoint="auto")
    rc = supervisor.run(str(cr), None)

    # Fail-closed: a hostile (unhashable) converged workspace must never
    # reach a qualified/CONVERGED terminal. Exit code 3, same "artifact
    # rejected" class as FINAL_EXAM_FAILED/SECURITY_GATE_FAILED (this is
    # discovered after a workspace was built and dev-verified, not a
    # build-level precondition failure like the exit-2 branches).
    assert rc == 3

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "ARTIFACT_UNHASHABLE" in states
    assert "CONVERGED" not in states
    assert "CUSTODY_PENDING" not in states

    manifest = _manifest(cr, run_id)
    assert manifest["outcome"] == "ARTIFACT_UNHASHABLE"
    assert manifest["qualified"] is False
    assert manifest["artifact"] is None

    # No object was ever published for this run's hostile workspace.
    object_store = supervisor._object_store_root(str(cr))
    objects_dir = os.path.join(object_store, "objects")
    if os.path.isdir(objects_dir):
        assert os.listdir(objects_dir) == []


def test_pre_workspace_terminal_has_artifact_null(tmp_path):
    """A terminal reached before any workspace exists (the M7 pre-build
    coverage gate, here) must carry artifact: null -- mirrors the existing
    snapshot_sha256=None seed on early aborts (spec 7.5 honesty)."""
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    (cr / "behaviors.json").write_text(
        json.dumps({"behaviors": [{"id": "BHV-001"}, {"id": "BHV-002"}, {"id": "BHV-999"}]}),
        encoding="utf-8",
    )

    rc = supervisor.run(str(cr), None)
    assert rc == 2

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "COVERAGE_GATE_FAILED" in states
    assert "BUILD" not in states  # confirms: no workspace-bearing build ever ran

    manifest = _manifest(cr, run_id)
    assert manifest["outcome"] == "GATE_FAILED"
    assert manifest["artifact"] is None


def test_final_exam_failure_still_carries_the_frozen_artifact(tmp_path):
    """FINAL_EXAM_FAILED is reached AFTER a successful freeze (the object
    exists, it's just rejected for scenario reasons) -- artifact must be
    bound, not null, and the bound object_id must independently verify."""
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # A final-cohort scenario the fixture builder can never satisfy (it only
    # ever writes greet.py, never a second, differently-behaved binary) --
    # forces the dev cohort to converge (BHV-001/BHV-002 unchanged) while the
    # sealed final exam still fails on this new final-only behavior.
    final_sc = {
        "ir_version": "0.1", "id": "BHV-003-S1", "behavior_id": "BHV-003", "cohort": "final",
        "title": f"{MARKER} never satisfied by the fixture builder",
        "given": f"{MARKER} workspace has greet.py",
        "when": {"run": ["python3", "farewell.py"], "timeout_s": 10},
        "then": {"exit_code": 0},
    }
    (cr / "scenarios" / "final_only.json").write_text(json.dumps(final_sc), encoding="utf-8")

    rc = supervisor.run(str(cr), None)
    assert rc == 3

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "FINAL_EXAM_FAILED" in states
    assert "CONVERGED" not in states

    manifest = _manifest(cr, run_id)
    assert manifest["outcome"] == "FINAL_EXAM_FAILED"
    assert manifest["qualified"] is False
    artifact = manifest["artifact"]
    assert artifact is not None
    object_store = supervisor._object_store_root(str(cr))
    assert df_seal.verify_object(object_store, artifact["object_id"]) is True
