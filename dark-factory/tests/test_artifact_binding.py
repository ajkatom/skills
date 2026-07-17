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
import shutil
import stat
import subprocess
import sys

import pytest

import df_common
import df_custody
import df_seal
import supervisor
from test_enterprise_config import (
    _approver,
    _enterprise_control,
    _fake_invoke,
    _patch_enterprise_probes,
    _sink_receiver,
)
from test_supervisor import FAKE, MARKER, read_journal, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
SYMLINK_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_symlink_artifact")
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")


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


# ---------------------------------------------------------------------------
# DF-01/M28a Task 3: verify-by-identity + custody-by-object-id + retention.
#
# Task 2 (above) bound `manifest["artifact"]` to the frozen object; this half
# makes that binding actually CHECKED, fail-closed, at verify + custody time:
#   - verify_manifest (and the verify-manifest CLI) recompute the bound
#     object's sidecar and require object_id_of(recomputed) == the manifest's
#     bound object_id -- any drift (content, mode, name, an added file/dir)
#     or a missing object is ARTIFACT MISMATCH / ARTIFACT UNAVAILABLE, never
#     a clean pass. A manifest that does not bind an object at all (pre-M28a,
#     or a pre-workspace terminal) is UNBOUND -- a DISTINCT non-success, never
#     confused with a clean OK.
#   - attach_custody / verify_custody_cmd REQUIRE the bound object and refuse
#     (non-zero / False) unless it independently re-verifies against the
#     live object store.
#   - retention: `supervisor.object_referenced` is the guard any future
#     prune/GC tooling MUST consult before removing an object dir; there is
#     no prune command today, so the fail-closed contract is proven directly
#     -- removing an object out from under a run that references it makes
#     verify report ARTIFACT UNAVAILABLE, never a pass.
# ---------------------------------------------------------------------------


def _object_content_dir(cr, object_id):
    return os.path.join(supervisor._object_store_root(str(cr)), "objects", object_id)


def _first_file_in(content_dir):
    for root, _dirs, files in os.walk(content_dir):
        for name in files:
            return os.path.join(root, name)
    return None


def _mutate_one_byte(path):
    data = bytearray(open(path, "rb").read())
    if data:
        data[0] ^= 0xFF
    else:
        data = bytearray(b"x")
    open(path, "wb").write(bytes(data))


def _run_and_get(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    run_id = os.listdir(cr / "runs")[0]
    run_dir = str(cr / "runs" / run_id)
    manifest = _manifest(cr, run_id)
    assert manifest["artifact"] is not None
    return cr, run_dir, manifest


def _make_unbound_manifest(run_dir):
    """Rewrite run_dir's manifest.json to artifact: null (a pre-M28a shape)
    and recompute manifest.sha256 so the manifest-integrity checks still
    pass -- isolating the artifact check from the byte-integrity checks."""
    mp = os.path.join(run_dir, "manifest.json")
    m = json.loads(open(mp, encoding="utf-8").read())
    m["artifact"] = None
    text = df_common.canonical_json(m)
    open(mp, "w", encoding="utf-8").write(text)
    open(os.path.join(run_dir, "manifest.sha256"), "w", encoding="utf-8").write(
        df_common.sha256_str(text) + "\n")


# --- verify_manifest: pristine passes, any object drift fails closed -------


def test_verify_manifest_pristine_converged_run_passes(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    assert supervisor.verify_manifest(run_dir) is True


def test_verify_manifest_cli_exits_0_on_pristine_object(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    proc = subprocess.run([sys.executable, SUP, "verify-manifest", "--run-dir", run_dir],
                          capture_output=True, text=True)
    assert proc.returncode == 0
    assert "OK" in proc.stdout


def test_verify_manifest_detects_one_byte_mutation_in_object(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    content_dir = _object_content_dir(cr, manifest["artifact"]["object_id"])
    target = _first_file_in(content_dir)
    assert target, "fixture object has no files to mutate"
    _mutate_one_byte(target)

    assert supervisor.verify_manifest(run_dir) is False


def test_verify_manifest_detects_file_mode_mutation_in_object(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    content_dir = _object_content_dir(cr, manifest["artifact"]["object_id"])
    target = _first_file_in(content_dir)
    assert target
    current_mode = stat.S_IMODE(os.stat(target).st_mode)
    os.chmod(target, current_mode ^ 0o111)  # flip exec bits -- a real mode change

    assert supervisor.verify_manifest(run_dir) is False


def test_verify_manifest_detects_filename_mutation_in_object(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    content_dir = _object_content_dir(cr, manifest["artifact"]["object_id"])
    target = _first_file_in(content_dir)
    assert target
    os.rename(target, target + ".renamed")

    assert supervisor.verify_manifest(run_dir) is False


def test_verify_manifest_detects_added_empty_dir_in_object(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    content_dir = _object_content_dir(cr, manifest["artifact"]["object_id"])
    os.mkdir(os.path.join(content_dir, "planted_empty_dir"))

    assert supervisor.verify_manifest(run_dir) is False


def test_verify_manifest_pruned_object_is_unavailable_not_pass(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    content_dir = _object_content_dir(cr, manifest["artifact"]["object_id"])
    shutil.rmtree(content_dir)

    assert supervisor.verify_manifest(run_dir) is False


def test_verify_manifest_cli_prints_artifact_unavailable_on_pruned_object(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    content_dir = _object_content_dir(cr, manifest["artifact"]["object_id"])
    shutil.rmtree(content_dir)

    proc = subprocess.run([sys.executable, SUP, "verify-manifest", "--run-dir", run_dir],
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "ARTIFACT UNAVAILABLE" in proc.stdout


# --- verify_manifest: UNBOUND is a distinct non-success, not a clean pass --


def test_verify_manifest_unbound_pre_m28_manifest_is_not_success(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    _make_unbound_manifest(run_dir)

    assert supervisor.verify_manifest(run_dir) is False


def test_verify_manifest_cli_distinguishes_unbound_from_mismatch(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    _make_unbound_manifest(run_dir)
    unbound = subprocess.run([sys.executable, SUP, "verify-manifest", "--run-dir", run_dir],
                             capture_output=True, text=True)
    assert unbound.returncode != 0
    assert "UNBOUND" in unbound.stdout

    cr2, run_dir2, manifest2 = _run_and_get(tmp_path / "second")
    content_dir2 = _object_content_dir(cr2, manifest2["artifact"]["object_id"])
    target2 = _first_file_in(content_dir2)
    assert target2
    _mutate_one_byte(target2)
    mismatch = subprocess.run([sys.executable, SUP, "verify-manifest", "--run-dir", run_dir2],
                              capture_output=True, text=True)
    assert mismatch.returncode != 0
    assert "ARTIFACT MISMATCH" in mismatch.stdout
    # The two failure modes must be machine-distinguishable, not just two
    # different flavors of the same nonzero exit code.
    assert mismatch.returncode != unbound.returncode


# --- retention guard ---------------------------------------------------


def test_object_referenced_true_for_a_runs_artifact_false_otherwise(tmp_path):
    cr, run_dir, manifest = _run_and_get(tmp_path)
    object_id = manifest["artifact"]["object_id"]
    assert supervisor.object_referenced(str(cr), object_id) is True
    assert supervisor.object_referenced(str(cr), "0" * 64) is False


# --- custody: REQUIRE + re-verify the bound artifact object ----------------


def _enterprise_run_custody_pending(tmp_path, monkeypatch):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    ctx = _sink_receiver(tmp_path)
    sink_url, _store = ctx.__enter__()
    cr = _enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
    _patch_enterprise_probes(monkeypatch)
    monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)
    assert supervisor.run(str(cr), None) == 3
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    return ctx, cr, run_dir, (priv_a, pub_a), (priv_b, pub_b)


def test_attach_custody_refuses_unbound_manifest(tmp_path, monkeypatch, capsys):
    ctx, cr, run_dir, (priv_a, pub_a), (priv_b, pub_b) = _enterprise_run_custody_pending(
        tmp_path, monkeypatch)
    try:
        _make_unbound_manifest(str(run_dir))
        manifest_bytes = (run_dir / "manifest.json").read_bytes()
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
            {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
        ]), encoding="utf-8")

        rc = supervisor.attach_custody(str(cr), str(run_dir))
        assert rc != 0
        assert not (run_dir / "custody_attestation.json").exists()
        assert "predates artifact binding" in capsys.readouterr().err
    finally:
        ctx.__exit__(None, None, None)


def test_attach_custody_refuses_mutated_object(tmp_path, monkeypatch, capsys):
    ctx, cr, run_dir, (priv_a, pub_a), (priv_b, pub_b) = _enterprise_run_custody_pending(
        tmp_path, monkeypatch)
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text())
        object_id = manifest["artifact"]["object_id"]
        content_dir = _object_content_dir(cr, object_id)
        target = _first_file_in(content_dir)
        assert target
        _mutate_one_byte(target)

        manifest_bytes = (run_dir / "manifest.json").read_bytes()
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
            {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
        ]), encoding="utf-8")

        rc = supervisor.attach_custody(str(cr), str(run_dir))
        assert rc != 0
        assert not (run_dir / "custody_attestation.json").exists()
        assert "re-verification" in capsys.readouterr().err
    finally:
        ctx.__exit__(None, None, None)


def test_attach_custody_succeeds_on_pristine_object(tmp_path, monkeypatch):
    ctx, cr, run_dir, (priv_a, pub_a), (priv_b, pub_b) = _enterprise_run_custody_pending(
        tmp_path, monkeypatch)
    try:
        manifest_bytes = (run_dir / "manifest.json").read_bytes()
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
            {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
        ]), encoding="utf-8")

        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0
        assert (run_dir / "custody_attestation.json").exists()
    finally:
        ctx.__exit__(None, None, None)


def test_verify_custody_cmd_refuses_after_object_mutated_post_attach(tmp_path, monkeypatch):
    ctx, cr, run_dir, (priv_a, pub_a), (priv_b, pub_b) = _enterprise_run_custody_pending(
        tmp_path, monkeypatch)
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text())
        object_id = manifest["artifact"]["object_id"]
        manifest_bytes = (run_dir / "manifest.json").read_bytes()
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
            {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
        ]), encoding="utf-8")
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is True

        content_dir = _object_content_dir(cr, object_id)
        target = _first_file_in(content_dir)
        assert target
        _mutate_one_byte(target)

        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False
    finally:
        ctx.__exit__(None, None, None)


def test_verify_custody_cmd_refuses_unbound_manifest(tmp_path, monkeypatch, capsys):
    ctx, cr, run_dir, (priv_a, pub_a), (priv_b, pub_b) = _enterprise_run_custody_pending(
        tmp_path, monkeypatch)
    try:
        _make_unbound_manifest(str(run_dir))

        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False
        assert "predates artifact binding" in capsys.readouterr().out
    finally:
        ctx.__exit__(None, None, None)


def test_verify_custody_cmd_pristine_object_qualified(tmp_path, monkeypatch):
    ctx, cr, run_dir, (priv_a, pub_a), (priv_b, pub_b) = _enterprise_run_custody_pending(
        tmp_path, monkeypatch)
    try:
        manifest_bytes = (run_dir / "manifest.json").read_bytes()
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
            {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
        ]), encoding="utf-8")
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0

        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is True
    finally:
        ctx.__exit__(None, None, None)


def test_attach_custody_takes_control_root_lock_around_writes(tmp_path, monkeypatch):
    ctx, cr, run_dir, (priv_a, pub_a), (priv_b, pub_b) = _enterprise_run_custody_pending(
        tmp_path, monkeypatch)
    try:
        manifest_bytes = (run_dir / "manifest.json").read_bytes()
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
            {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
        ]), encoding="utf-8")

        lock = supervisor.acquire_lock(str(cr))
        try:
            rc = supervisor.attach_custody(str(cr), str(run_dir))
            assert rc != 0
            assert not (run_dir / "custody_attestation.json").exists()
        finally:
            supervisor.release_lock(lock)

        # Once released, attach proceeds normally.
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0
    finally:
        ctx.__exit__(None, None, None)
