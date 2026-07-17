"""M36b (Part B) e2e tests for `df-fork` — spec-fork lineage + parent
supersession. A parent run converges (cooperative, auto mode) and binds a
frozen artifact object; forking seeds a NEW child run from that object, records
lineage on the child manifest, marks the parent superseded, and still lets the
parent verify clean (surfacing the supersession)."""
import json
import os

import pytest

import df_seal
import supervisor
from test_supervisor import FAKE, setup_control


def _converged_parent(tmp_path):
    """A cooperative parent that converges (COMPLETE_UNQUALIFIED) with a bound
    artifact. checkpoint='auto' (H3) so a single run() converges with no pause
    (no after-verify pause, no before-ship pause)."""
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    return cr, run_id


def test_fork_records_lineage_and_supersedes_parent(tmp_path):
    cr, parent_id = _converged_parent(tmp_path)
    parent_dir = cr / "runs" / parent_id
    parent_manifest = json.loads((parent_dir / "manifest.json").read_text())
    parent_object_id = parent_manifest["artifact"]["object_id"]
    parent_sha = (parent_dir / "manifest.sha256").read_text().strip()

    rc = supervisor.fork_cmd(str(cr), str(parent_dir))
    assert rc == 0

    # A NEW child run exists.
    run_ids = sorted(os.listdir(cr / "runs"))
    assert len(run_ids) == 2
    child_id = next(r for r in run_ids if r != parent_id)
    child_dir = cr / "runs" / child_id
    child_manifest = json.loads((child_dir / "manifest.json").read_text())

    # Lineage recorded on the child manifest.
    lineage = child_manifest["lineage"]
    assert lineage["parent_run_id"] == parent_id
    assert lineage["parent_artifact_object_id"] == parent_object_id
    assert lineage["parent_manifest_sha256"] == parent_sha
    assert lineage["forked_at"]

    # FORKED journaled in the child.
    child_states = [json.loads(l)["state"]
                    for l in (child_dir / "journal.jsonl").read_text().splitlines()]
    assert "FORKED" in child_states

    # Parent marked superseded (sidecar + post-seal SUPERSEDED event, NOT the
    # sealed journal), and its manifest STILL verifies clean.
    sb = json.loads((parent_dir / "superseded_by.json").read_text())
    assert sb["child_run_id"] == child_id
    events = (parent_dir / "audit_events.jsonl").read_text()
    assert "SUPERSEDED" in events
    assert supervisor.verify_manifest(str(parent_dir),
                                      object_store=supervisor._object_store_root(str(cr)))


def test_verify_manifest_surfaces_supersession(tmp_path, capsys):
    cr, parent_id = _converged_parent(tmp_path)
    parent_dir = cr / "runs" / parent_id
    supervisor.fork_cmd(str(cr), str(parent_dir))
    capsys.readouterr()
    status = supervisor._verify_manifest_status(
        str(parent_dir), object_store=supervisor._object_store_root(str(cr)))
    out = capsys.readouterr().out
    assert status == "OK"
    assert "OK" in out and "SUPERSEDED" in out


def test_fork_refuses_parent_without_artifact(tmp_path):
    # A GATE_FAILED parent (inert oracle) binds no artifact -> refuse to fork.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # Break the oracle so the pre-build gate fails (no artifact ever bound).
    scen_dir = cr / "scenarios"
    for name in os.listdir(scen_dir):
        sc = json.loads((scen_dir / name).read_text())
        sc["then"] = {}  # non-discriminating oracle -> inert
        (scen_dir / name).write_text(json.dumps(sc))
    assert supervisor.run(str(cr), None) == 2
    parent_id = os.listdir(cr / "runs")[0]
    parent_dir = cr / "runs" / parent_id
    assert supervisor.fork_cmd(str(cr), str(parent_dir)) == 2
    # No child run was created.
    assert os.listdir(cr / "runs") == [parent_id]


def test_fork_refuses_tampered_parent(tmp_path):
    cr, parent_id = _converged_parent(tmp_path)
    parent_dir = cr / "runs" / parent_id
    # Tamper the frozen object so verify-by-identity fails -> parent not clean.
    parent_manifest = json.loads((parent_dir / "manifest.json").read_text())
    object_id = parent_manifest["artifact"]["object_id"]
    obj_greet = cr / "objects" / "objects" / object_id / "greet.py"
    obj_greet.write_text("tampered\n", encoding="utf-8")
    assert supervisor.fork_cmd(str(cr), str(parent_dir)) == 2
    assert os.listdir(cr / "runs") == [parent_id]  # no child


def test_fork_refuses_parent_outside_control_root(tmp_path):
    cr, parent_id = _converged_parent(tmp_path)
    # A run_dir that isn't under this control root's runs/.
    assert supervisor.fork_cmd(str(cr), str(tmp_path / "not" / "a" / "run")) == 2


def test_materialize_object_roundtrip_and_fail_closed(tmp_path):
    # df_seal.materialize_object: verify-before-copy, empty-dest requirement.
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("hello", encoding="utf-8")
    (src / "sub").mkdir()
    (src / "sub" / "b.txt").write_text("world", encoding="utf-8")
    store = str(tmp_path / "store")
    object_id = df_seal.freeze(str(src), store)

    dest = tmp_path / "dest"
    dest.mkdir()
    df_seal.materialize_object(store, object_id, str(dest))
    assert (dest / "a.txt").read_text() == "hello"
    assert (dest / "sub" / "b.txt").read_text() == "world"

    # Non-empty dest is refused.
    with pytest.raises(df_seal.SealError):
        df_seal.materialize_object(store, object_id, str(dest))

    # A drifted object is refused (verify-before-materialize).
    (tmp_path / "store" / "objects" / object_id / "a.txt").write_text("drift", encoding="utf-8")
    dest2 = tmp_path / "dest2"
    dest2.mkdir()
    with pytest.raises(df_seal.SealError):
        df_seal.materialize_object(store, object_id, str(dest2))
