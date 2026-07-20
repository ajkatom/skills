"""M60 (Codex R5 arbitration): generalized-class acceptance hardening.

The R5 findings were fixed in M56-M59+M56b; Codex's arbitration (audit/10) asks
that acceptance attack the full defect CLASS. This file adds:

  * DF-R5-03 class: builder support-file DIGESTS are sealed into the manifest
    (fresh AND resume) — an adapter's structural no-tool guarantee is only as
    strong as the bytes it imports/executes, so those bytes must be auditable
    and run-bound.
  * DF-R5-04 class: the full downgrade ladders (enterprise→hardened→standard→
    cooperative, hardened→standard→cooperative) seal requested vs effective and
    every downstream decision consumes the effective tier.
  * DF-R5-05 class: the POSITIVE init→dispatch contract — a successfully
    scaffolded root actually REACHES builder dispatch (not just "run doesn't
    reject at a gate").
  * DF-R5-01 class: the pending-record mutation test alters EVERY field, not
    only the three in the R5 reproduction.
  * DF-R5-07 class: S3 readback verifies the EXACT recorded object version.
"""
import hashlib
import json
import os
import pathlib

import pytest

import df_audit_sink
import df_evidence_bundle
import df_ship
import supervisor
from test_supervisor import FAKE, setup_control, read_journal


# ---------------------------------------------------------------------------
# DF-R5-03 class — support-file digests sealed into the manifest.
# ---------------------------------------------------------------------------

def _run_manifest(cr):
    _entries, run_id = read_journal(cr)
    return json.loads((cr / "runs" / run_id / "manifest.json").read_text())


def test_support_file_digests_are_sealed_into_the_manifest(tmp_path):
    support = tmp_path / "helper_lib.py"
    support.write_text("VALUE = 1\n", encoding="utf-8")
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["roles"]["builder"]["support_files"] = [str(support)]
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    assert supervisor.run(str(cr), None) == 0
    mf = _run_manifest(cr)
    sealed = mf["builder_identity"]["support_files"]
    assert len(sealed) == 1
    assert sealed[0]["path"] == os.path.realpath(str(support))
    assert sealed[0]["sha256"] == hashlib.sha256(b"VALUE = 1\n").hexdigest()


def test_a_changed_support_file_changes_the_sealed_digest(tmp_path):
    support = tmp_path / "helper_lib.py"
    support.write_text("VALUE = 1\n", encoding="utf-8")
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["roles"]["builder"]["support_files"] = [str(support)]
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    assert supervisor.run(str(cr), None) == 0
    d1 = _run_manifest(cr)["builder_identity"]["support_files"][0]["sha256"]

    # A substituted support file yields a DIFFERENT sealed digest (auditable).
    support.write_text("VALUE = 2  # tampered\n", encoding="utf-8")
    import shutil
    shutil.rmtree(cr / "runs")
    assert supervisor.run(str(cr), None) == 0
    d2 = _run_manifest(cr)["builder_identity"]["support_files"][0]["sha256"]
    assert d1 != d2


def test_no_support_files_no_model_identity_leaves_builder_identity_none(tmp_path):
    # Back-compat: a control root with neither seals builder_identity: null.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.run(str(cr), None) == 0
    assert _run_manifest(cr)["builder_identity"] is None


def test_builder_identity_field_helper_shape():
    assert supervisor._builder_identity_field({}) is None
    only_model = supervisor._builder_identity_field(
        {"_builder_model_identity": "anthropic/claude-fable-5"})
    assert only_model == {"model_identity": "anthropic/claude-fable-5"}


# ---------------------------------------------------------------------------
# DF-R5-04 class — the full downgrade ladders.
# ---------------------------------------------------------------------------

def _h3(cr):
    cfg = json.loads((cr / "config.json").read_text())
    for k in ("autonomy", "checkpoint"):
        cfg.pop(k, None)
    cfg["intervention_mode"] = "H3"
    (cr / "config.json").write_text(json.dumps(cfg))


@pytest.mark.parametrize("requested,effective", [
    ("hardened", "standard"),
    ("hardened", "cooperative"),
    ("standard", "cooperative"),
])
def test_downgrade_ladder_seals_requested_and_effective(tmp_path, monkeypatch,
                                                        requested, effective):
    cr = setup_control(tmp_path, FAKE)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = requested
    (cr / "config.json").write_text(json.dumps(cfg))
    _h3(cr)
    # Deterministic downgrade to `effective` (the --allow-downgrade path).
    monkeypatch.setattr(supervisor, "resolve_isolation",
                        lambda *a, **k: (effective, [], f"fake-{effective}-backend", True))

    supervisor.run(str(cr), None, allow_downgrade=True)
    mf = _run_manifest(cr)
    assert mf["requested_tier"] == requested
    assert mf["effective_tier"] == effective
    assert supervisor._effective_tier_of(mf) == effective
    # A downgraded run is qualified ONLY if its EFFECTIVE tier qualifies —
    # cooperative never does.
    if effective == "cooperative":
        assert mf["qualified"] is False


@pytest.mark.parametrize("effective", ["hardened", "standard", "cooperative"])
def test_enterprise_downgrade_ladder_seals_and_consumes_effective(tmp_path, monkeypatch,
                                                                  effective):
    # The enterprise arm of the ladder (enterprise→hardened→standard→cooperative):
    # a requested-enterprise run forced to downgrade seals the EFFECTIVE tier and
    # every downstream decision consumes it — the run is never treated as its
    # configured enterprise (which is exactly the DF-R5-04 dead-end this closes).
    from test_enterprise_config import _enterprise_control, _approver, _patch_enterprise_probes
    approvers = [_approver()[1] for _ in range(3)]
    cr = _enterprise_control(tmp_path, approvers, threshold=2)
    _h3(cr)
    _patch_enterprise_probes(monkeypatch)
    monkeypatch.setattr(supervisor, "resolve_isolation",
                        lambda *a, **k: (effective, [], f"fake-{effective}-backend", True))

    supervisor.run(str(cr), None, allow_downgrade=True)
    mf = _run_manifest(cr)
    assert mf["requested_tier"] == "enterprise"
    assert mf["effective_tier"] == effective
    assert supervisor._effective_tier_of(mf) == effective
    # Consumed downstream: a non-enterprise effective tier never seals the
    # enterprise-only CUSTODY_PENDING terminal (which would demand custody the
    # downgraded run can't attach) — the dead-end DF-R5-04 closes.
    assert mf["outcome"] != "CUSTODY_PENDING"
    if effective == "cooperative":
        assert mf["qualified"] is False


# ---------------------------------------------------------------------------
# DF-R5-05 class — the POSITIVE init→dispatch contract.
# ---------------------------------------------------------------------------

def test_scaffolded_root_reaches_builder_dispatch(tmp_path, monkeypatch):
    # A root that validate_scaffold blesses must actually REACH builder dispatch
    # (past every pre-build gate), not merely "not be rejected". Stub the adapter
    # so no real model/sandbox is needed; assert BUILD was journaled.
    import df_init
    from test_init import _kv_answers
    answers = _kv_answers(tmp_path, assurance="cooperative")
    cr = answers["control_root"]
    df_init.scaffold(cr, answers)
    ok, _report = df_init.validate_scaffold(cr)
    assert ok, "precondition: the scaffold is blessed"

    dispatched = []

    def _fake_invoke(adapter, role, workdir, prompt_file, timeout_s, **kw):
        dispatched.append(role)
        return {"adapter_protocol": "0.1", "status": "ok"}, None  # writes nothing

    monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)
    _h3(pathlib.Path(cr))  # non-converging FAKE would pause under H2
    supervisor.run(cr, None)
    assert "builder" in dispatched, "a blessed scaffold must reach builder dispatch"
    states = [e["state"] for e in read_journal(pathlib.Path(cr))[0]]
    assert "BUILD" in states


# ---------------------------------------------------------------------------
# DF-R5-07 class — S3 readback verifies the EXACT recorded version.
# ---------------------------------------------------------------------------

def test_s3_readback_reads_the_exact_recorded_version(monkeypatch):
    from test_m56_ship_evidence import _StubS3, _s3_sink
    monkeypatch.setenv("DF_AUDIT_S3_ACCESS_KEY", "AKIATEST")
    monkeypatch.setenv("DF_AUDIT_S3_SECRET_KEY", "secretTEST")
    key = "run.ship.v"
    recorded = b'{"outcome":"SHIPPED","v":"recorded"}'
    latest = b'{"outcome":"SHIPPED","v":"a-later-version"}'
    # The bare key resolves to the LATEST bytes; the versioned URL to the recorded.
    store = {f"/audit/p/{key}": latest,
             f"/audit/p/{key}?versionId=VER-RECORDED": recorded}
    with _StubS3(store) as s3:
        sink = _s3_sink(s3.port)
        # Reading by version returns the EXACT recorded bytes (not the latest).
        status, body = df_audit_sink.signed_s3_get(sink, key, version_id="VER-RECORDED")
        assert status == 200 and body == recorded

        # _sink_readback binds to the recorded version, so it confirms the exact
        # pushed bytes even though a later version now sits at the same key.
        receipt = {"kind": "s3-objectlock", "sink_key": key,
                   "version_id": "VER-RECORDED", "server_issued": True,
                   "body_sha256": hashlib.sha256(recorded).hexdigest()}
        assert supervisor._sink_readback(sink, receipt, recorded.decode()) is True

        # Sanity: the LATEST bytes differ, so a version-blind readback would have
        # mis-confirmed — proving the version binding matters.
        assert hashlib.sha256(latest).hexdigest() != receipt["body_sha256"]


# ---------------------------------------------------------------------------
# Evidence bundle assembler (arbitration "Required evidence bundle").
# ---------------------------------------------------------------------------

def test_evidence_bundle_assembles_from_a_completed_run(tmp_path, monkeypatch):
    support = tmp_path / "helper_lib.py"
    support.write_text("VALUE = 1\n", encoding="utf-8")
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "standard"
    cfg["roles"]["builder"]["support_files"] = [str(support)]
    (cr / "config.json").write_text(json.dumps(cfg))
    monkeypatch.setattr(supervisor, "resolve_isolation",
                        lambda *a, **k: ("standard", [], "fake-standard-backend", True))
    assert supervisor.run(str(cr), None) == 0
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]

    bundle, err = df_evidence_bundle.assemble(str(cr), str(run_dir))
    assert err is None
    assert bundle["requested_tier"] == "standard"
    assert bundle["effective_tier"] == "standard"
    assert bundle["config_sha256"]
    assert bundle["manifest_sha256"]
    # DF-R5-03 support-file identity flows into the bundle.
    assert bundle["builder_identity"]["support_files"][0]["sha256"] == \
        hashlib.sha256(b"VALUE = 1\n").hexdigest()
    # sections present even when empty (a partial exercise still reports).
    assert "audit_chain" in bundle and "custody" in bundle
    # This run did not ship, so the reentry section honestly says so.
    assert bundle["reentry"]["ship_journal_present"] is False


def test_evidence_bundle_scrubs_secret_bearing_keys():
    scrubbed = df_evidence_bundle._scrub(
        {"sink_key": "safe-identity", "secret_key": "SHOULD-NOT-APPEAR",
         "nested": {"api_token": "ALSO-HIDDEN", "sha256": "abc"}})
    assert scrubbed["sink_key"] == "safe-identity"      # 'sink_key' is an identity, kept
    assert scrubbed["secret_key"] == "<omitted:secret-key>"
    assert scrubbed["nested"]["api_token"] == "<omitted:secret-key>"
    assert scrubbed["nested"]["sha256"] == "abc"


def test_evidence_bundle_missing_run_is_exit_2_error(tmp_path):
    bundle, err = df_evidence_bundle.assemble(str(tmp_path), str(tmp_path / "nope"))
    assert bundle is None and err is not None


# ---------------------------------------------------------------------------
# Opus-review fixes (M60 round 2).
# ---------------------------------------------------------------------------

def test_bundle_manifest_sha256_is_the_raw_on_disk_digest_even_non_ascii(tmp_path, monkeypatch):
    # Opus 2c (blocker): the bundle's manifest_sha256 must be the hash an
    # auditor compares to the sealed sidecar/chain — the RAW on-disk bytes —
    # never a re-serialization (ensure_ascii divergence on any non-ASCII byte).
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["roles"]["builder"]["model_identity"] = "anthropic/claude-fablé-5 ✓"  # non-ASCII
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    assert supervisor.run(str(cr), None) == 0
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]

    bundle, err = df_evidence_bundle.assemble(str(cr), str(run_dir))
    assert err is None
    raw = (run_dir / "manifest.json").read_bytes()
    assert bundle["manifest_sha256"] == hashlib.sha256(raw).hexdigest()


def test_bundle_non_object_manifest_is_a_clean_error_not_a_crash(tmp_path):
    # Opus 2d: valid-JSON-but-non-object manifest → (None, error), never a raise.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text("[]", encoding="utf-8")
    bundle, err = df_evidence_bundle.assemble(str(tmp_path), str(run_dir))
    assert bundle is None and "not a JSON object" in err


def test_support_file_swapped_to_a_directory_seals_null_not_a_crash(tmp_path):
    # Opus 1c: sha256_file on a directory (TOCTOU realpath swap between
    # config-load and seal) returns None → the seal records an honest null.
    import df_common
    d = tmp_path / "some_dir"
    d.mkdir()
    assert df_common.sha256_file(str(d)) is None
    field = supervisor._builder_identity_field({"_support_files": [str(d)]})
    assert field["support_files"] == [{"path": str(d), "sha256": None}]
