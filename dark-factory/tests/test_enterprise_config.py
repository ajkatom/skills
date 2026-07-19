"""M17 Task 3: the enterprise tier -- kernel-locked egress-to-proxy + seccomp +
config composition + the supervisor's split-custody CONVERGED gate.

Enterprise is fail-closed composition on top of hardened: assurance:
"enterprise" REQUIRES custody (Task 1), credential_proxy.enabled:true (Task
2), audit.sink.required:true (M13), builder_confinement.required:true (M14),
and signed audit -- any missing/weakened guarantee is a ConfigError naming
it. Split custody is a GENUINE two-phase ship: an enterprise run with required
custody ALWAYS terminates CUSTODY_PENDING (qualified False) — the sealed
manifest.json is the IMMUTABLE, signable artifact and never self-qualifies
(no single process/operator can ship). Approvers then sign those exact bytes;
`df-custody attach` verifies >=K distinct signatures over the sealed manifest
and, only then, writes a SEPARATE `custody_attestation.json` (+ anchors it in
the M13 hash chain); `verify-custody` re-verifies the attestation binds the
CURRENT manifest bytes, so a one-byte manifest edit or a forged attestation
fails. Covered by a full run -> 1-of-3 attach (not satisfied) -> 2-of-3
attach (attestation) -> verify QUALIFIED -> tamper -> FAILS e2e over real
supervisor.run + real ed25519 signatures.

The live egress/seccomp probe (`df_container.probe_enterprise_egress`) is
skipif no docker, mirroring test_container.py/test_linux_harness.py.
"""
import contextlib
import json
import os
import subprocess
import sys
import urllib.request

import pytest

import df_audit_receiver
import df_config
import df_container
import df_custody
import df_proxy
import supervisor
from test_config import write_config
from test_supervisor import FAKE, setup_control

# enterprise validates roles.builder.adapter the same way hardened does (its
# directory is bind-mounted ro into the builder container): an absolute
# EXISTING file whose directory is disjoint from the control root.
VALID_ADAPTER = sys.executable

GREET_PY = (
    "import sys\n"
    "if len(sys.argv) != 2:\n"
    "    print('usage: greet.py <name>', file=sys.stderr); sys.exit(2)\n"
    "print(f'Hello, {sys.argv[1]}!')\n"
)


def _approver():
    priv, pub = df_custody.generate_keypair()
    return priv, pub


def _base_enterprise(approvers=None, threshold=2, **extra):
    if approvers is None:
        approvers = [_approver()[1] for _ in range(3)]
    overrides = {
        "assurance": "enterprise",
        "roles": {"builder": {"adapter": VALID_ADAPTER, "timeout_s": 60}},
        "custody": {"approvers": approvers, "threshold": threshold},
        "credential_proxy": {
            "enabled": True, "allowlist": ["api.example.test"],
            "token_env": "DF_ENTERPRISE_TEST_TOKEN",
        },
        "audit": {"sink": {"kind": "http-append", "url": "http://127.0.0.1:8080",
                           "required": True}},
        "builder_confinement": {"enabled": True, "required": True},
    }
    overrides.update(extra)
    return overrides


# ---------------------------------------------------------------------------
# supported_tiers.json registration
# ---------------------------------------------------------------------------

def test_enterprise_registered_qualified_container_enterprise_backend():
    tiers = df_config.load_supported_tiers()["tiers"]
    assert "enterprise" in tiers
    assert tiers["enterprise"]["qualified"] is True
    assert tiers["enterprise"]["backend"] == "container-enterprise"


# ---------------------------------------------------------------------------
# config composition: enterprise REQUIRES each guarantee, fail-closed
# ---------------------------------------------------------------------------

def test_enterprise_requires_custody(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise()
    del overrides["custody"]
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="custody"):
        df_config.load_config(str(cr))


def test_enterprise_requires_credential_proxy_enabled(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise(credential_proxy={"enabled": False})
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="credential_proxy"):
        df_config.load_config(str(cr))


def test_enterprise_requires_credential_proxy_absent_rejected(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise()
    del overrides["credential_proxy"]
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="credential_proxy"):
        df_config.load_config(str(cr))


def test_enterprise_requires_sink_required_true(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise(audit={
        "sink": {"kind": "http-append", "url": "http://127.0.0.1:8080", "required": False}
    })
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="sink"):
        df_config.load_config(str(cr))


def test_enterprise_requires_sink_configured_not_kind_none(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise(audit={"sink": {"kind": "none"}})
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="sink"):
        df_config.load_config(str(cr))


def test_enterprise_requires_builder_confinement_required_true(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise(builder_confinement={"enabled": True, "required": False})
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="confinement"):
        df_config.load_config(str(cr))


def test_enterprise_requires_builder_confinement_present(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise()
    del overrides["builder_confinement"]
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="confinement"):
        df_config.load_config(str(cr))


def test_enterprise_confinement_required_true_but_enabled_false_rejected(tmp_path):
    # RA-04 (the audited High): {enabled:false, required:true} previously PASSED
    # enterprise validation (the gate only checked `required`) while runtime
    # confinement was OFF — an enterprise run that CLAIMS mandatory confinement
    # yet runs the builder unconfined. Now rejected: the ANY-tier coherence
    # check fires first (required-without-enabled is incoherent), and the
    # enterprise gate additionally names `enabled` explicitly. Either way,
    # fail-closed at load.
    cr = tmp_path / "control"
    overrides = _base_enterprise(builder_confinement={"enabled": False, "required": True})
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="confinement"):
        df_config.load_config(str(cr))


def test_enterprise_confinement_enabled_true_required_true_still_valid(tmp_path):
    # Superset guard: the canonical enterprise confinement block
    # {enabled:true, required:true} still validates unchanged.
    cr = tmp_path / "control"
    approvers = sorted(_approver()[1] for _ in range(3))
    overrides = _base_enterprise(
        approvers=approvers, threshold=2,
        builder_confinement={"enabled": True, "required": True})
    write_config(cr, **overrides)
    cfg = df_config.load_config(str(cr))
    assert cfg["_confine"] == {"enabled": True, "required": True, "profile": "standard"}


def test_enterprise_requires_signed_audit(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise(audit={
        "signing": False,
        "sink": {"kind": "http-append", "url": "http://127.0.0.1:8080", "required": True},
    })
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="signed audit"):
        df_config.load_config(str(cr))


def test_enterprise_well_formed_validates_and_injects(tmp_path):
    cr = tmp_path / "control"
    approvers = sorted(_approver()[1] for _ in range(3))
    overrides = _base_enterprise(approvers=approvers, threshold=2)
    write_config(cr, **overrides)
    cfg = df_config.load_config(str(cr))
    assert cfg["assurance"] == "enterprise"
    assert cfg["_qualified"] is True
    assert cfg["_custody"] == {"approvers": approvers, "threshold": 2}
    assert cfg["_proxy"]["enabled"] is True
    assert cfg["_proxy"]["allowlist"] == ["api.example.test"]
    assert cfg["_enterprise"] == {"seccomp": df_container.DEFAULT_SECCOMP_PATH}
    assert os.path.isfile(cfg["_enterprise"]["seccomp"])
    assert cfg["_audit"]["signing"] is True
    assert cfg["_audit"]["sink"]["required"] is True
    assert cfg["_confine"]["required"] is True


def test_enterprise_hardened_block_also_accepted(tmp_path):
    # The SAME `hardened` block configures cfg["_container"] at enterprise
    # (enterprise's container path IS the hardened container path).
    cr = tmp_path / "control"
    overrides = _base_enterprise(hardened={"memory": "512m", "pids": 64})
    write_config(cr, **overrides)
    cfg = df_config.load_config(str(cr))
    assert cfg["_container"]["memory"] == "512m"
    assert cfg["_container"]["pids"] == 64


def test_non_enterprise_tier_gets_none_enterprise_field(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)  # default cooperative
    cfg = df_config.load_config(str(cr))
    assert cfg["_enterprise"] is None


# ---------------------------------------------------------------------------
# M17 Task-1-review fixes, re-verified here per the Task 3 brief:
#   (1) verify_custody k < 1 is a defensive "invalid threshold", never
#       satisfiable regardless of how many valid sigs are present;
#   (2) approver hex is canonicalized to lowercase, both in df_config's
#       custody validation AND in verify_custody's own matching, so case
#       can never cause a fail-closed mismatch.
# ---------------------------------------------------------------------------

def test_verify_custody_k_zero_never_satisfied():
    priv, pub = _approver()
    manifest = b"some-manifest-bytes"
    sig = df_custody.sign_manifest(priv, manifest)
    satisfied, reason = df_custody.verify_custody(
        manifest, [{"approver": pub, "sig": sig}], [pub], 0)
    assert satisfied is False
    assert "invalid threshold" in reason


def test_verify_custody_k_negative_never_satisfied():
    satisfied, reason = df_custody.verify_custody(b"x", [], ["a" * 64], -1)
    assert satisfied is False
    assert "invalid threshold" in reason


def test_verify_custody_case_insensitive_approver_matches_uppercase_config():
    priv, pub = _approver()
    manifest = b"payload-bytes"
    sig = df_custody.sign_manifest(priv, manifest)
    # approvers list holds the UPPERCASE form; the signature entry's
    # "approver" is the (naturally lowercase) hex sign_manifest/generate_
    # keypair produce -- these must still match.
    satisfied, _reason = df_custody.verify_custody(
        manifest, [{"approver": pub, "sig": sig}], [pub.upper()], 1)
    assert satisfied is True


def test_verify_custody_case_insensitive_signature_entry_uppercase():
    priv, pub = _approver()
    manifest = b"payload-bytes-2"
    sig = df_custody.sign_manifest(priv, manifest)
    # the SIGNATURE ENTRY's approver field is uppercase; approvers list is
    # the natural lowercase form.
    satisfied, _reason = df_custody.verify_custody(
        manifest, [{"approver": pub.upper(), "sig": sig}], [pub], 1)
    assert satisfied is True


def test_df_config_custody_approvers_canonicalized_to_lowercase(tmp_path):
    _priv, pub = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub.upper()], "threshold": 1})
    cfg = df_config.load_config(str(cr))
    assert cfg["_custody"]["approvers"] == [pub.lower()]


def test_df_config_custody_case_variant_duplicate_rejected(tmp_path):
    _priv, pub = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub.lower(), pub.upper()], "threshold": 1})
    with pytest.raises(df_config.ConfigError, match="unique|duplicate"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# supervisor: resolve_isolation / builder-wiring probes, fully injected (no
# docker needed for the custody-gate logic itself)
# ---------------------------------------------------------------------------

class _FakeJournal:
    def __init__(self):
        self.entries = []

    def write(self, state, **data):
        self.entries.append((state, data))


class _FakeOSBackend:
    name = "fake-os-backend"
    # M44 RA-03: a properly-isolated enterprise run confines the candidate with
    # a default-deny profile (host_isolation qualifies). The fake backend
    # advertises that capability so these integration runs model a REAL
    # enterprise posture — a host-isolation-LIMITED run is now custody-refused,
    # so the happy path must actually be host-isolated.
    supports_default_deny = True

    def available(self):
        return True

    def wrap_prefix(self, deny_root, workspace, network="unrestricted"):
        return []

    def wrap_candidate_prefix(self, deny_root, workspace, network="unrestricted",
                              allowed_loopback_ports=None, scratch_dirs=()):
        return []


def _patch_enterprise_probes(monkeypatch, os_ok=True, dk_ok=True, seccomp_ok=True,
                             egress_ok=True):
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend", lambda: _FakeOSBackend())
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: os_ok)
    # M44 RA-03: model a candidate default-deny confinement that PASSES, so the
    # enterprise run seals with host_isolation.qualified True — the honest
    # posture a properly-isolated enterprise run has (and the one a custody
    # attestation is allowed to qualify).
    monkeypatch.setattr(supervisor.df_sandbox, "probe_candidate_confinement",
                        lambda *a, **k: (True, {"mode": "default_deny", "residuals": []}))
    monkeypatch.setattr(supervisor.df_container, "docker_available", lambda: dk_ok)
    monkeypatch.setattr(supervisor.df_container, "probe_container", lambda *a, **k: dk_ok)
    # M22 Task 1: the enterprise resolve now ALSO live-probes the seccomp
    # profile (df_container.probe_seccomp) before accepting enterprise —
    # patched here (like docker_available/probe_container above) so these
    # config-composition/custody-gate tests stay fast and docker-free; the
    # real live probe is exercised separately in test_seccomp_probe.py.
    monkeypatch.setattr(supervisor.df_container, "probe_seccomp", lambda *a, **k: seccomp_ok)
    # DF-05/M32: _run_loop now ALSO live-probes the egress transport+lock
    # (df_container.probe_enterprise_egress, via supervisor._verify_
    # enterprise_egress) once per enterprise run, before the first builder
    # call — patched here for the same reason as probe_seccomp above (fast,
    # docker-free config/custody-gate tests); the real live probe is
    # exercised separately by test_probe_enterprise_egress_live below.
    monkeypatch.setattr(
        supervisor.df_container, "probe_enterprise_egress",
        lambda *a, **k: (egress_ok, {"stub": True, "egress_ok": egress_ok}))


def test_resolve_isolation_enterprise_both_ok(tmp_path, monkeypatch):
    _patch_enterprise_probes(monkeypatch)
    j = _FakeJournal()
    cfg = {
        "assurance": "enterprise",
        "_container": {"image": "img", "network": "none", "memory": "2g", "pids": 256},
        "_enterprise": {"seccomp": df_container.DEFAULT_SECCOMP_PATH},
    }
    result = supervisor.resolve_isolation(cfg, str(tmp_path / "cr"), str(tmp_path / "ws"), j, False)
    assert result == ("enterprise", [], df_container.ENTERPRISE_BACKEND_NAME, True)
    assert not j.entries


def test_resolve_isolation_enterprise_bad_seccomp_path_downgrades_to_hardened(tmp_path, monkeypatch):
    _patch_enterprise_probes(monkeypatch)
    j = _FakeJournal()
    cfg = {
        "assurance": "enterprise",
        "_container": {"image": "img", "network": "none", "memory": "2g", "pids": 256},
        "_enterprise": {"seccomp": str(tmp_path / "does-not-exist.json")},
    }
    eff, prefix, backend, probe_passed = supervisor.resolve_isolation(
        cfg, str(tmp_path / "cr"), str(tmp_path / "ws"), j, True)
    assert eff == "hardened"
    assert probe_passed is True
    assert any(s == "DOWNGRADE" and d.get("effective") == "hardened" for s, d in j.entries)


def test_resolve_isolation_enterprise_bad_seccomp_no_downgrade_raises(tmp_path, monkeypatch):
    import df_sandbox
    _patch_enterprise_probes(monkeypatch)
    j = _FakeJournal()
    cfg = {
        "assurance": "enterprise",
        "_container": {"image": "img", "network": "none", "memory": "2g", "pids": 256},
        "_enterprise": {"seccomp": str(tmp_path / "does-not-exist.json")},
    }
    with pytest.raises(df_sandbox.SandboxError, match="enterprise"):
        supervisor.resolve_isolation(cfg, str(tmp_path / "cr"), str(tmp_path / "ws"), j, False)


# ---------------------------------------------------------------------------
# Full supervisor.run() integration — monkeypatched invoke_adapter + resolve
# probes, so no docker is needed. Proves the redesigned, genuinely-reachable
# two-phase ship: an enterprise run ALWAYS seals CUSTODY_PENDING (the manifest
# is the immutable signable artifact, never self-qualifying); attach over the
# sealed bytes writes a SEPARATE custody_attestation.json only at K-of-N; and
# verify-custody is tamper-evident (a one-byte manifest edit breaks it).
# ---------------------------------------------------------------------------

def _enterprise_control(tmp_path, approvers, threshold=2, checkpoint="auto", sink_url=None):
    cr = setup_control(tmp_path, FAKE, checkpoint=checkpoint)
    cfg = json.loads((cr / "config.json").read_text())
    overrides = _base_enterprise(approvers=approvers, threshold=threshold)
    if sink_url is not None:
        overrides["audit"] = {
            "sink": {"kind": "http-append", "url": sink_url, "required": True}}
    cfg.update(overrides)
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cr


@contextlib.contextmanager
def _sink_receiver(tmp_path):
    """A live M13 reference receiver (http-append). Enterprise mandates a
    REQUIRED sink, and attach now pushes the qualification off-box, so any
    test that reaches attach's success path needs a reachable sink."""
    store = tmp_path / "sink-store"
    httpd, port = df_audit_receiver.serve(str(store), port=0)
    try:
        yield f"http://127.0.0.1:{port}", store
    finally:
        httpd.shutdown()
        httpd.server_close()


def _fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                 exec_prefix=None, env_extra=None, env_full=None, confine=False):
    assert role == "builder"
    # Enterprise passes NO credential env into the container at all -- the
    # proxy is the sole credential path.
    assert env_extra is None
    with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
        f.write(GREET_PY)
    return {"adapter_protocol": "0.1", "status": "ok"}, None


def test_enterprise_run_always_custody_pending_exit_3(tmp_path, monkeypatch):
    approvers = [_approver()[1] for _ in range(3)]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

        rc = supervisor.run(str(cr), None)
        assert rc == 3

        run_id = os.listdir(cr / "runs")[0]
        m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
        assert m["outcome"] == "CUSTODY_PENDING"
        assert m["qualified"] is False
        assert m["custody"]["satisfied"] is False
        assert m["custody"]["required_k"] == 2
        assert m["custody"]["approvers"] == 3
        assert m["proxy"] == {"enabled": True, "allowlist": ["api.example.test"]}
        # DF-05/M32: the mandatory per-run egress probe (here, monkeypatched
        # via _patch_enterprise_probes -- egress_ok=True) ran and passed
        # BEFORE the (monkeypatched) builder call, so the manifest records a
        # genuinely per-run-verified result, not merely "configured".
        assert m["enterprise_egress"]["probed"] is True
        assert m["enterprise_egress"]["passed"] is True
        assert isinstance(m["enterprise_egress"]["policy_digest"], str)
        assert m["enterprise_egress"]["policy_digest"]
        assert "checked_at" in m["enterprise_egress"]
        assert m["container"]["image"] == df_container.DEFAULT_IMAGE
        assert m["sandbox_backend"] == df_container.ENTERPRISE_BACKEND_NAME
        # No attestation exists yet — the manifest never self-qualifies.
        assert not (cr / "runs" / run_id / "custody_attestation.json").exists()
        assert supervisor.verify_custody_cmd(str(cr), str(cr / "runs" / run_id)) is False


def test_dep_cache_dir_enterprise_mounted_and_env_injected(tmp_path, monkeypatch):
    # §7.3 Task 3: identical dep-cache wiring on the enterprise branch
    # (build_enterprise_argv instead of build_argv) — the mount + four
    # non-secret env vars carry through even though enterprise otherwise
    # passes env=None for credentials (the credential_proxy is the sole
    # credential path; dep-cache env is NOT a credential, so it's exempt).
    approvers = [_approver()[1] for _ in range(3)]
    dep_cache = tmp_path / "depcache"
    (dep_cache / "pypi").mkdir(parents=True)
    (dep_cache / "npm-cache").mkdir(parents=True)
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        cfg_dict = json.loads((cr / "config.json").read_text())
        cfg_dict["hardened"] = {"dep_cache_dir": str(dep_cache)}
        (cr / "config.json").write_text(json.dumps(cfg_dict), encoding="utf-8")

        _patch_enterprise_probes(monkeypatch)

        captured = []

        def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                        exec_prefix=None, env_extra=None, env_full=None, confine=False):
            assert env_extra is None  # unchanged: creds still never cross via env_extra
            captured.append(list(exec_prefix) if exec_prefix else [])
            with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
                f.write(GREET_PY)
            return {"adapter_protocol": "0.1", "status": "ok"}, None

        monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

        rc = supervisor.run(str(cr), None)
        assert rc == 3  # enterprise always seals CUSTODY_PENDING; unrelated to dep-cache
        assert captured, "builder invoke_adapter was never called"

        argv = captured[0]
        dep_cache_real = os.path.realpath(str(dep_cache))
        v_specs = [argv[i + 1] for i, x in enumerate(argv) if x == "-v"]
        assert any(spec == f"{dep_cache_real}:{dep_cache_real}:ro" for spec in v_specs), v_specs

        e_pairs = {argv[i + 1] for i, x in enumerate(argv) if x == "-e"}
        assert "PIP_NO_INDEX=1" in e_pairs
        assert f"PIP_FIND_LINKS={os.path.join(dep_cache_real, 'pypi')}" in e_pairs
        assert f"npm_config_cache={os.path.join(dep_cache_real, 'npm-cache')}" in e_pairs
        assert "npm_config_offline=true" in e_pairs

        run_id = os.listdir(cr / "runs")[0]
        m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
        assert m["container"]["dep_cache_dir"] == dep_cache_real


def test_enterprise_two_phase_attach_and_tamper_evidence(tmp_path, monkeypatch):
    """THE end-to-end contract: real supervisor.run + real ed25519 sigs.
    run -> CUSTODY_PENDING; 1-of-3 attach -> not satisfied (exit 3, no
    attestation); 2-of-3 attach -> attestation written + verify-custody
    QUALIFIED; then mutate manifest.json one byte -> verify-custody FAILS.
    """
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

        assert supervisor.run(str(cr), None) == 3
        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        manifest_path = run_dir / "manifest.json"
        manifest_bytes = manifest_path.read_bytes()

        # --- Phase 2a: ONE signature (k=2) -> attach NOT satisfied, exit 3, no attestation.
        sig_a = df_custody.sign_manifest(priv_a, manifest_bytes)
        (cr / "custody-signatures.json").write_text(
            json.dumps([{"approver": pub_a, "sig": sig_a}]), encoding="utf-8")
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 3
        assert not (run_dir / "custody_attestation.json").exists()
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False

        # --- Phase 2b: TWO distinct signatures -> attach writes attestation, exit 0.
        sig_b = df_custody.sign_manifest(priv_b, manifest_bytes)
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": pub_a, "sig": sig_a}, {"approver": pub_b, "sig": sig_b},
        ]), encoding="utf-8")
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0
        att = json.loads((run_dir / "custody_attestation.json").read_text())
        assert att["qualified"] is True
        assert att["threshold"] == 2
        assert sorted(att["approvers_satisfied"]) == sorted([pub_a.lower(), pub_b.lower()])
        assert len(att["signatures"]) == 2
        # The manifest itself is UNCHANGED — still CUSTODY_PENDING (immutable).
        assert json.loads(manifest_path.read_text())["outcome"] == "CUSTODY_PENDING"
        # verify-custody now confirms QUALIFIED over the sealed bytes.
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is True

        # --- Tamper evidence: flip ONE byte of manifest.json -> verify-custody FAILS.
        corrupted = bytearray(manifest_bytes)
        corrupted[-5] = corrupted[-5] ^ 0x01
        manifest_path.write_bytes(bytes(corrupted))
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False


def test_enterprise_attach_appends_to_audit_chain_and_pushes_off_box(tmp_path, monkeypatch):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

        assert supervisor.run(str(cr), None) == 3
        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        manifest_bytes = (run_dir / "manifest.json").read_bytes()

        chain_before = (cr / "audit-chain.jsonl").read_text().count("\n")
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
            {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
        ]), encoding="utf-8")
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0
        chain_after = (cr / "audit-chain.jsonl").read_text().count("\n")
        assert chain_after == chain_before + 1  # the attestation was anchored

        # Important fix: the qualification event is pushed OFF-BOX (enterprise
        # mandates sink.required). A receipt sidecar is written, and the
        # receiver actually holds the exact attestation bytes.
        assert (run_dir / "custody_sink_receipt.json").exists()
        att_text = (run_dir / "custody_attestation.json").read_text()
        key = run_id + ".custody"
        with urllib.request.urlopen(f"{sink_url}/audit/{key}", timeout=5) as resp:
            stored = resp.read().decode("utf-8")
        assert stored == att_text


def test_enterprise_attach_required_sink_down_fails_closed(tmp_path, monkeypatch):
    # A REQUIRED sink that is unreachable makes attach fail closed (exit 3):
    # qualification must be recorded off-box or it does not count.
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    # A port that nothing is listening on.
    cr = _enterprise_control(tmp_path, approvers, threshold=2,
                             sink_url="http://127.0.0.1:9")
    _patch_enterprise_probes(monkeypatch)
    monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

    assert supervisor.run(str(cr), None) == 3
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest_bytes = (run_dir / "manifest.json").read_bytes()
    (cr / "custody-signatures.json").write_text(json.dumps([
        {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
        {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
    ]), encoding="utf-8")
    # Custody IS satisfied, but the required sink push fails -> exit 3.
    assert supervisor.attach_custody(str(cr), str(run_dir)) == 3


def test_enterprise_config_mutation_after_run_refuses_attach_and_verify(tmp_path, monkeypatch):
    """The Critical bypass: an operator with control-root write access edits
    config.json's custody block to {rogue_key, threshold:1} AFTER a legit
    threshold:2 run, self-signs, and tries to self-qualify. Binding the
    policy to the manifest's sealed config_sha256 makes attach AND
    verify-custody fail closed."""
    priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

        assert supervisor.run(str(cr), None) == 3
        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        manifest_bytes = (run_dir / "manifest.json").read_bytes()
        # sanity: sealed policy is required_k 2
        assert json.loads(manifest_bytes)["custody"]["required_k"] == 2

        # Attacker rewrites config.json: threshold 1, their OWN key.
        rogue_priv, rogue_pub = _approver()
        cfg = json.loads((cr / "config.json").read_text())
        cfg["custody"] = {"approvers": [rogue_pub], "threshold": 1}
        (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        (cr / "custody-signatures.json").write_text(json.dumps([
            {"approver": rogue_pub, "sig": df_custody.sign_manifest(rogue_priv, manifest_bytes)},
        ]), encoding="utf-8")

        # attach REFUSES (config_sha256 mismatch) — no attestation.
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 3
        assert not (run_dir / "custody_attestation.json").exists()
        # verify-custody REFUSES too.
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False


def test_verify_custody_rejects_forged_attestation(tmp_path, monkeypatch):
    """Even a hand-written custody_attestation.json (bypassing attach) with a
    self-declared threshold:1 + rogue approver is REJECTED: verify-custody
    re-derives approvers/threshold from the (unchanged) config, never trusting
    the attestation's own claimed values."""
    priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

        assert supervisor.run(str(cr), None) == 3
        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        manifest_bytes = (run_dir / "manifest.json").read_bytes()
        manifest_sha = (run_dir / "manifest.sha256").read_text().strip()

        rogue_priv, rogue_pub = _approver()
        forged = {
            "attestation_version": "0.1",
            "manifest_sha256": manifest_sha,   # correct sha -> binding check passes
            "threshold": 1,                    # self-declared, must be IGNORED
            "approvers_satisfied": [rogue_pub],
            "signatures": [
                {"approver": rogue_pub, "sig": df_custody.sign_manifest(rogue_priv, manifest_bytes)}
            ],
            "qualified": True,
            "ts": "2026-01-01T00:00:00Z",
        }
        (run_dir / "custody_attestation.json").write_text(json.dumps(forged), encoding="utf-8")
        # config unchanged (config_sha256 matches), so the rejection is purely
        # from re-verifying against config approvers (rogue ∉ set) + threshold 2.
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False


def test_verify_custody_cmd_missing_manifest_not_found(tmp_path):
    cr = tmp_path / "control"
    cr.mkdir()
    run_dir = tmp_path / "nope"
    assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False


# ---------------------------------------------------------------------------
# df-custody sign CLI — produces a self-describing {approver,sig} entry that
# verifies over the exact file bytes.
# ---------------------------------------------------------------------------

def test_df_custody_sign_helper_roundtrip(tmp_path):
    priv, pub = _approver()
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b'{"invocation":"x","outcome":"CUSTODY_PENDING"}')
    # public_from_private derives the same pubkey the signer advertises.
    assert df_custody.public_from_private(priv) == pub
    sig = df_custody.sign_manifest(priv, manifest.read_bytes())
    assert df_custody.verify_one(pub, manifest.read_bytes(), sig) is True


# ---------------------------------------------------------------------------
# Token-collision guard (Important): credential_proxy.token_env must not also
# be listed in credentials.allowlist at enterprise.
# ---------------------------------------------------------------------------

def test_enterprise_token_env_in_credentials_allowlist_rejected(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise()
    overrides["credentials"] = {
        "source": "env",
        "allowlist": ["DF_ENTERPRISE_TEST_TOKEN", "SOME_OTHER_KEY"],
    }
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="token_env"):
        df_config.load_config(str(cr))


def test_enterprise_disjoint_credentials_allowlist_ok(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise()
    overrides["credentials"] = {"source": "env", "allowlist": ["SOME_OTHER_KEY"]}
    write_config(cr, **overrides)
    cfg = df_config.load_config(str(cr))  # token_env not in allowlist -> ok
    assert cfg["_proxy"]["token_env"] == "DF_ENTERPRISE_TEST_TOKEN"


# ---------------------------------------------------------------------------
# M30 (DF-03) hardening: the enterprise entrypoint clears NO_PROXY/no_proxy
# before exec'ing the builder -- an inherited NO_PROXY could make an
# HTTP(S)_PROXY-respecting client bypass the proxy and connect DIRECTLY,
# straight into the iptables default-deny-egress wall the same entrypoint
# just installed. Offline (rendered-script) check -- no docker required.
# ---------------------------------------------------------------------------

def test_enterprise_entrypoint_clears_no_proxy_before_exec():
    script = df_container.enterprise_entrypoint_script("proxyhost:12345")
    assert "unset NO_PROXY no_proxy" in script
    # Cleared BEFORE the builder is exec'd (and, for good measure, before
    # HTTP_PROXY is exported -- order doesn't matter functionally here since
    # unset/export target different names, but this keeps the script's
    # narrative order sane: clear the footgun, then set the real proxy vars).
    unset_pos = script.index("unset NO_PROXY no_proxy")
    export_pos = script.index("export HTTP_PROXY")
    exec_pos = script.index('exec setpriv')
    assert unset_pos < export_pos < exec_pos


# ---------------------------------------------------------------------------
# Live egress/seccomp probe — requires a real docker daemon, skipif absent.
# ---------------------------------------------------------------------------

DOCKER_LIVE = df_container.docker_available()

_ENTERPRISE_DOCKERFILE = """FROM python:3.12-alpine
RUN apk add --no-cache iptables util-linux
"""


@pytest.fixture(scope="session")
def enterprise_probe_image():
    if not DOCKER_LIVE:
        pytest.skip("docker daemon unavailable")
    proc = subprocess.run(
        ["docker", "build", "-q", "-"],
        input=_ENTERPRISE_DOCKERFILE, capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, f"enterprise probe image build failed: {proc.stderr}"
    image_id = proc.stdout.strip()
    assert image_id, "docker build -q produced no image id"
    return image_id


def _start_allowed_stub():
    """Minimal stub upstream (127.0.0.1, ephemeral port) the proxy forwards
    allowlisted requests to."""
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"df-enterprise-live-probe-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, format, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_probe_enterprise_egress_live(enterprise_probe_image, monkeypatch):
    """The live self-check: allowlisted-via-proxy reachable, direct-to-
    denied-host DENIED, and the child CANNOT re-add iptables rules (NET_ADMIN
    was dropped). Runs a real container on Docker Desktop's Linux VM."""
    monkeypatch.setenv("DF_ENTERPRISE_LIVE_TEST_TOKEN", "test-token-value")
    upstream_httpd, upstream_port = _start_allowed_stub()
    # M30 (DF-03): exact-origin allowlisting -- the stub binds an EPHEMERAL
    # port, so the allowlist entry must name it explicitly (a bare "127.0.0.1"
    # now only permits the two DEFAULT ports, 80/443). A capability token is
    # also mandatory now; the probe is given the SAME one so its in-container
    # request can present it.
    cap_token = "df-enterprise-live-probe-capability-token"
    proxy_httpd, proxy_port = df_proxy.serve(
        [f"127.0.0.1:{upstream_port}"], "DF_ENTERPRISE_LIVE_TEST_TOKEN",
        capability_token=cap_token,
    )
    try:
        proxy_endpoint = f"host.docker.internal:{proxy_port}"
        allowed_url = f"http://127.0.0.1:{upstream_port}/"
        ok, detail = df_container.probe_enterprise_egress(
            enterprise_probe_image, proxy_endpoint, allowed_url, "1.1.1.1",
            capability_token=cap_token)
        assert ok is True, detail
        assert detail.get("allowed_reachable") is True, detail
        assert detail.get("denied_blocked") is True, detail
        assert detail.get("iptables_blocked") is True, detail
    finally:
        proxy_httpd.shutdown()
        proxy_httpd.server_close()
        upstream_httpd.shutdown()
        upstream_httpd.server_close()
