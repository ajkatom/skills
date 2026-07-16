"""M17 Task 3: the enterprise tier -- kernel-locked egress-to-proxy + seccomp +
config composition + the supervisor's split-custody CONVERGED gate.

Enterprise is fail-closed composition on top of hardened: assurance:
"enterprise" REQUIRES custody (Task 1), credential_proxy.enabled:true (Task
2), audit.sink.required:true (M13), builder_confinement.required:true (M14),
and signed audit -- any missing/weakened guarantee is a ConfigError naming
it. The supervisor's custody gate runs at the CONVERGED point (after the
final exam + M9 security gates, like M9's own gates): NOT satisfied -> a
terminal CUSTODY_PENDING (exit 3, qualified False); satisfied -> qualified
true CONVERGED. Because approvers sign the manifest AFTER it exists, this is
a genuine TWO-PHASE ship -- covered here via `_custody_gate` unit tests
(satisfied/unsatisfied against real ed25519 signatures over the exact preview
bytes) AND a full run -> CUSTODY_PENDING -> sign the real sealed manifest ->
`verify-custody` flips to SATISFIED integration test.

The live egress/seccomp probe (`df_container.probe_enterprise_egress`) is
skipif no docker, mirroring test_container.py/test_linux_harness.py.
"""
import json
import os
import subprocess
import sys

import pytest

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

    def available(self):
        return True

    def wrap_prefix(self, deny_root, workspace):
        return []


def _patch_enterprise_probes(monkeypatch, os_ok=True, dk_ok=True):
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend", lambda: _FakeOSBackend())
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: os_ok)
    monkeypatch.setattr(supervisor.df_container, "docker_available", lambda: dk_ok)
    monkeypatch.setattr(supervisor.df_container, "probe_container", lambda *a, **k: dk_ok)


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
# _custody_gate — direct unit coverage of the CONVERGED-point gate, using
# REAL ed25519 signatures over the REAL preview bytes it checks against.
# ---------------------------------------------------------------------------

def _custody_test_setup(tmp_path, threshold=2):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    cr = tmp_path / "control"
    cr.mkdir(parents=True)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "journal.jsonl").write_text('{"ts":"x","state":"INIT","data":{}}\n', encoding="utf-8")
    cfg = {"_custody": {"approvers": approvers, "threshold": threshold}, "_control_root": str(cr)}
    mf_candidate = {"invocation": "run-abc", "outcome": "COMPLETE_QUALIFIED", "iterations": 1}
    finished_ts = "2026-01-01T00:00:00Z"
    return cr, run_dir, cfg, mf_candidate, finished_ts, (priv_a, pub_a), (priv_b, pub_b), (_priv_c, pub_c)


def test_custody_gate_satisfied_with_two_of_three_real_signatures(tmp_path):
    cr, run_dir, cfg, mf_candidate, finished_ts, a, b, _c = _custody_test_setup(tmp_path, threshold=2)
    preview = supervisor._manifest_preview_bytes(str(run_dir), mf_candidate, None, finished_ts, None)
    sig_a = df_custody.sign_manifest(a[0], preview)
    sig_b = df_custody.sign_manifest(b[0], preview)
    (cr / "custody-signatures.json").write_text(json.dumps([
        {"approver": a[1], "sig": sig_a}, {"approver": b[1], "sig": sig_b},
    ]), encoding="utf-8")
    journal = _FakeJournal()
    satisfied, field = supervisor._custody_gate(
        cfg, journal, str(run_dir), mf_candidate, finished_ts, None, None)
    assert satisfied is True
    assert field == {
        "required_k": 2, "approvers": 3, "signatures": 2,
        "satisfied": True, "reason": field["reason"],
    }
    assert "2" in field["reason"]


def test_custody_gate_not_satisfied_with_only_one_of_two_required(tmp_path):
    cr, run_dir, cfg, mf_candidate, finished_ts, a, _b, _c = _custody_test_setup(tmp_path, threshold=2)
    preview = supervisor._manifest_preview_bytes(str(run_dir), mf_candidate, None, finished_ts, None)
    sig_a = df_custody.sign_manifest(a[0], preview)
    (cr / "custody-signatures.json").write_text(json.dumps([
        {"approver": a[1], "sig": sig_a},
    ]), encoding="utf-8")
    journal = _FakeJournal()
    satisfied, field = supervisor._custody_gate(
        cfg, journal, str(run_dir), mf_candidate, finished_ts, None, None)
    assert satisfied is False
    assert field["signatures"] == 1
    assert field["required_k"] == 2


def test_custody_gate_missing_signatures_file_not_satisfied(tmp_path):
    cr, run_dir, cfg, mf_candidate, finished_ts, *_rest = _custody_test_setup(tmp_path, threshold=2)
    journal = _FakeJournal()
    satisfied, field = supervisor._custody_gate(
        cfg, journal, str(run_dir), mf_candidate, finished_ts, None, None)
    assert satisfied is False
    assert field["signatures"] == 0
    assert "not found" in field["reason"]


def test_custody_gate_sig_over_wrong_bytes_not_counted(tmp_path):
    # A signature over a DIFFERENT manifest preview (e.g. stale, or for a
    # different run) must not satisfy custody for THIS run.
    cr, run_dir, cfg, mf_candidate, finished_ts, a, b, _c = _custody_test_setup(tmp_path, threshold=2)
    other_preview = supervisor._manifest_preview_bytes(
        str(run_dir), {"invocation": "other-run"}, None, finished_ts, None)
    sig_a = df_custody.sign_manifest(a[0], other_preview)
    correct_preview = supervisor._manifest_preview_bytes(
        str(run_dir), mf_candidate, None, finished_ts, None)
    sig_b = df_custody.sign_manifest(b[0], correct_preview)
    (cr / "custody-signatures.json").write_text(json.dumps([
        {"approver": a[1], "sig": sig_a}, {"approver": b[1], "sig": sig_b},
    ]), encoding="utf-8")
    journal = _FakeJournal()
    satisfied, field = supervisor._custody_gate(
        cfg, journal, str(run_dir), mf_candidate, finished_ts, None, None)
    assert satisfied is False
    # `signatures` is the raw entry count (2 -- both entries are present in
    # custody-signatures.json); the VALID-distinct count (only sig_b, since
    # sig_a is over the wrong bytes) is reflected in `reason`, not this
    # field -- df_custody.verify_custody's "m/k distinct approver
    # signatures" reason string.
    assert field["signatures"] == 2
    assert "1/2" in field["reason"]


# ---------------------------------------------------------------------------
# Full supervisor.run() integration — monkeypatched invoke_adapter + resolve
# probes, so no docker is needed. Proves the CONVERGED-point wiring: manifest
# carries custody/proxy/enterprise_egress, CUSTODY_PENDING is exit 3 /
# qualified False, and the two-phase sign-after-run workflow really flips
# `verify-custody` to SATISFIED once real signatures cover the sealed bytes.
# ---------------------------------------------------------------------------

def _enterprise_control(tmp_path, approvers, threshold=2, checkpoint="auto"):
    cr = setup_control(tmp_path, FAKE, checkpoint=checkpoint)
    cfg = json.loads((cr / "config.json").read_text())
    cfg.update(_base_enterprise(approvers=approvers, threshold=threshold))
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cr


def _fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                 exec_prefix=None, env_extra=None, env_full=None, confine=False):
    assert role == "builder"
    with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
        f.write(GREET_PY)
    return {"adapter_protocol": "0.1", "status": "ok"}, None


def test_enterprise_run_custody_unsatisfied_is_custody_pending_exit_3(tmp_path, monkeypatch):
    approvers = [_approver()[1] for _ in range(3)]
    cr = _enterprise_control(tmp_path, approvers, threshold=2)
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
    assert m["custody"]["signatures"] == 0
    assert m["proxy"] == {"enabled": True, "allowlist": ["api.example.test"]}
    assert m["enterprise_egress"] == {"locked": True, "probe": "unverified"}
    assert m["container"]["image"] == df_container.DEFAULT_IMAGE
    assert m["sandbox_backend"] == df_container.ENTERPRISE_BACKEND_NAME


def test_enterprise_two_phase_ship_sign_after_run_flips_to_satisfied(tmp_path, monkeypatch):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    cr = _enterprise_control(tmp_path, approvers, threshold=2)
    _patch_enterprise_probes(monkeypatch)
    monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 3

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest_bytes = (run_dir / "manifest.json").read_bytes()

    # ONE signature (k=2 required): must NOT qualify -- the single-operator-
    # proof property holds even across the two-phase boundary.
    sig_a = df_custody.sign_manifest(priv_a, manifest_bytes)
    (cr / "custody-signatures.json").write_text(
        json.dumps([{"approver": pub_a, "sig": sig_a}]), encoding="utf-8")
    assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False

    # TWO distinct signatures: satisfied.
    sig_b = df_custody.sign_manifest(priv_b, manifest_bytes)
    (cr / "custody-signatures.json").write_text(json.dumps([
        {"approver": pub_a, "sig": sig_a}, {"approver": pub_b, "sig": sig_b},
    ]), encoding="utf-8")
    assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is True


def test_verify_custody_cmd_missing_manifest_not_found(tmp_path):
    cr = tmp_path / "control"
    cr.mkdir()
    run_dir = tmp_path / "nope"
    assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False


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
    proxy_httpd, proxy_port = df_proxy.serve(["127.0.0.1"], "DF_ENTERPRISE_LIVE_TEST_TOKEN")
    try:
        proxy_endpoint = f"host.docker.internal:{proxy_port}"
        allowed_url = f"http://127.0.0.1:{upstream_port}/"
        ok, detail = df_container.probe_enterprise_egress(
            enterprise_probe_image, proxy_endpoint, allowed_url, "1.1.1.1")
        assert ok is True, detail
        assert detail.get("allowed_reachable") is True, detail
        assert detail.get("denied_blocked") is True, detail
        assert detail.get("iptables_blocked") is True, detail
    finally:
        proxy_httpd.shutdown()
        proxy_httpd.server_close()
        upstream_httpd.shutdown()
        upstream_httpd.server_close()
