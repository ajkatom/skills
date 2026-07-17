"""DF-05/M32: per-run enterprise egress verification + the deferred M30/DF-03
supervisor-wiring (DF_PROXY_DESCRIPTOR into the enterprise container for API
builder adapters).

Two coupled behaviors, both in supervisor.py's enterprise builder-call region:

1. Descriptor wiring (Part 1): when the enterprise builder is one of the two
   shipped API adapters (api_anthropic/api_openai), the run's real credential
   proxy is started with a per-run capability token + `provider=` (arming
   df_proxy's M30 method/path injection lock), and the enterprise container
   is given a `DF_PROXY_DESCRIPTOR` env var (endpoint/provider/target_base_url/
   capability_token) -- the ONLY channel that carries the capability token,
   which is NOT the provider secret (the real provider key is still only ever
   injected by the proxy, host-side, on its own leg). CLI builder adapters are
   unaffected (no descriptor).

2. Mandatory egress probe (Part 2): before the first builder call on an
   enterprise run, `_verify_enterprise_egress` runs the transport+lock probe
   deferred by resolve_isolation (it needs a running proxy). A failing probe
   refuses the run (EGRESS_PROBE_FAILED, exit 2, unqualified, builder never
   invoked). A passing probe's result (probed/passed/policy_digest) is
   recorded on the manifest's `enterprise_egress` field.

These tests monkeypatch df_container.probe_enterprise_egress (like
test_enterprise_config.py's _patch_enterprise_probes patches probe_seccomp)
so they stay fast and docker-free; a genuinely live, real-docker exercise of
probe_enterprise_egress already exists at
test_enterprise_config.py::test_probe_enterprise_egress_live, and
test_enterprise_config.py's own full-run tests (which do NOT further
monkeypatch probe_enterprise_egress beyond _patch_enterprise_probes's
default egress_ok=True stub) confirm the wiring end to end against whatever
real docker is available in this environment -- see that file's
_patch_enterprise_probes docstring note.
"""
import json
import os

import pytest

import df_config
import df_container
import df_proxy
import supervisor
from test_enterprise_config import (
    GREET_PY,
    _approver,
    _base_enterprise,
    _patch_enterprise_probes,
    _sink_receiver,
    VALID_ADAPTER,
)
from test_supervisor import FAKE, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.dirname(os.path.abspath(supervisor.__file__))
API_ANTHROPIC = os.path.join(SCRIPTS_DIR, "adapters", "api_anthropic")


def _api_enterprise_control(tmp_path, approvers, threshold=2, sink_url=None):
    """Like test_enterprise_config._enterprise_control, but with
    roles.builder.adapter set to the REAL api_anthropic adapter (needed so
    df_config's hardened/enterprise adapter validation -- an absolute,
    existing file whose directory is disjoint from the control root --
    passes) and a credential_proxy block coherent with it (df_config's M30
    Part C check requires header=="x-api-key" and "api.anthropic.com" in the
    allowlist for this adapter)."""
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    overrides = _base_enterprise(
        approvers=approvers, threshold=threshold,
        roles={"builder": {"adapter": API_ANTHROPIC, "timeout_s": 60}},
        credential_proxy={
            "enabled": True, "allowlist": ["api.anthropic.com"],
            "token_env": "DF_ENTERPRISE_TEST_TOKEN", "header": "x-api-key",
        },
    )
    if sink_url is not None:
        overrides["audit"] = {
            "sink": {"kind": "http-append", "url": sink_url, "required": True}}
    cfg.update(overrides)
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cr


def _e_pairs_from_argv(argv):
    return {argv[i + 1].split("=", 1)[0]: argv[i + 1].split("=", 1)[1]
            for i, x in enumerate(argv) if x == "-e" and "=" in argv[i + 1]}


# ---------------------------------------------------------------------------
# Part 1: DF_PROXY_DESCRIPTOR wiring for API builder adapters
# ---------------------------------------------------------------------------

def test_api_adapter_enterprise_run_wires_proxy_descriptor(tmp_path, monkeypatch):
    approvers = [_approver()[1] for _ in range(3)]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _api_enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch)

        # Spy on df_proxy.serve (still calling through to the real
        # implementation) so we can assert the RUN's real proxy -- not the
        # mandatory egress probe's own throwaway proxy -- was started with
        # provider="anthropic" and a real capability token.
        real_serve = df_proxy.serve
        serve_calls = []

        def spy_serve(*a, **k):
            httpd, port = real_serve(*a, **k)
            serve_calls.append((a, k, httpd.capability_token))
            return httpd, port

        monkeypatch.setattr(supervisor.df_proxy, "serve", spy_serve)

        captured_env = []

        def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                        exec_prefix=None, env_extra=None, env_full=None, confine=False):
            assert role == "builder"
            assert env_extra is None  # enterprise: no credential env via env_extra
            captured_env.append(_e_pairs_from_argv(list(exec_prefix) if exec_prefix else []))
            with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
                f.write(GREET_PY)
            return {"adapter_protocol": "0.1", "status": "ok"}, None

        monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

        rc = supervisor.run(str(cr), None)
        assert rc == 3  # enterprise always seals CUSTODY_PENDING

        # Exactly one serve() call armed the anthropic provider lock: the
        # run's real proxy. The egress probe's own throwaway proxy (Part 2)
        # never sets provider.
        real_proxy_calls = [c for c in serve_calls if c[1].get("provider") == "anthropic"]
        assert len(real_proxy_calls) == 1, serve_calls
        _, kwargs, real_cap_token = real_proxy_calls[0]
        assert kwargs["capability_token"] == real_cap_token
        assert real_cap_token and isinstance(real_cap_token, str)

        assert captured_env, "builder invoke_adapter was never called"
        env = captured_env[0]
        assert "DF_PROXY_DESCRIPTOR" in env
        descriptor = json.loads(env["DF_PROXY_DESCRIPTOR"])
        assert descriptor["provider"] == "anthropic"
        assert descriptor["target_base_url"] == "https://api.anthropic.com"
        assert descriptor["endpoint"].startswith("http://host.docker.internal:")
        assert descriptor["capability_token"] == real_cap_token

        # No provider secret, ever, in the container -- only the capability
        # token (a local-workload credential, not the provider key).
        assert "ANTHROPIC_API_KEY" not in env
        assert not any(k.startswith("ANTHROPIC") for k in env if k != "DF_PROXY_DESCRIPTOR")

        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        manifest_text = (run_dir / "manifest.json").read_text()
        journal_text = (run_dir / "journal.jsonl").read_text()
        # The capability token must never leak into the manifest or journal.
        assert real_cap_token not in manifest_text
        assert real_cap_token not in journal_text
        # But the journal DOES record that a descriptor was wired.
        assert "PROXY_DESCRIPTOR_WIRED" in journal_text


def test_cli_adapter_enterprise_run_gets_no_descriptor(tmp_path, monkeypatch):
    """Back-compat: a CLI builder adapter (VALID_ADAPTER == sys.executable,
    basename not api_anthropic/api_openai) gets NO DF_PROXY_DESCRIPTOR and no
    provider lock -- unchanged from pre-M32 behavior."""
    approvers = [_approver()[1] for _ in range(3)]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = setup_control(tmp_path, FAKE, checkpoint="auto")
        cfg = json.loads((cr / "config.json").read_text())
        overrides = _base_enterprise(approvers=approvers, threshold=2)
        overrides["audit"] = {
            "sink": {"kind": "http-append", "url": sink_url, "required": True}}
        cfg.update(overrides)
        (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

        _patch_enterprise_probes(monkeypatch)

        real_serve = df_proxy.serve
        serve_calls = []

        def spy_serve(*a, **k):
            httpd, port = real_serve(*a, **k)
            serve_calls.append(k)
            return httpd, port

        monkeypatch.setattr(supervisor.df_proxy, "serve", spy_serve)

        captured_env = []

        def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                        exec_prefix=None, env_extra=None, env_full=None, confine=False):
            captured_env.append(_e_pairs_from_argv(list(exec_prefix) if exec_prefix else []))
            with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
                f.write(GREET_PY)
            return {"adapter_protocol": "0.1", "status": "ok"}, None

        monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

        rc = supervisor.run(str(cr), None)
        assert rc == 3

        real_proxy_calls = [k for k in serve_calls if k.get("provider") is not None]
        assert not real_proxy_calls, serve_calls

        assert captured_env, "builder invoke_adapter was never called"
        assert "DF_PROXY_DESCRIPTOR" not in captured_env[0]


# ---------------------------------------------------------------------------
# Part 2: mandatory per-run egress probe, fail-closed
# ---------------------------------------------------------------------------

def test_egress_probe_runs_before_first_builder_call_and_passes(tmp_path, monkeypatch):
    approvers = [_approver()[1] for _ in range(3)]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _api_enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch, egress_ok=True)

        invoked = []

        def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                        exec_prefix=None, env_extra=None, env_full=None, confine=False):
            invoked.append(True)
            with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
                f.write(GREET_PY)
            return {"adapter_protocol": "0.1", "status": "ok"}, None

        monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

        rc = supervisor.run(str(cr), None)
        assert rc == 3
        assert invoked, "the builder should have been invoked once the probe passed"

        run_id = os.listdir(cr / "runs")[0]
        m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
        assert m["enterprise_egress"]["probed"] is True
        assert m["enterprise_egress"]["passed"] is True
        assert isinstance(m["enterprise_egress"]["policy_digest"], str)
        assert m["enterprise_egress"]["policy_digest"]
        assert m["enterprise_egress"]["checked_at"]


def test_egress_probe_failure_refuses_before_any_builder_call(tmp_path, monkeypatch):
    approvers = [_approver()[1] for _ in range(3)]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _api_enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch, egress_ok=False)

        invoked = []

        def fake_invoke(*a, **k):
            invoked.append(True)
            return {"adapter_protocol": "0.1", "status": "ok"}, None

        monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

        rc = supervisor.run(str(cr), None)
        assert rc == 2
        assert not invoked, "the builder must NEVER be invoked when the egress probe fails"

        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        m = json.loads((run_dir / "manifest.json").read_text())
        assert m["outcome"] == "EGRESS_PROBE_FAILED"
        assert m["qualified"] is False
        assert m["enterprise_egress"]["probed"] is True
        assert m["enterprise_egress"]["passed"] is False
        assert isinstance(m["enterprise_egress"]["policy_digest"], str)
        assert m["enterprise_egress"]["policy_digest"]

        journal_text = (run_dir / "journal.jsonl").read_text()
        assert "EGRESS_PROBE_FAILED" in journal_text


def test_egress_probe_exception_also_refuses_fail_closed(tmp_path, monkeypatch):
    """A probe that raises (docker error, launch failure, ...) -- not merely
    returns False -- must ALSO refuse, never propagate an unhandled
    exception or (worse) silently proceed to the builder."""
    approvers = [_approver()[1] for _ in range(3)]
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _api_enterprise_control(tmp_path, approvers, threshold=2, sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch)

        def boom(*a, **k):
            raise RuntimeError("docker daemon unavailable mid-probe")

        monkeypatch.setattr(supervisor.df_container, "probe_enterprise_egress", boom)

        invoked = []

        def fake_invoke(*a, **k):
            invoked.append(True)
            return {"adapter_protocol": "0.1", "status": "ok"}, None

        monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

        rc = supervisor.run(str(cr), None)
        assert rc == 2
        assert not invoked

        run_id = os.listdir(cr / "runs")[0]
        m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
        assert m["outcome"] == "EGRESS_PROBE_FAILED"
        assert m["enterprise_egress"]["passed"] is False


# ---------------------------------------------------------------------------
# Unaffected: non-enterprise runs never touch the egress probe machinery.
# ---------------------------------------------------------------------------

def test_non_enterprise_run_never_probes_egress(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")

    def must_not_be_called(*a, **k):
        raise AssertionError("probe_enterprise_egress must not be called at cooperative tier")

    monkeypatch.setattr(supervisor.df_container, "probe_enterprise_egress", must_not_be_called)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["enterprise_egress"] is None
    assert m["proxy"] is None
