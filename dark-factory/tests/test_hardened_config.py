"""M10-2: hardened tier config gates (registry + df_config), resolve_isolation
hardened branch, and builder-vs-verifier exec wiring.

Registry: supported_tiers.json now qualifies "hardened" (container-docker).
Config: optional `hardened` block -> cfg["_container"]; autonomy L5 gate;
hardened requires signed audit. resolve_isolation/wiring tests use fully
injected fakes (OS backend + docker probes) so nothing here requires a real
Docker daemon or a real platform sandbox — this suite must pass everywhere.
"""
import json
import os
import sys

import pytest

import df_config
import df_container
import df_sandbox
import supervisor
from test_config import write_config
from test_supervisor import FAKE, MARKER, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
GREETER = os.path.join(HERE, "fixtures", "twin_greeter")

# hardened validates roles.builder.adapter as an absolute EXISTING file whose
# directory is disjoint from the control root (its dir is mounted into the
# container). test_config.write_config's default "/bin/true" does not exist on
# every platform (macOS ships only /usr/bin/true), so hardened tests pin a
# real file that always exists and lives outside any tmp control root.
VALID_ADAPTER = sys.executable


def write_hardened(cr, **overrides):
    overrides.setdefault("assurance", "hardened")
    overrides.setdefault(
        "roles", {"builder": {"adapter": VALID_ADAPTER, "timeout_s": 60}})
    return write_config(cr, **overrides)

GREET_PY = (
    "import sys\n"
    "if len(sys.argv) != 2:\n"
    "    print('usage: greet.py <name>', file=sys.stderr); sys.exit(2)\n"
    "print(f'Hello, {sys.argv[1]}!')\n"
)


# ---------------------------------------------------------------------------
# config: hardened block -> cfg["_container"]
# ---------------------------------------------------------------------------

def test_hardened_tier_accepted_with_defaults(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["assurance"] == "hardened"
    assert cfg["_qualified"] is True
    assert cfg["_container"] == {
        "image": df_container.DEFAULT_IMAGE, "network": "none",
        "memory": "2g", "pids": 256,
    }


def test_hardened_block_overrides_defaults(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, hardened={
        "image": "myorg/img:1", "network": "bridge", "memory": "512m", "pids": 64,
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_container"] == {
        "image": "myorg/img:1", "network": "bridge", "memory": "512m", "pids": 64,
    }


def test_hardened_empty_image_rejected(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, hardened={"image": ""})
    with pytest.raises(df_config.ConfigError, match="image"):
        df_config.load_config(str(cr))


def test_hardened_bad_network_rejected(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, hardened={"network": "host"})
    with pytest.raises(df_config.ConfigError, match="network"):
        df_config.load_config(str(cr))


def test_hardened_bad_memory_rejected(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, hardened={"memory": "lots"})
    with pytest.raises(df_config.ConfigError, match="memory"):
        df_config.load_config(str(cr))


def test_hardened_uppercase_memory_rejected(tmp_path):
    # plan: lowercase ok only ("2g", "512m") — uppercase must not silently pass.
    cr = tmp_path / "control"
    write_hardened(cr, hardened={"memory": "2G"})
    with pytest.raises(df_config.ConfigError, match="memory"):
        df_config.load_config(str(cr))


def test_hardened_low_pids_rejected(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, hardened={"pids": 2})
    with pytest.raises(df_config.ConfigError, match="pids"):
        df_config.load_config(str(cr))


def test_hardened_bool_pids_rejected(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, hardened={"pids": True})
    with pytest.raises(df_config.ConfigError, match="pids"):
        df_config.load_config(str(cr))


def test_hardened_non_dict_block_rejected(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, hardened="oops")
    with pytest.raises(df_config.ConfigError, match="hardened"):
        df_config.load_config(str(cr))


def test_hardened_block_under_standard_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard", hardened={"image": "x"})
    with pytest.raises(df_config.ConfigError, match="assurance: hardened"):
        df_config.load_config(str(cr))


def test_hardened_block_under_cooperative_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="cooperative", hardened={})
    with pytest.raises(df_config.ConfigError, match="assurance: hardened"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# L5 gate: autonomy must be 4 or 5; 5 requires assurance hardened
# ---------------------------------------------------------------------------

def test_autonomy_5_requires_hardened(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard", autonomy=5)
    with pytest.raises(df_config.ConfigError, match="autonomy 5"):
        df_config.load_config(str(cr))


def test_autonomy_5_cooperative_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="cooperative", autonomy=5)
    with pytest.raises(df_config.ConfigError, match="autonomy 5"):
        df_config.load_config(str(cr))


def test_autonomy_5_with_hardened_ok_checkpoint_defaults_auto(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, autonomy=5)
    cfg = df_config.load_config(str(cr))
    assert cfg["assurance"] == "hardened"
    assert cfg["_checkpoint"] == "auto"


def test_autonomy_3_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, autonomy=3)
    with pytest.raises(df_config.ConfigError, match="autonomy"):
        df_config.load_config(str(cr))


def test_autonomy_string_five_rejected(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, autonomy="5")
    with pytest.raises(df_config.ConfigError, match="autonomy"):
        df_config.load_config(str(cr))


def test_autonomy_bool_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, autonomy=True)
    with pytest.raises(df_config.ConfigError, match="autonomy"):
        df_config.load_config(str(cr))


def test_autonomy_absent_defaults_to_4_checkpoint_pause(tmp_path):
    cr = tmp_path / "control"
    cfg_dict = write_config(cr)
    del cfg_dict["autonomy"]
    (cr / "config.json").write_text(json.dumps(cfg_dict), encoding="utf-8")
    cfg = df_config.load_config(str(cr))
    assert cfg["_checkpoint"] == "pause"


# ---------------------------------------------------------------------------
# hardened => signed audit
# ---------------------------------------------------------------------------

def test_hardened_signing_explicit_false_rejected(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, audit={"signing": False})
    with pytest.raises(df_config.ConfigError, match="signed audit"):
        df_config.load_config(str(cr))


def test_hardened_audit_absent_defaults_signing_true(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["signing"] is True
    assert cfg["_audit"]["key_path"]


def test_hardened_signing_explicit_true_ok(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, audit={"signing": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["signing"] is True


# ---------------------------------------------------------------------------
# resolve_isolation — hardened branch, fully injected (no real docker/sandbox)
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


def _hardened_cfg(**container_overrides):
    c = {"image": "img", "network": "none", "memory": "2g", "pids": 256}
    c.update(container_overrides)
    return {"assurance": "hardened", "_container": c}


def _patch_hardened_probes(monkeypatch, os_ok, dk_ok):
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend", lambda: _FakeOSBackend())
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: os_ok)
    monkeypatch.setattr(supervisor.df_container, "docker_available", lambda: dk_ok)
    monkeypatch.setattr(supervisor.df_container, "probe_container", lambda *a, **k: dk_ok)


def test_resolve_isolation_hardened_both_ok(tmp_path, monkeypatch):
    _patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=True)
    j = _FakeJournal()
    result = supervisor.resolve_isolation(
        _hardened_cfg(), str(tmp_path / "cr"), str(tmp_path / "ws"), j, False)
    assert result == ("hardened", [], df_container.BACKEND_NAME, True)
    assert not j.entries  # no downgrade/failure noise on the happy path


def test_resolve_isolation_docker_down_no_downgrade_raises(tmp_path, monkeypatch):
    _patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=False)
    j = _FakeJournal()
    with pytest.raises(df_sandbox.SandboxError, match="hardened"):
        supervisor.resolve_isolation(
            _hardened_cfg(), str(tmp_path / "cr"), str(tmp_path / "ws"), j, False)
    assert any(s == "PROBE_FAILED" for s, _ in j.entries)


def test_resolve_isolation_docker_down_downgrade_os_ok_to_standard(tmp_path, monkeypatch):
    _patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=False)
    j = _FakeJournal()
    eff, prefix, backend, probe_passed = supervisor.resolve_isolation(
        _hardened_cfg(), str(tmp_path / "cr"), str(tmp_path / "ws"), j, True)
    assert eff == "standard"
    assert prefix == []
    assert probe_passed is True
    assert any(s == "DOWNGRADE" and d.get("effective") == "standard" for s, d in j.entries)


def test_resolve_isolation_both_down_downgrade_to_cooperative(tmp_path, monkeypatch):
    _patch_hardened_probes(monkeypatch, os_ok=False, dk_ok=False)
    j = _FakeJournal()
    eff, prefix, backend, probe_passed = supervisor.resolve_isolation(
        _hardened_cfg(), str(tmp_path / "cr"), str(tmp_path / "ws"), j, True)
    assert eff == "cooperative"
    assert prefix == []
    assert probe_passed is False
    assert any(s == "DOWNGRADE" and d.get("effective") == "cooperative" for s, d in j.entries)


def test_resolve_isolation_os_down_docker_ok_no_downgrade_raises(tmp_path, monkeypatch):
    # BOTH halves are mandatory: a working docker alone is not sufficient
    # without a working OS sandbox for the verifier.
    _patch_hardened_probes(monkeypatch, os_ok=False, dk_ok=True)
    j = _FakeJournal()
    with pytest.raises(df_sandbox.SandboxError, match="hardened"):
        supervisor.resolve_isolation(
            _hardened_cfg(), str(tmp_path / "cr"), str(tmp_path / "ws"), j, False)


# ---------------------------------------------------------------------------
# builder-vs-verifier wiring — real supervisor.run(), fully injected probes +
# invoke_adapter capture (no real docker daemon required)
# ---------------------------------------------------------------------------

def _hardened_control(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "hardened"
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cr


def test_builder_wiring_docker_prefix_no_control_root_mount(tmp_path, monkeypatch):
    cr = _hardened_control(tmp_path)
    _patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=True)

    captured_builder = []
    captured_verify = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None):
        assert role == "builder"
        captured_builder.append({
            "exec_prefix": list(exec_prefix) if exec_prefix else [],
            "env_extra": env_extra,
        })
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    real_run_all = supervisor.run_all

    def fake_run_all(scenarios_dir, workspace, exec_wrapper=None, env_extra=None, cohort=None,
                     observer_files=None):
        captured_verify.append(list(exec_wrapper) if exec_wrapper else [])
        return real_run_all(scenarios_dir, workspace, exec_wrapper=exec_wrapper,
                            env_extra=env_extra, cohort=cohort, observer_files=observer_files)

    monkeypatch.setattr(supervisor, "run_all", fake_run_all)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    assert captured_builder, "builder invoke_adapter was never called"
    prefix = captured_builder[0]["exec_prefix"]
    assert prefix[0] == "docker"
    control_root_real = os.path.realpath(str(cr))
    v_specs = [prefix[i + 1] for i, x in enumerate(prefix) if x == "-v"]
    assert v_specs, "expected at least one -v mount"
    for spec in v_specs:
        host_path = spec.split(":")[0]
        assert host_path != control_root_real
        assert not host_path.startswith(control_root_real + os.sep)
    assert captured_builder[0]["env_extra"] is None

    assert captured_verify, "verifier run_all was never called"
    assert captured_verify[0] == []  # the (fake) OS wrapper, never docker

    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_QUALIFIED"
    assert m["qualified"] is True
    assert m["sandbox_backend"] == df_container.BACKEND_NAME
    assert m["denial_probe_passed"] is True
    assert m["container"] == {"image": df_container.DEFAULT_IMAGE, "network": "none",
                              "memory": "2g", "pids": 256}


def test_builder_wiring_twin_env_skipped_at_hardened(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    (cr / "twins").mkdir()
    (cr / "twins" / "greeter.json").write_text(json.dumps(
        {"twin_version": "0.1", "name": "greeter", "launch": ["python3", GREETER],
         "fidelity": "dev mock"}), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "hardened"
    cfg["twins"] = {"enabled": True, "startup_timeout_s": 20}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    _patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=True)

    captured_env = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None):
        assert role == "builder"
        captured_env.append(env_extra)
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured_env == [None]  # env_extra forced None at hardened, even though a twin started

    run_id = os.listdir(cr / "runs")[0]
    states = [json.loads(l)["state"] for l in
              (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    assert "TWIN_ENV_SKIPPED" in states


# ---------------------------------------------------------------------------
# manifest: `container` is additive on every terminal manifest, including
# early aborts (pre resolve_isolation) and resume abort/accept.
# ---------------------------------------------------------------------------

def test_container_none_on_cooperative_manifest(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # cooperative default
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["container"] is None


def test_container_none_on_early_gate_abort_manifest(tmp_path):
    # ORACLE_GATE_FAILED finalizes BEFORE resolve_isolation ever runs; the
    # additive `container` field must still be explicitly None, never absent.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    sc = {
        "ir_version": "0.1", "id": "BHV-001-S9", "behavior_id": "BHV-001",
        "title": f"{MARKER} inert", "given": f"{MARKER} workspace has greet.py",
        "when": {"run": ["python3", "greet.py", "World"], "timeout_s": 10},
        "then": {"stdout_contains": ""},
    }
    (cr / "scenarios" / "inert.json").write_text(json.dumps(sc), encoding="utf-8")
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "GATE_FAILED"
    assert m["container"] is None


def test_container_none_on_resume_abort_manifest(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # default autonomy 4 -> checkpoint pause
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "abort") == 2
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "ABORTED_BY_HUMAN"
    assert m["container"] is None


# ---------------------------------------------------------------------------
# M10-2 review fixes: the adapter's directory is bind-mounted ro into the
# builder container, so at hardened it must be an absolute existing file whose
# directory is disjoint from the control root — at CONFIG time (layer 1) and
# re-verified in the supervisor right before the mount (layer 2).
# ---------------------------------------------------------------------------

def test_hardened_adapter_inside_control_root_rejected(tmp_path):
    cr = tmp_path / "control"
    cr.mkdir(parents=True)
    bad = cr / "adapter.py"
    bad.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    write_config(cr, assurance="hardened",
                 roles={"builder": {"adapter": str(bad), "timeout_s": 60}})
    with pytest.raises(df_config.ConfigError, match="disjoint from the control root"):
        df_config.load_config(str(cr))


def test_hardened_bare_command_adapter_rejected(tmp_path):
    # A bare command name has no dir component: realpath would resolve against
    # the process CWD, mounting whatever directory the operator runs from.
    cr = tmp_path / "control"
    write_config(cr, assurance="hardened",
                 roles={"builder": {"adapter": "claude", "timeout_s": 60}})
    with pytest.raises(df_config.ConfigError, match="absolute path"):
        df_config.load_config(str(cr))


def test_hardened_relative_adapter_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="hardened",
                 roles={"builder": {"adapter": "./scripts/adapter", "timeout_s": 60}})
    with pytest.raises(df_config.ConfigError, match="absolute path"):
        df_config.load_config(str(cr))


def test_hardened_absolute_nonexistent_adapter_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="hardened",
                 roles={"builder": {"adapter": str(tmp_path / "nope"), "timeout_s": 60}})
    with pytest.raises(df_config.ConfigError, match="existing file"):
        df_config.load_config(str(cr))


def test_hardened_absolute_outside_adapter_ok(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="hardened",
                 roles={"builder": {"adapter": VALID_ADAPTER, "timeout_s": 60}})
    cfg = df_config.load_config(str(cr))
    assert cfg["roles"]["builder"]["adapter"] == VALID_ADAPTER


def test_standard_bare_command_adapter_still_ok(tmp_path):
    # No regression: outside hardened the adapter dir is never mounted, so
    # bare command names stay legal.
    cr = tmp_path / "control"
    write_config(cr, assurance="standard",
                 roles={"builder": {"adapter": "claude", "timeout_s": 60}})
    cfg = df_config.load_config(str(cr))
    assert cfg["roles"]["builder"]["adapter"] == "claude"


def test_hardened_flag_like_image_rejected_at_config(tmp_path):
    cr = tmp_path / "control"
    write_hardened(cr, hardened={"image": "--privileged"})
    with pytest.raises(df_config.ConfigError, match="image"):
        df_config.load_config(str(cr))


def test_supervisor_guard_refuses_control_root_adapter_mount(tmp_path, monkeypatch):
    # Layer 2 (defense in depth): even if a control-root-inside adapter slips
    # past config validation (drift/TOCTOU), the supervisor must refuse to
    # build the mount — SandboxError, and NEITHER build_argv NOR
    # invoke_adapter is ever called.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    bad_adapter = cr / "evil_adapter"
    bad_adapter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    bad_adapter.chmod(0o755)

    real_load = supervisor.load_config

    def sneaky_load(control_root):
        cfg = real_load(control_root)  # loads as valid cooperative config
        cfg["assurance"] = "hardened"  # mutate AFTER validation (simulates drift)
        cfg["roles"]["builder"]["adapter"] = str(bad_adapter)
        return cfg

    monkeypatch.setattr(supervisor, "load_config", sneaky_load)
    _patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=True)

    called = []
    monkeypatch.setattr(supervisor.df_container, "build_argv",
                        lambda *a, **k: called.append("build_argv") or ["docker"])
    monkeypatch.setattr(
        supervisor, "invoke_adapter",
        lambda *a, **k: called.append("invoke_adapter")
        or ({"adapter_protocol": "0.1", "status": "ok"}, None))

    rc = supervisor.run(str(cr), None)
    assert rc == 2  # in-loop guard refuses with the standard refusal exit code
    assert called == []  # refused BEFORE any docker argv was built or spawned


def test_container_none_on_resume_accept_manifest(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # default autonomy 4 -> checkpoint pause
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "accept") == 0
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "ACCEPTED_WAIVED"
    assert m["container"] is None
