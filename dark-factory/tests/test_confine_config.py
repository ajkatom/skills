"""M14-2: builder_confinement config (cfg["_confine"]), supervisor confine
signal + fail-closed tier gating, and the `builder_confinement` manifest
field.

Config: an optional `builder_confinement` block -> cfg["_confine"]
({"enabled", "required", "profile"}). Supervisor: when enabled, threads
`confine=True` into the builder's invoke_adapter request; when the adapter
reports `status:"error"` with `detail` containing "confinement unsupported",
a `required:true` tier refuses fail-closed (CONFINEMENT_REFUSED, exit 2, no
build ever runs unconfined), while `required:false` warns and falls back to
an unconfined retry so the run can still converge. `builder_confinement` is
an additive manifest field on every terminal, fresh + resume — same pattern
as `credentials` (M11) / `mode`+`characterization` (M15).

All supervisor-level tests here monkeypatch `supervisor.invoke_adapter`
directly (never spawn a real adapter subprocess or CLI) — the adapter's own
`confine` handling is Task 1's suite (test_confine.py). Real docker/OS-
sandbox probes are never exercised; every control root here defaults to
`assurance: "cooperative"` (test_supervisor.setup_control's default).
"""
import json
import os
import sys

import pytest

import df_config
import df_confine
import supervisor
from test_config import write_config
from test_hardened_config import GREET_PY
from test_supervisor import read_journal, setup_control

# ---------------------------------------------------------------------------
# config matrix: cfg["_confine"]
# ---------------------------------------------------------------------------

def test_builder_confinement_absent_defaults_disabled(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_confine"] == {"enabled": False, "required": False, "profile": "standard"}


def test_builder_confinement_enabled_defaults_required_true(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, builder_confinement={"enabled": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_confine"] == {"enabled": True, "required": True, "profile": "standard"}


def test_builder_confinement_enabled_required_explicit_false(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, builder_confinement={"enabled": True, "required": False})
    cfg = df_config.load_config(str(cr))
    assert cfg["_confine"] == {"enabled": True, "required": False, "profile": "standard"}


def test_builder_confinement_disabled_required_default_false(tmp_path):
    # enabled: False explicit -> required still defaults to enabled (False),
    # not to some independent default.
    cr = tmp_path / "control"
    write_config(cr, builder_confinement={"enabled": False})
    cfg = df_config.load_config(str(cr))
    assert cfg["_confine"] == {"enabled": False, "required": False, "profile": "standard"}


def test_builder_confinement_required_true_enabled_false_incoherent_rejected(tmp_path):
    # RA-04 coherence (ANY tier): explicitly requiring confinement while
    # disabling it is a contradiction the runtime cannot honor (confine=enabled
    # would be False, so the builder runs UNCONFINED despite "required"). Refuse
    # at load, fail-closed. Because `required` defaults to `enabled`, only this
    # EXPLICIT {enabled:false, required:true} trips it.
    cr = tmp_path / "control"
    write_config(cr, builder_confinement={"enabled": False, "required": True})
    with pytest.raises(df_config.ConfigError, match="incoherent"):
        df_config.load_config(str(cr))


def test_builder_confinement_not_a_dict_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, builder_confinement="yes")
    with pytest.raises(df_config.ConfigError, match="builder_confinement"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("bad", [
    {"enabled": "yes"},
    {"enabled": 1},
    {"enabled": True, "required": "no"},
    {"enabled": True, "required": 0},
])
def test_builder_confinement_bad_types_rejected(tmp_path, bad):
    cr = tmp_path / "control"
    write_config(cr, builder_confinement=bad)
    with pytest.raises(df_config.ConfigError, match="builder_confinement"):
        df_config.load_config(str(cr))


def test_builder_confinement_unknown_profile_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, builder_confinement={"enabled": True, "profile": "paranoid"})
    with pytest.raises(df_config.ConfigError, match="profile"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# invoke_adapter protocol wiring — the real function (not monkeypatched),
# proving `confine` actually serializes into the request JSON sent to the
# adapter subprocess.
# ---------------------------------------------------------------------------

def _capture_adapter(tmp_path, out_file):
    script = tmp_path / "capture_adapter.py"
    script.write_text(
        "import json, sys\n"
        "req = json.load(sys.stdin)\n"
        f"open({str(out_file)!r}, 'w', encoding='utf-8').write(json.dumps(req))\n"
        "print(json.dumps({'adapter_protocol': '0.1', 'status': 'ok'}))\n",
        encoding="utf-8",
    )
    return script


def test_invoke_adapter_confine_true_serializes_into_request_json(tmp_path):
    out_file = tmp_path / "req.json"
    script = _capture_adapter(tmp_path, out_file)
    workdir = tmp_path / "ws"
    workdir.mkdir()
    prompt_file = tmp_path / "prompt.md"
    prompt_file.write_text("hi", encoding="utf-8")

    resp, err = supervisor.invoke_adapter(
        str(script), "builder", str(workdir), str(prompt_file), 30,
        exec_prefix=[sys.executable], confine=True,
    )
    assert err is None and resp["status"] == "ok"
    req = json.loads(out_file.read_text(encoding="utf-8"))
    assert req["confine"] is True


def test_invoke_adapter_confine_default_serializes_false(tmp_path):
    out_file = tmp_path / "req.json"
    script = _capture_adapter(tmp_path, out_file)
    workdir = tmp_path / "ws"
    workdir.mkdir()
    prompt_file = tmp_path / "prompt.md"
    prompt_file.write_text("hi", encoding="utf-8")

    resp, err = supervisor.invoke_adapter(
        str(script), "builder", str(workdir), str(prompt_file), 30,
        exec_prefix=[sys.executable],
    )
    assert err is None and resp["status"] == "ok"
    req = json.loads(out_file.read_text(encoding="utf-8"))
    assert req["confine"] is False


# ---------------------------------------------------------------------------
# supervisor wiring — monkeypatched supervisor.invoke_adapter; no real
# docker/sandbox/CLI required. `setup_control` always yields assurance:
# "cooperative" (test_supervisor's default).
# ---------------------------------------------------------------------------

def _set_confine(cr, **overrides):
    cfg = json.loads((cr / "config.json").read_text())
    bc = {"enabled": True, "required": True, "profile": "standard"}
    bc.update(overrides)
    cfg["builder_confinement"] = bc
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")


def _read_manifest(cr):
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    return run_id, m


def _ok_write_greet(workdir):
    with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
        f.write(GREET_PY)


def test_enabled_confine_true_passed_and_present_on_converged_manifest(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")
    _set_confine(cr)  # enabled True, required True (default)

    captured = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        captured.append(confine)
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured == [True]  # single converging builder call, confined

    _, m = _read_manifest(cr)
    assert m["outcome"] in ("COMPLETE_QUALIFIED", "COMPLETE_UNQUALIFIED")
    assert m["builder_confinement"] == {
        "enabled": True,
        "profile": "standard",
        "mcp_disabled": True,
        "tool_allowlist": df_confine.BUILD_TOOLS,
        "probe": "unverified",
    }


def test_required_unsupported_refuses_fail_closed_no_build(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/gemini", checkpoint="auto")
    _set_confine(cr)  # enabled True, required True

    calls = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        calls.append(confine)
        assert confine is True
        # A real gemini adapter fails closed WITHOUT writing anything.
        return {"adapter_protocol": "0.1", "status": "error",
                "detail": "confinement unsupported for gemini"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 2
    assert calls == [True]  # exactly one attempt — no unconfined retry, ever

    run_id, m = _read_manifest(cr)
    assert m["outcome"] == "CONFINEMENT_REFUSED"
    assert m["qualified"] is False
    assert m["builder_confinement"]["enabled"] is True

    # No build proceeded: the workspace never got the artifact.
    ws_dir = os.path.join(str(tmp_path / "ws"), run_id)
    assert not os.path.exists(os.path.join(ws_dir, "greet.py"))

    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "CONFINEMENT_UNSUPPORTED" in states
    assert "BUILD" not in states


def test_not_required_unsupported_warns_and_converges_unconfined(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/gemini", checkpoint="auto")
    _set_confine(cr, required=False)

    calls = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        calls.append(confine)
        if confine:
            return {"adapter_protocol": "0.1", "status": "error",
                    "detail": "confinement unsupported for gemini"}, None
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert calls == [True, False]  # confined attempt, then the unconfined retry

    _, m = _read_manifest(cr)
    assert m["outcome"] in ("COMPLETE_QUALIFIED", "COMPLETE_UNQUALIFIED")
    assert m["builder_confinement"] == {
        "enabled": False,
        "profile": "standard",
        "mcp_disabled": False,
        "tool_allowlist": [],
        "probe": "n/a",
    }

    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "CONFINEMENT_WARN" in states
    assert "CONFINEMENT_UNSUPPORTED" not in states  # that journal state is required-only
    assert "BUILD" in states


def test_builder_confinement_present_on_generic_aborted_build_error(tmp_path, monkeypatch):
    # A build error UNRELATED to confinement (e.g. a real crash) must still
    # carry builder_confinement on its terminal manifest, and must NOT be
    # mistaken for a confinement refusal. Uses claude (the one supported,
    # probe-verified profile) so the confined field reflects a real enforced
    # profile.
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")
    _set_confine(cr, required=False)

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        assert confine is True
        return {"adapter_protocol": "0.1", "status": "error",
                "detail": "boom: unrelated crash"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 2

    _, m = _read_manifest(cr)
    assert m["outcome"] == "ABORTED_BUILD_ERROR"
    assert m["builder_confinement"] == {
        "enabled": True,
        "profile": "standard",
        "mcp_disabled": True,
        "tool_allowlist": df_confine.BUILD_TOOLS,
        "probe": "unverified",
    }

    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "CONFINEMENT_UNSUPPORTED" not in states
    assert "CONFINEMENT_WARN" not in states


def test_builder_confinement_present_on_aborted_by_human_resume_manifest(tmp_path, monkeypatch):
    # Pause at checkpoint 1 (dev scenarios not yet satisfied), then resume
    # with decision="abort" -- this exercises resume()'s OWN manifest_base
    # construction (a separate code path from _run_locked's), which must
    # carry builder_confinement exactly like the fresh-run path.
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="pause")
    _set_confine(cr, required=False)

    def fake_invoke_incomplete(adapter, role, workdir, prompt_file, timeout_s,
                               exec_prefix=None, env_extra=None, env_full=None, confine=False):
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write("print('not what the spec wants')\n")
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke_incomplete)

    rc = supervisor.run(str(cr), None)
    assert rc == supervisor.PAUSED

    rc2 = supervisor.resume(str(cr), decision="abort")
    assert rc2 == 2

    _, m = _read_manifest(cr)
    assert m["outcome"] == "ABORTED_BY_HUMAN"
    assert m["builder_confinement"] == {
        "enabled": True,
        "profile": "standard",
        "mcp_disabled": True,
        "tool_allowlist": df_confine.BUILD_TOOLS,
        "probe": "unverified",
    }


def test_disabled_confine_false_and_manifest_field_disabled(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")
    # No builder_confinement block at all -> absent -> disabled defaults.

    captured = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        captured.append(confine)
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured == [False]

    _, m = _read_manifest(cr)
    assert m["builder_confinement"] == {
        "enabled": False,
        "profile": "standard",
        "mcp_disabled": False,
        "tool_allowlist": [],
        "probe": "n/a",
    }


def test_confine_manifest_field_reflects_only_enforced_and_is_per_cli_distinguishable():
    # The manifest's builder_confinement.tool_allowlist must reflect only what
    # the CLI ACTUALLY enforces, so an auditor reading the machine-readable
    # manifest can tell profiles apart and is never misled into thinking an
    # un-enforced allowlist was applied.
    enabled = {"enabled": True, "required": True, "profile": "standard"}
    claude_field = supervisor._confine_manifest_field(enabled, "claude")
    codex_field = supervisor._confine_manifest_field(enabled, "codex")

    # claude: genuinely-enforced allowlist + mcp disabled.
    assert claude_field["tool_allowlist"] == df_confine.BUILD_TOOLS
    assert claude_field["mcp_disabled"] is True

    # codex: unsupported profile -> honestly records NO enforced confinement
    # (empty allowlist, mcp_disabled False), never claiming claude's allowlist.
    assert codex_field["tool_allowlist"] == []
    assert codex_field["mcp_disabled"] is False

    # Distinguishable: a codex manifest is never byte-identical to a claude one.
    assert claude_field != codex_field


def test_disabled_confine_kwarg_never_passed_to_legacy_invoke_signature(tmp_path, monkeypatch):
    # Back-compat regression guard (Global Constraint): with builder_confinement
    # absent, the supervisor must not even ATTEMPT to pass a `confine` kwarg —
    # proven here by a fake_invoke with a pre-M14 signature that would raise
    # TypeError on an unexpected kwarg.
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0


# ---------- DF-R3-05 (M50): _confine_manifest_field binds structural claim to identity ----------

_SHIPPED_API_ANTHROPIC = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "adapters", "api_anthropic")


def test_confine_field_structural_supported_for_shipped_adapter():
    # The genuine shipped api_anthropic path -> the structural no-tool-surface
    # claim IS granted (mcp_disabled True), probe "unverified".
    enabled = {"enabled": True, "required": True, "profile": "standard"}
    field = supervisor._confine_manifest_field(
        enabled, "api_anthropic", _SHIPPED_API_ANTHROPIC, None)
    assert field["mcp_disabled"] is True
    assert field["probe"] == "unverified"


def test_confine_field_structural_unsupported_for_impostor(tmp_path):
    # An impostor renamed api_anthropic at an untrusted path with no digest pin
    # -> the field HONESTLY records the claim was NOT granted (mcp_disabled
    # False, empty allowlist, probe "unsupported"), never a false structural
    # claim earned by basename.
    impostor = tmp_path / "api_anthropic"
    impostor.write_text("#!/bin/sh\necho impostor\n")
    enabled = {"enabled": True, "required": True, "profile": "standard"}
    field = supervisor._confine_manifest_field(
        enabled, "api_anthropic", str(impostor), None)
    assert field["enabled"] is True
    assert field["mcp_disabled"] is False
    assert field["tool_allowlist"] == []
    assert field["probe"] == "unsupported"


def test_confine_field_structural_supported_with_matching_digest(tmp_path):
    # A byte-identical relocated copy is trusted again once its digest is pinned.
    copy = tmp_path / "api_anthropic"
    copy.write_bytes(open(_SHIPPED_API_ANTHROPIC, "rb").read())
    digest = df_confine._file_sha256(str(copy))
    enabled = {"enabled": True, "required": True, "profile": "standard"}
    field = supervisor._confine_manifest_field(
        enabled, "api_anthropic", str(copy), digest)
    assert field["mcp_disabled"] is True
    assert field["probe"] == "unverified"
