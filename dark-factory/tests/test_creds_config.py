"""M11-2: credentials config (cfg["_credentials"]), df_creds.launcher_scoped_env,
and the supervisor's brokered builder env + redacted writers.

Config: an optional `credentials` block -> cfg["_credentials"] (source,
env_file, service_prefix, allowlist). Supervisor: resolves credentials via
df_creds.load_credentials BEFORE any builder call (fail-closed, exit 2 on
CredsError); builds a Redactor from the resolved values and threads it
through every journal/manifest/state/checkpoint/report writer; broker the
builder's env per tier (hardened: `-e` container env via build_argv;
standard/cooperative: launcher_scoped_env strip+merge, a FULL env
replacement via invoke_adapter's new `env_full` param).

All supervisor-level tests here monkeypatch df_creds.load_credentials (never
touch a real env-file/keychain) — df_creds' own sourcing is Task 1's test
suite (test_creds.py). Real docker/OS-sandbox probes are faked exactly like
test_hardened_config.py, so this suite needs neither Docker nor a platform
sandbox.
"""
import json
import os

import pytest

import df_config
import df_creds
import supervisor
from test_config import write_config
from test_hardened_config import GREET_PY, _hardened_control, _patch_hardened_probes
from test_supervisor import FAKE, setup_control

# ---------------------------------------------------------------------------
# config matrix: cfg["_credentials"]
# ---------------------------------------------------------------------------

def test_credentials_absent_is_none(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_credentials"] is None


def test_credentials_env_file_valid_shape(tmp_path):
    cr = tmp_path / "control"
    env_file = tmp_path / "creds" / ".env"  # disjoint from control root + workspace
    write_config(cr, credentials={
        "source": "env-file", "env_file": str(env_file),
        "allowlist": ["FOO_API_KEY", "BAR_TOKEN"],
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_credentials"] == {
        "source": "env-file",
        "env_file": str(env_file),
        "service_prefix": "dark-factory/",
        "allowlist": ["FOO_API_KEY", "BAR_TOKEN"],
    }


def test_credentials_keychain_valid_default_prefix(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={"source": "keychain", "allowlist": ["FOO_TOKEN"]})
    cfg = df_config.load_config(str(cr))
    assert cfg["_credentials"]["source"] == "keychain"
    assert cfg["_credentials"]["service_prefix"] == "dark-factory/"
    assert cfg["_credentials"]["env_file"] is None
    assert cfg["_credentials"]["allowlist"] == ["FOO_TOKEN"]


def test_credentials_keychain_custom_prefix(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={
        "source": "keychain", "service_prefix": "myorg/", "allowlist": ["FOO_TOKEN"],
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_credentials"]["service_prefix"] == "myorg/"


def test_credentials_env_source_valid(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={"source": "env", "allowlist": ["FOO_API_KEY"]})
    cfg = df_config.load_config(str(cr))
    assert cfg["_credentials"]["source"] == "env"
    assert cfg["_credentials"]["env_file"] is None


def test_credentials_unknown_source_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={"source": "vault", "allowlist": ["FOO_API_KEY"]})
    with pytest.raises(df_config.ConfigError, match="source"):
        df_config.load_config(str(cr))


def test_credentials_non_dict_block_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials="oops")
    with pytest.raises(df_config.ConfigError, match="credentials"):
        df_config.load_config(str(cr))


def test_credentials_env_file_missing_field_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={"source": "env-file", "allowlist": ["FOO_API_KEY"]})
    with pytest.raises(df_config.ConfigError, match="env_file"):
        df_config.load_config(str(cr))


def test_credentials_env_file_relative_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={
        "source": "env-file", "env_file": "relative/.env",
        "allowlist": ["FOO_API_KEY"],
    })
    with pytest.raises(df_config.ConfigError, match="absolute"):
        df_config.load_config(str(cr))


def test_credentials_env_file_expanduser_then_absolute_checked(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    cr = tmp_path / "control"
    write_config(cr, credentials={
        "source": "env-file", "env_file": "~/creds/.env",
        "allowlist": ["FOO_API_KEY"],
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_credentials"]["env_file"] == str(fake_home / "creds" / ".env")


def test_credentials_env_file_inside_control_root_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={
        "source": "env-file", "env_file": str(cr / "secrets.env"),
        "allowlist": ["FOO_API_KEY"],
    })
    with pytest.raises(df_config.ConfigError, match="disjoint"):
        df_config.load_config(str(cr))


def test_credentials_env_file_inside_workspace_rejected(tmp_path):
    cr = tmp_path / "control"
    ws = tmp_path / "ws"
    write_config(cr, workspace_root=str(ws), credentials={
        "source": "env-file", "env_file": str(ws / "secrets.env"),
        "allowlist": ["FOO_API_KEY"],
    })
    with pytest.raises(df_config.ConfigError, match="disjoint"):
        df_config.load_config(str(cr))


def test_credentials_empty_allowlist_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={"source": "env", "allowlist": []})
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("bad", ["foo_api_key", "1FOO", "FOO-KEY", "FOO KEY", ""])
def test_credentials_malformed_allowlist_name_rejected(tmp_path, bad):
    cr = tmp_path / "control"
    write_config(cr, credentials={"source": "env", "allowlist": [bad]})
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


def test_credentials_duplicate_allowlist_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={
        "source": "env", "allowlist": ["FOO_API_KEY", "FOO_API_KEY"],
    })
    with pytest.raises(df_config.ConfigError, match="duplicate"):
        df_config.load_config(str(cr))


def test_credentials_env_file_field_on_non_env_file_source_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credentials={
        "source": "env", "env_file": "/whatever/.env", "allowlist": ["FOO_API_KEY"],
    })
    with pytest.raises(df_config.ConfigError, match="env_file"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("source", ["env", "env-file"])
def test_credentials_service_prefix_on_non_keychain_source_rejected(tmp_path, source):
    cr = tmp_path / "control"
    creds = {"source": source, "service_prefix": "myorg/", "allowlist": ["FOO_API_KEY"]}
    if source == "env-file":
        creds["env_file"] = str(tmp_path / "creds" / ".env")
    write_config(cr, credentials=creds)
    with pytest.raises(df_config.ConfigError, match="service_prefix"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# df_creds.launcher_scoped_env — pure helper
# ---------------------------------------------------------------------------

def test_launcher_scoped_env_strips_unallowlisted_cred_shaped_vars():
    base = {
        "PATH": "/usr/bin", "HOME": "/home/x",
        "FOO_API_KEY": "leaked-fookey-1", "X_TOKEN": "leaked-token-1",
        "A_SECRET": "leaked-secret-1", "B_PASSWORD": "leaked-pw-1",
        "ANTHROPIC_API_KEY": "stale-should-be-overridden",
        "UNRELATED_VAR": "keep-me",
    }
    creds = {"ANTHROPIC_API_KEY": "resolved-value-123"}
    out = df_creds.launcher_scoped_env(base, ["ANTHROPIC_API_KEY"], creds)
    assert out["PATH"] == "/usr/bin"
    assert out["HOME"] == "/home/x"
    assert "FOO_API_KEY" not in out
    assert "X_TOKEN" not in out
    assert "A_SECRET" not in out
    assert "B_PASSWORD" not in out
    assert out["UNRELATED_VAR"] == "keep-me"
    assert out["ANTHROPIC_API_KEY"] == "resolved-value-123"  # creds merged in last


def test_launcher_scoped_env_no_creds_still_strips():
    base = {"PATH": "/usr/bin", "LEAKED_API_KEY": "x", "LEAKED_TOKEN": "y"}
    out = df_creds.launcher_scoped_env(base, [], {})
    assert out == {"PATH": "/usr/bin"}


def test_launcher_scoped_env_pure_no_mutation():
    base = {"PATH": "/usr/bin", "FOO_TOKEN": "leak"}
    base_copy = dict(base)
    df_creds.launcher_scoped_env(base, [], {"X": "y"})
    assert base == base_copy


# ---------------------------------------------------------------------------
# Journal redaction round-trip (unit level: a stubbed event smuggling a
# credential value into a field must never survive to disk).
# ---------------------------------------------------------------------------

def test_journal_redacts_smuggled_value_on_disk(tmp_path):
    secret = "supersecretvalue-9f8e7d6c5b4a"
    redactor = df_creds.Redactor([secret])
    path = tmp_path / "journal.jsonl"
    journal = supervisor.Journal(str(path), redactor=redactor)
    journal.write("STUB_EVENT", detail=f"adapter said: {secret} was rejected")
    text = path.read_text(encoding="utf-8")
    assert secret not in text
    assert "***REDACTED***" in text


def test_journal_redactor_none_is_strict_noop(tmp_path):
    path = tmp_path / "journal.jsonl"
    journal = supervisor.Journal(str(path))  # redactor=None default
    journal.write("STATE", detail="anything at all, no redactor configured")
    text = path.read_text(encoding="utf-8")
    assert "anything at all, no redactor configured" in text


# ---------------------------------------------------------------------------
# supervisor wiring — monkeypatched df_creds.load_credentials + captured
# invoke_adapter; no real docker/sandbox required.
# ---------------------------------------------------------------------------

SECRET = "supersecretvalue-9f8e7d6c5b4a"


def _add_credentials(cr, **overrides):
    cfg = json.loads((cr / "config.json").read_text())
    creds = {"source": "env", "allowlist": ["FOO_API_KEY"]}
    creds.update(overrides)
    cfg["credentials"] = creds
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")


def _fake_load_credentials_ok(monkeypatch, calls=None, value=SECRET, returned=None):
    def _fake(spec):
        if calls is not None:
            calls.append(spec)
        result = {name: value for name in spec["allowlist"]}
        if returned is not None:
            returned.append(result)
        return result
    monkeypatch.setattr(supervisor.df_creds, "load_credentials", _fake)


def test_hardened_builder_env_is_creds_and_argv_has_exact_allowlist_e_flags(tmp_path, monkeypatch):
    cr = _hardened_control(tmp_path)
    _add_credentials(cr, allowlist=["FOO_API_KEY", "BAR_TOKEN"])
    _patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=True)
    returned = []
    _fake_load_credentials_ok(monkeypatch, returned=returned)

    captured = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None):
        captured.append({"exec_prefix": list(exec_prefix) if exec_prefix else [],
                          "env_extra": env_extra, "env_full": env_full})
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured, "builder invoke_adapter was never called"

    argv = captured[0]["exec_prefix"]
    e_pairs = {argv[i + 1] for i, x in enumerate(argv) if x == "-e"}
    cred_pairs = {p for p in e_pairs if not p.startswith("HOME=")}
    assert cred_pairs == {f"FOO_API_KEY={SECRET}", f"BAR_TOKEN={SECRET}"}

    # builder_env passed to invoke_adapter's env_extra IS the resolved creds
    # dict, by identity (not merely equal) — values enter the container only
    # via the -e argv above, never via the docker client's own env mechanism.
    assert captured[0]["env_extra"] == {"FOO_API_KEY": SECRET, "BAR_TOKEN": SECRET}
    assert captured[0]["env_extra"] is returned[0]
    assert captured[0]["env_full"] is None

    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["credentials"] == {"source": "env", "allowlist": ["FOO_API_KEY", "BAR_TOKEN"]}
    # names-only: never a value anywhere in the manifest text.
    manifest_text = (cr / "runs" / run_id / "manifest.json").read_text()
    assert SECRET not in manifest_text


def test_standard_cooperative_builder_env_is_stripped_and_merged(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # cooperative default;
    # shares the identical non-hardened wiring branch as "standard" tier.
    _add_credentials(cr, allowlist=["FOO_API_KEY"])
    _fake_load_credentials_ok(monkeypatch)
    monkeypatch.setenv("DF_LEAKME_API_KEY", "leaked-value-should-never-appear")

    captured = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None):
        captured.append({"env_extra": env_extra, "env_full": env_full})
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured
    env_full = captured[0]["env_full"]
    assert isinstance(env_full, dict)
    assert env_full.get("PATH")  # PATH survives the strip
    assert "DF_LEAKME_API_KEY" not in env_full  # not allowlisted, credential-shaped -> stripped
    assert env_full["FOO_API_KEY"] == SECRET  # allowlisted, merged in from resolved creds
    assert captured[0]["env_extra"] is None  # env_full REPLACES, not merges


def test_twins_plus_credentials_merge_twin_env_over_scoped_env(tmp_path, monkeypatch):
    # Twin env vars (DF_TWIN_* endpoints) are NOT credentials: at
    # standard/cooperative with credentials configured, the builder env must
    # be launcher_scoped_env(...) WITH the twin env merged over it — never a
    # silent drop of the twin endpoints (pre-M11 regression guard).
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    (cr / "twins").mkdir()
    (cr / "twins" / "x.json").write_text("{}", encoding="utf-8")  # load_defs is faked
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"] = {"enabled": True, "startup_timeout_s": 20}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    _add_credentials(cr, allowlist=["FOO_API_KEY"])
    _fake_load_credentials_ok(monkeypatch)
    monkeypatch.setenv("DF_LEAKME_API_KEY", "leaked-value-should-never-appear")

    twin_env = {"DF_TWIN_X": "http://127.0.0.1:9"}

    class _FakeTwinSet:
        env = twin_env

        def start(self, defs, run_dir, timeout):
            return twin_env

        def reset(self, defs, run_dir, timeout):
            return twin_env

        def stop(self):
            pass

    monkeypatch.setattr(supervisor.df_twins, "TwinSet", _FakeTwinSet)
    monkeypatch.setattr(supervisor.df_twins, "load_defs", lambda d: [])

    captured = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None):
        captured.append({"env_extra": env_extra, "env_full": env_full})
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured
    env_full = captured[0]["env_full"]
    assert isinstance(env_full, dict)
    assert env_full["DF_TWIN_X"] == "http://127.0.0.1:9"  # twin env survives the broker
    assert env_full["FOO_API_KEY"] == SECRET  # allowlisted cred present
    assert env_full.get("PATH")  # base env kept
    assert "DF_LEAKME_API_KEY" not in env_full  # non-allowlisted cred-shaped var stripped


def test_no_credentials_configured_env_full_never_passed(tmp_path, monkeypatch):
    # Back-compat: an invoke_adapter caller that predates env_full (no such
    # kwarg) must keep working when no credentials are configured.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")

    captured = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None):  # no env_full param at all
        captured.append(env_extra)
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured == [None]


def test_unresolvable_credentials_exit_2_before_any_builder_call(tmp_path, monkeypatch, capsys):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _add_credentials(cr, allowlist=["FOO_API_KEY"])

    def _fail(spec):
        raise df_creds.CredsError("credential 'FOO_API_KEY' not set in launcher environment")

    monkeypatch.setattr(supervisor.df_creds, "load_credentials", _fail)

    called = []
    monkeypatch.setattr(supervisor, "invoke_adapter", lambda *a, **k: called.append(1))

    rc = supervisor.run(str(cr), None)
    assert rc == 2
    assert called == []
    assert "credentials:" in capsys.readouterr().err
    # fail-closed at run start: nothing was ever written to disk.
    assert not (cr / "runs").exists()


def test_manifest_credentials_names_only_on_converged(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _add_credentials(cr, allowlist=["FOO_API_KEY"])
    _fake_load_credentials_ok(monkeypatch)
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_UNQUALIFIED"
    assert m["credentials"] == {"source": "env", "allowlist": ["FOO_API_KEY"]}
    assert SECRET not in (cr / "runs" / run_id / "manifest.json").read_text()


def test_manifest_credentials_names_only_on_abort_gate_failed(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _add_credentials(cr, allowlist=["FOO_API_KEY"])
    _fake_load_credentials_ok(monkeypatch)
    # inert oracle -> GATE_FAILED, well before any builder call.
    sc = {
        "ir_version": "0.1", "id": "BHV-001-S9", "behavior_id": "BHV-001",
        "title": "inert", "given": "workspace has greet.py",
        "when": {"run": ["python3", "greet.py", "World"], "timeout_s": 10},
        "then": {"stdout_contains": ""},
    }
    (cr / "scenarios" / "inert.json").write_text(json.dumps(sc), encoding="utf-8")
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "GATE_FAILED"
    assert m["credentials"] == {"source": "env", "allowlist": ["FOO_API_KEY"]}


def test_resume_reresolves_credentials_and_state_json_is_value_free(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE)  # default autonomy 4 -> checkpoint pause
    _add_credentials(cr, allowlist=["FOO_API_KEY"])

    calls = []
    _fake_load_credentials_ok(monkeypatch, calls=calls)

    rc = supervisor.run(str(cr), None)
    assert rc == supervisor.PAUSED
    assert len(calls) == 1  # resolved once, at run start

    run_id = os.listdir(cr / "runs")[0]
    state_path = cr / "runs" / run_id / "state.json"
    assert state_path.exists()
    state_text = state_path.read_text(encoding="utf-8")
    assert SECRET not in state_text  # state.json must NEVER carry a credential value

    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == 0
    assert len(calls) == 2  # re-resolved on resume, before the loop re-enters

    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["credentials"] == {"source": "env", "allowlist": ["FOO_API_KEY"]}


def test_resume_abort_manifest_credentials_names_only(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE)  # default autonomy 4 -> checkpoint pause
    _add_credentials(cr, allowlist=["FOO_API_KEY"])
    _fake_load_credentials_ok(monkeypatch)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    assert supervisor.resume(str(cr), "abort") == 2
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "ABORTED_BY_HUMAN"
    assert m["credentials"] == {"source": "env", "allowlist": ["FOO_API_KEY"]}


def test_resume_unresolvable_credentials_exit_2_before_builder(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE)  # default autonomy 4 -> checkpoint pause
    _add_credentials(cr, allowlist=["FOO_API_KEY"])
    _fake_load_credentials_ok(monkeypatch)
    assert supervisor.run(str(cr), None) == supervisor.PAUSED

    def _fail(spec):
        raise df_creds.CredsError("env-file no longer readable")
    monkeypatch.setattr(supervisor.df_creds, "load_credentials", _fail)

    called = []
    monkeypatch.setattr(supervisor, "invoke_adapter", lambda *a, **k: called.append(1))
    rc = supervisor.resume(str(cr), "continue")
    assert rc == 2
    assert called == []
