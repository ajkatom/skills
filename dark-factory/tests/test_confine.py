import json
import os
import shutil
import subprocess

import pytest

import df_confine

HERE = os.path.dirname(os.path.abspath(__file__))
CLAUDE_ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "claude")
CODEX_ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "codex")
GEMINI_ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "gemini")
OK = os.path.join(HERE, "fixtures", "fake_cli_ok")


# ---------- confinement_flags / profiles (pure, deterministic, no live CLI) ----------

def test_claude_confinement_flags_disable_mcp_and_restrict_tools():
    argv = df_confine.confinement_flags("claude", "PROMPT")
    assert argv[0] == "claude"
    assert "PROMPT" in argv
    assert "--strict-mcp-config" in argv
    i = argv.index("--mcp-config")
    assert json.loads(argv[i + 1]) == {"mcpServers": {}}
    i = argv.index("--disallowedTools")
    denied = set(argv[i + 1].split(","))
    assert {"Task", "Bash", "WebFetch", "WebSearch"} <= denied
    i = argv.index("--allowedTools")
    allowed = argv[i + 1].split(",")
    assert allowed == df_confine.BUILD_TOOLS
    assert "--permission-mode" in argv and "acceptEdits" in argv


def test_codex_confinement_flags_raise_unsupported():
    # codex was marked unsupported in M14 (Task 3): the live probe caught that
    # `-c mcp_servers={}` does not close codex's desktop-app-injected MCP
    # bridge on this install, so no probe-verified profile exists. Requesting
    # its flags must fail-closed, exactly like gemini.
    with pytest.raises(df_confine.ConfineError):
        df_confine.confinement_flags("codex", "PROMPT")


def test_gemini_confinement_flags_raise():
    with pytest.raises(df_confine.ConfineError):
        df_confine.confinement_flags("gemini", "PROMPT")


def test_unknown_cli_confinement_flags_raise():
    with pytest.raises(df_confine.ConfineError):
        df_confine.confinement_flags("llama", "PROMPT")


@pytest.mark.parametrize("cli,expected", [
    # codex is False in M14: unsupported after the live probe falsified its
    # confinement (desktop-app MCP bridge survives the flags).
    ("claude", True), ("codex", False), ("gemini", False), ("unknown-cli", False),
])
def test_is_supported_matrix(cli, expected):
    assert df_confine.is_supported(cli) is expected


def test_profile_for_known_cli_matches_profiles_dict():
    assert df_confine.profile_for("claude") is df_confine.PROFILES["claude"]


def test_profile_for_unknown_cli_defaults_unsupported():
    profile = df_confine.profile_for("unknown-cli")
    assert profile.get("supported") is False


# ---------- probe_confinement stub (pure orchestration, no live CLI call here) ----------

def test_probe_confinement_unsupported_cli_fails_closed_without_spawning(tmp_path):
    calls = []

    def fake_runner(*a, **k):
        calls.append((a, k))
        raise AssertionError("must not spawn a CLI for an unsupported profile")

    ok, reason = df_confine.probe_confinement("gemini", str(tmp_path), runner=fake_runner)
    assert ok is False
    assert isinstance(reason, str) and reason
    assert calls == []


# ---------- probe non-vacuity: DENIED_CALL_RAN liveness marker (deterministic) ----------
#
# The probe makes TWO calls: call 1 (allowed) writes ALLOWED_PROOF; call 2
# (denied-only) attempts DENIED_PROOF via the denied tool and ALWAYS writes
# DENIED_CALL_RAN as its final action. A pass requires ALLOWED_PROOF AND
# DENIED_CALL_RAN present AND DENIED_PROOF absent. These fake-runner tests
# prove the three branches with NO live CLI — the runner just materializes
# the files a real confined CLI would (or would not) leave behind.

class _FakeProc:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr


def _make_probe_runner(workdir, *, write_allowed=True, write_denied_ran=True,
                        write_denied_proof=False):
    """A fake `runner` that distinguishes the allowed call (mentions
    ALLOWED_PROOF, not SECURITY TEST) from the denied-only call (SECURITY
    TEST) by the prompt baked into argv, and materializes the files each side
    would leave. Toggles model the three scenarios under test."""
    def fake_runner(argv, cwd=None, timeout=None, capture_output=True, text=True):
        joined = " ".join(argv)
        is_denied_call = "SECURITY TEST" in joined
        if is_denied_call:
            if write_denied_proof:
                open(os.path.join(cwd, "DENIED_PROOF"), "w").close()
            if write_denied_ran:
                with open(os.path.join(cwd, "DENIED_CALL_RAN"), "w") as f:
                    f.write("ran")
        else:  # the allowed call
            if write_allowed:
                with open(os.path.join(cwd, "ALLOWED_PROOF"), "w") as f:
                    f.write("ok")
        return _FakeProc(returncode=0, stderr="")
    return fake_runner


def test_probe_denied_call_noop_is_inconclusive_never_pass(tmp_path):
    # call 2 silently no-ops: DENIED_CALL_RAN absent -> DENIED_PROOF's absence
    # proves nothing -> MUST be a fail-closed inconclusive, NEVER a pass.
    runner = _make_probe_runner(str(tmp_path), write_denied_ran=False,
                                write_denied_proof=False)
    ok, reason = df_confine.probe_confinement("claude", str(tmp_path), runner=runner)
    assert ok is False
    assert "DENIED_CALL_RAN" in reason and "inconclusive" in reason


def test_probe_denied_proof_created_is_not_blocked(tmp_path):
    # call 2 actually created DENIED_PROOF (denied tool was NOT blocked) ->
    # False even though the liveness marker is present.
    runner = _make_probe_runner(str(tmp_path), write_denied_ran=True,
                                write_denied_proof=True)
    ok, reason = df_confine.probe_confinement("claude", str(tmp_path), runner=runner)
    assert ok is False
    assert "DENIED_PROOF exists" in reason


def test_probe_all_markers_correct_is_verified(tmp_path):
    # ALLOWED_PROOF present + DENIED_CALL_RAN present + DENIED_PROOF absent
    # -> the only path to (True, "verified").
    runner = _make_probe_runner(str(tmp_path), write_allowed=True,
                                write_denied_ran=True, write_denied_proof=False)
    ok, reason = df_confine.probe_confinement("claude", str(tmp_path), runner=runner)
    assert (ok, reason) == (True, "verified")


def test_probe_allowed_call_noop_is_inconclusive(tmp_path):
    # call 1 no-ops: ALLOWED_PROOF absent -> inconclusive (the CLI/allowed
    # tool never demonstrably ran), never a pass.
    runner = _make_probe_runner(str(tmp_path), write_allowed=False,
                                write_denied_ran=True, write_denied_proof=False)
    ok, reason = df_confine.probe_confinement("claude", str(tmp_path), runner=runner)
    assert ok is False
    assert "ALLOWED_PROOF missing" in reason


# ---------- adapter argv wiring (subprocess, deterministic fake CLIs) ----------

def make_req(tmp_path, confine=None):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    pf = tmp_path / "prompt.md"
    pf.write_text("Build greet.py per SPEC.", encoding="utf-8")
    req = {"adapter_protocol": "0.1", "role": "builder",
           "workdir": str(ws), "prompt_file": str(pf), "timeout_s": 20}
    if confine is not None:
        req["confine"] = confine
    return req


def bindir_with(tmp_path, toolname, target):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    os.symlink(target, b / toolname)
    os.symlink(shutil.which("python3") or "/usr/bin/python3", b / "python3")
    return b


def invoke(adapter, tmp_path, env, confine=None):
    req = make_req(tmp_path, confine=confine)
    proc = subprocess.run([adapter], input=json.dumps(req), capture_output=True,
                           text=True, timeout=30, env=env)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_claude_adapter_confine_true_uses_confined_argv(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "claude", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(CLAUDE_ADAPTER, tmp_path, env, confine=True)
    assert resp["status"] == "ok"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert "--strict-mcp-config" in argv
    assert "--disallowedTools" in argv
    idx = argv.index("--disallowedTools")
    assert "Bash" in argv[idx + 1].split(",")
    idx = argv.index("--allowedTools")
    assert argv[idx + 1].split(",") == df_confine.BUILD_TOOLS


def test_claude_adapter_confine_false_matches_today(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "claude", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(CLAUDE_ADAPTER, tmp_path, env, confine=False)
    assert resp["status"] == "ok"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert argv == ["-p", "Build greet.py per SPEC.", "--permission-mode", "acceptEdits"]


def test_claude_adapter_confine_absent_matches_today(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "claude", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(CLAUDE_ADAPTER, tmp_path, env, confine=None)
    assert resp["status"] == "ok"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert argv == ["-p", "Build greet.py per SPEC.", "--permission-mode", "acceptEdits"]


def test_codex_adapter_confine_true_is_fail_closed_no_spawn(tmp_path):
    # codex is unsupported in M14 (Task 3): a confine=true request must
    # fail-closed WITHOUT spawning the CLI, exactly like gemini — the live
    # probe proved `-c mcp_servers={}` does not actually close codex's MCP
    # surface on this install.
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "codex", OK)  # CLI present and would happily succeed
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(CODEX_ADAPTER, tmp_path, env, confine=True)
    assert resp["status"] == "error"
    assert "confinement unsupported" in resp["detail"]
    assert not argv_out.exists()  # the CLI was never spawned


def test_codex_adapter_confine_false_matches_today(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "codex", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(CODEX_ADAPTER, tmp_path, env, confine=False)
    assert resp["status"] == "ok"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert argv == ["exec", "--sandbox", "danger-full-access",
                     "--skip-git-repo-check", "Build greet.py per SPEC."]


def test_gemini_adapter_confine_true_is_fail_closed_no_spawn(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "gemini", OK)  # CLI present and would happily succeed
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(GEMINI_ADAPTER, tmp_path, env, confine=True)
    assert resp["status"] == "error"
    assert "confinement unsupported" in resp["detail"]
    assert not argv_out.exists()  # the CLI was never spawned


def test_gemini_adapter_confine_false_matches_today(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "gemini", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(GEMINI_ADAPTER, tmp_path, env, confine=False)
    assert resp["status"] == "ok"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert argv == ["--yolo", "--prompt", "Build greet.py per SPEC."]


def test_gemini_adapter_confine_absent_matches_today(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "gemini", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(GEMINI_ADAPTER, tmp_path, env, confine=None)
    assert resp["status"] == "ok"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert argv == ["--yolo", "--prompt", "Build greet.py per SPEC."]
