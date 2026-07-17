"""DF-02 / M29a Task 1: candidate scenario subprocesses must run under a
minimal allowlisted env, NOT the full host environment -- SSH agent
sockets, proxy config, and cloud/API credentials must never reach candidate
code. See run_scenarios.candidate_env.
"""
import run_scenarios


_DANGEROUS = {
    "SSH_AUTH_SOCK": "/tmp/agent.sock",
    "HTTP_PROXY": "http://proxy.example:8080",
    "http_proxy": "http://proxy.example:8080",
    "AWS_SECRET_ACCESS_KEY": "aws-secret-value",
    "OPENAI_API_KEY": "sk-openai-value",
    "MY_SECRET_TOKEN": "should-never-leak",
}
_BENIGN_NOT_ALLOWLISTED = {"MY_HOST_THING": "host-only-value"}
_SAFE = {"PATH": "/usr/bin:/bin", "HOME": "/home/tester"}


def _set_host_env(monkeypatch):
    monkeypatch.setattr(run_scenarios.os, "environ", {})
    for name, value in {**_SAFE, **_DANGEROUS, **_BENIGN_NOT_ALLOWLISTED}.items():
        run_scenarios.os.environ[name] = value


def test_includes_safe_allowlisted_vars(monkeypatch):
    _set_host_env(monkeypatch)
    env = run_scenarios.candidate_env(None)
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/home/tester"


def test_excludes_dangerous_vars(monkeypatch):
    _set_host_env(monkeypatch)
    env = run_scenarios.candidate_env(None)
    for name in _DANGEROUS:
        assert name not in env, f"{name} leaked into candidate env"


def test_excludes_non_allowlisted_benign_var(monkeypatch):
    _set_host_env(monkeypatch)
    env = run_scenarios.candidate_env(None)
    assert "MY_HOST_THING" not in env


def test_env_extra_is_included(monkeypatch):
    _set_host_env(monkeypatch)
    env = run_scenarios.candidate_env(
        {"DF_TWIN_X": "http://127.0.0.1:9", "DF_CRED": "v"}
    )
    assert env["DF_TWIN_X"] == "http://127.0.0.1:9"
    assert env["DF_CRED"] == "v"
    # still safe + still scrubbed
    assert env["PATH"] == "/usr/bin:/bin"
    for name in _DANGEROUS:
        assert name not in env


def test_denylisted_var_in_os_environ_never_reaches_result_even_with_env_extra(monkeypatch):
    _set_host_env(monkeypatch)
    env = run_scenarios.candidate_env({"DF_TWIN_X": "http://127.0.0.1:9"})
    for name in _DANGEROUS:
        assert name not in env
