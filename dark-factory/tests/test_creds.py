import os
import subprocess
import sys

import pytest

import df_creds
from df_creds import CredsError, Redactor, check_gitignored, keychain_lookup, load_credentials, parse_env_file


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _run_git(args, cwd):
    return subprocess.run(
        ["git"] + list(args), cwd=str(cwd), capture_output=True, text=True
    )


def _git_init(repo_dir):
    repo_dir.mkdir(parents=True, exist_ok=True)
    assert _run_git(["init", "-q"], repo_dir).returncode == 0
    assert _run_git(["config", "user.email", "test@example.com"], repo_dir).returncode == 0
    assert _run_git(["config", "user.name", "Test"], repo_dir).returncode == 0
    return repo_dir


def _write_env_file(path, content, mode=0o600):
    path.write_text(content)
    os.chmod(str(path), mode)
    return path


class _FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# parse_env_file
# ---------------------------------------------------------------------------

def test_parse_env_file_happy_path(tmp_path):
    p = tmp_path / "secrets.env"
    _write_env_file(
        p,
        "\n".join([
            "# a comment",
            "",
            "PLAIN=value1",
            "export EXPORTED=value2",
            'DOUBLE_QUOTED="value with spaces"',
            "SINGLE_QUOTED='another value'",
            "",
        ]),
    )
    result = parse_env_file(str(p))
    assert result == {
        "PLAIN": "value1",
        "EXPORTED": "value2",
        "DOUBLE_QUOTED": "value with spaces",
        "SINGLE_QUOTED": "another value",
    }


def test_parse_env_file_malformed_line_reports_line_number(tmp_path):
    p = tmp_path / "secrets.env"
    _write_env_file(p, "GOOD=ok\nNOTANASSIGNMENT\n")
    with pytest.raises(CredsError) as exc:
        parse_env_file(str(p))
    assert "2" in str(exc.value)


def test_parse_env_file_empty_key_is_malformed(tmp_path):
    p = tmp_path / "secrets.env"
    _write_env_file(p, "=novalue\n")
    with pytest.raises(CredsError) as exc:
        parse_env_file(str(p))
    assert "1" in str(exc.value)


def test_parse_env_file_missing_file(tmp_path):
    p = tmp_path / "nope.env"
    with pytest.raises(CredsError):
        parse_env_file(str(p))


def test_parse_env_file_permissive_mode_0644_refused(tmp_path):
    p = tmp_path / "secrets.env"
    _write_env_file(p, "FOO=bar\n", mode=0o644)
    with pytest.raises(CredsError) as exc:
        parse_env_file(str(p))
    assert "permission" in str(exc.value).lower()


def test_parse_env_file_mode_0600_ok(tmp_path):
    p = tmp_path / "secrets.env"
    _write_env_file(p, "FOO=bar\n", mode=0o600)
    assert parse_env_file(str(p)) == {"FOO": "bar"}


# ---------------------------------------------------------------------------
# check_gitignored (real git)
# ---------------------------------------------------------------------------

def test_check_gitignored_ignored_file_ok(tmp_path):
    repo = _git_init(tmp_path / "repo")
    envfile = repo / "secrets.env"
    envfile.write_text("FOO=bar\n")
    (repo / ".gitignore").write_text("secrets.env\n")
    check_gitignored(str(envfile))  # must not raise


def test_check_gitignored_not_ignored_raises(tmp_path):
    repo = _git_init(tmp_path / "repo")
    envfile = repo / "secrets.env"
    envfile.write_text("FOO=bar\n")
    with pytest.raises(CredsError) as exc:
        check_gitignored(str(envfile))
    assert "not git-ignored" in str(exc.value)


def test_check_gitignored_tracked_file_raises_even_if_now_ignored(tmp_path):
    repo = _git_init(tmp_path / "repo")
    envfile = repo / "secrets.env"
    envfile.write_text("FOO=bar\n")
    assert _run_git(["add", "secrets.env"], repo).returncode == 0
    assert _run_git(["commit", "-q", "-m", "add secrets (oops)"], repo).returncode == 0
    # Now gitignore it after the fact.
    (repo / ".gitignore").write_text("secrets.env\n")
    with pytest.raises(CredsError) as exc:
        check_gitignored(str(envfile))
    assert "git-TRACKED" in str(exc.value)


def test_check_gitignored_outside_any_repo_ok(tmp_path):
    outside = tmp_path / "no_repo_here"
    outside.mkdir()
    envfile = outside / "secrets.env"
    envfile.write_text("FOO=bar\n")
    check_gitignored(str(envfile))  # must not raise


def test_check_gitignored_git_absent_ok(tmp_path):
    envfile = tmp_path / "secrets.env"
    envfile.write_text("FOO=bar\n")

    def fake_runner(*args, **kwargs):
        raise OSError("git binary not found")

    check_gitignored(str(envfile), runner=fake_runner)  # must not raise


# ---------------------------------------------------------------------------
# keychain_lookup
# ---------------------------------------------------------------------------

def test_keychain_lookup_success(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")

    def fake_runner(argv, **kwargs):
        assert argv == ["security", "find-generic-password", "-s", "dark-factory/FOO", "-w"]
        return _FakeResult(returncode=0, stdout="topsecret\n")

    assert keychain_lookup("dark-factory/FOO", runner=fake_runner) == "topsecret"


def test_keychain_lookup_empty_stdout_raises(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")

    def fake_runner(argv, **kwargs):
        return _FakeResult(returncode=0, stdout="   \n")

    with pytest.raises(CredsError):
        keychain_lookup("dark-factory/FOO", runner=fake_runner)


def test_keychain_lookup_nonzero_exit_raises_naming_service(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")

    def fake_runner(argv, **kwargs):
        return _FakeResult(returncode=44, stdout="")

    with pytest.raises(CredsError) as exc:
        keychain_lookup("dark-factory/FOO", runner=fake_runner)
    assert "dark-factory/FOO" in str(exc.value)


def test_keychain_lookup_oserror_raises(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")

    def fake_runner(argv, **kwargs):
        raise OSError("no security binary")

    with pytest.raises(CredsError):
        keychain_lookup("dark-factory/FOO", runner=fake_runner)


def test_keychain_lookup_timeout_raises(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")

    def fake_runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=10)

    with pytest.raises(CredsError):
        keychain_lookup("dark-factory/FOO", runner=fake_runner)


def test_keychain_lookup_non_darwin_raises(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    def fake_runner(argv, **kwargs):
        raise AssertionError("runner should not be called on non-darwin")

    with pytest.raises(CredsError) as exc:
        keychain_lookup("dark-factory/FOO", runner=fake_runner)
    assert "macOS" in str(exc.value)


# ---------------------------------------------------------------------------
# load_credentials
# ---------------------------------------------------------------------------

def test_load_credentials_env_file_resolves_exactly_the_allowlist(tmp_path):
    p = tmp_path / "secrets.env"
    _write_env_file(p, "A=1val\nB=2val\nEXTRA=not_allowlisted\n")
    spec = {"source": "env-file", "env_file": str(p), "allowlist": ["A", "B"]}
    result = load_credentials(spec)
    assert result == {"A": "1val", "B": "2val"}
    assert "EXTRA" not in result


def test_load_credentials_env_file_missing_allowlisted_name_raises(tmp_path):
    p = tmp_path / "secrets.env"
    _write_env_file(p, "A=1val\n")
    spec = {"source": "env-file", "env_file": str(p), "allowlist": ["A", "MISSING"]}
    with pytest.raises(CredsError):
        load_credentials(spec)


def test_load_credentials_env_source(monkeypatch):
    monkeypatch.setenv("DF_TEST_CRED_XYZ", "envvalue")
    spec = {"source": "env", "allowlist": ["DF_TEST_CRED_XYZ"]}
    assert load_credentials(spec) == {"DF_TEST_CRED_XYZ": "envvalue"}


def test_load_credentials_env_source_missing_raises(monkeypatch):
    monkeypatch.delenv("DF_TEST_CRED_MISSING", raising=False)
    spec = {"source": "env", "allowlist": ["DF_TEST_CRED_MISSING"]}
    with pytest.raises(CredsError):
        load_credentials(spec)


def test_load_credentials_keychain_source_uses_prefix_and_name(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")

    seen = []

    def fake_runner(argv, **kwargs):
        seen.append(argv)
        return _FakeResult(returncode=0, stdout="kcvalue\n")

    spec = {
        "source": "keychain",
        "service_prefix": "myapp/",
        "allowlist": ["FOO", "BAR"],
    }
    result = load_credentials(spec, runner=fake_runner)
    assert result == {"FOO": "kcvalue", "BAR": "kcvalue"}
    assert seen == [
        ["security", "find-generic-password", "-s", "myapp/FOO", "-w"],
        ["security", "find-generic-password", "-s", "myapp/BAR", "-w"],
    ]


def test_load_credentials_empty_value_raises(monkeypatch):
    monkeypatch.setenv("DF_TEST_CRED_EMPTY", "")
    spec = {"source": "env", "allowlist": ["DF_TEST_CRED_EMPTY"]}
    with pytest.raises(CredsError):
        load_credentials(spec)


def test_load_credentials_unknown_source_raises():
    spec = {"source": "carrier-pigeon", "allowlist": ["FOO"]}
    with pytest.raises(CredsError):
        load_credentials(spec)


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------

def test_redactor_single_value():
    r = Redactor(["mysecretvalue"])
    assert r.redact("prefix mysecretvalue suffix") == "prefix ***REDACTED*** suffix"


def test_redactor_multiple_values():
    r = Redactor(["secretone", "secrettwo"])
    text = "a=secretone b=secrettwo"
    redacted = r.redact(text)
    assert "secretone" not in redacted
    assert "secrettwo" not in redacted
    assert redacted.count("***REDACTED***") == 2


def test_redactor_longest_first_no_partial_leftover():
    short = "secret123"
    long_ = "secret123-extended-token"
    r = Redactor([short, long_])
    text = f"value is {long_} here, and also {short} alone"
    redacted = r.redact(text)
    assert short not in redacted
    assert long_ not in redacted
    assert redacted.count("***REDACTED***") == 2


def test_redactor_skips_short_values():
    r = Redactor(["abc12"])  # 5 chars, below MIN_LEN of 6
    text = "contains abc12 inline"
    assert r.redact(text) == text  # unchanged


def test_redactor_non_str_input_returned_unchanged():
    r = Redactor(["longenoughvalue"])
    assert r.redact(12345) == 12345
    assert r.redact(None) is None


def test_redactor_redact_obj_nested_shape_preserved():
    r = Redactor(["longenoughvalue"])
    obj = {
        "a": "contains longenoughvalue here",
        "b": ["longenoughvalue", "clean", 42, None],
        "c": ("longenoughvalue", "clean"),
        "d": {"nested": "longenoughvalue"},
        "e": True,
    }
    redacted = r.redact_obj(obj)
    assert redacted["a"] == "contains ***REDACTED*** here"
    assert redacted["b"] == ["***REDACTED***", "clean", 42, None]
    assert isinstance(redacted["b"], list)
    assert redacted["c"] == ("***REDACTED***", "clean")
    assert isinstance(redacted["c"], tuple)
    assert redacted["d"] == {"nested": "***REDACTED***"}
    assert redacted["e"] is True
