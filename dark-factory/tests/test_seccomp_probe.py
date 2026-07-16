"""M22 Task 1: configurable + LIVE-PROBED enterprise seccomp.

M17 shipped one FIXED seccomp profile (scripts/seccomp/enterprise.json),
sanity-checked only offline (parses as JSON, has the right shape). That
proves nothing about what the profile actually DOES on a real kernel -- a
profile with `defaultAction: SCMP_ACT_ALLOW` and an empty (or wrong) deny
list parses fine and denies nothing. M22 Task 1 makes the profile an
operator knob (`enterprise.seccomp_profile`, df_config) that is (a)
JSON-shape-validated at config load, and (b) LIVE-PROBED at enterprise
resolve time (df_container.probe_seccomp) to prove it actually denies
mount/unshare/ptrace while still allowing an ordinary file write --
fail-closed: a profile that doesn't genuinely deny is rejected, never
silently trusted.

Three layers of coverage here:
  1. df_config: default profile injected when absent; bad path / non-JSON /
     missing `defaultAction` -> ConfigError; the shipped strict profile
     validates too.
  2. df_container.probe_seccomp: fully injected fake-runner matrix (no
     docker needed) -- proves the fail-closed decision logic itself.
  3. LIVE (skipif no docker): the real default profile denies for real; a
     deliberately-empty/loose profile does NOT get denied, proving the
     probe actually catches a toothless profile rather than rubber-stamping
     anything that merely parses.
"""
import json
import os

import pytest

import df_config
import df_container
import supervisor
from test_config import write_config
from test_enterprise_config import _base_enterprise, _approver


STRICT_PROFILE = os.path.join(
    os.path.dirname(os.path.abspath(df_container.__file__)), "seccomp", "enterprise-strict.json"
)


# ---------------------------------------------------------------------------
# df_config: enterprise.seccomp_profile
# ---------------------------------------------------------------------------

def _enterprise_cfg(tmp_path, **extra):
    cr = tmp_path / "control"
    approvers = [_approver()[1] for _ in range(3)]
    overrides = _base_enterprise(approvers=approvers, threshold=2, **extra)
    write_config(cr, **overrides)
    return cr


def test_default_profile_injected_when_absent(tmp_path):
    cr = _enterprise_cfg(tmp_path)
    cfg = df_config.load_config(str(cr))
    assert cfg["_enterprise"] == {"seccomp": df_container.DEFAULT_SECCOMP_PATH}
    assert os.path.isfile(cfg["_enterprise"]["seccomp"])


def test_explicit_default_path_equivalent_to_absent(tmp_path):
    cr = _enterprise_cfg(tmp_path, enterprise={"seccomp_profile": df_container.DEFAULT_SECCOMP_PATH})
    cfg = df_config.load_config(str(cr))
    assert cfg["_enterprise"]["seccomp"] == df_container.DEFAULT_SECCOMP_PATH


def test_strict_profile_validates_and_is_injected(tmp_path):
    cr = _enterprise_cfg(tmp_path, enterprise={"seccomp_profile": STRICT_PROFILE})
    cfg = df_config.load_config(str(cr))
    assert cfg["_enterprise"]["seccomp"] == os.path.abspath(STRICT_PROFILE)
    with open(cfg["_enterprise"]["seccomp"], encoding="utf-8") as f:
        data = json.load(f)
    assert data["defaultAction"] == "SCMP_ACT_ALLOW"
    for name in ("keyctl", "add_key", "request_key", "acct", "quotactl", "ioperm", "iopl"):
        assert name in data["syscalls"][0]["names"], name


def test_bad_path_rejected(tmp_path):
    cr = _enterprise_cfg(
        tmp_path, enterprise={"seccomp_profile": str(tmp_path / "does-not-exist.json")})
    with pytest.raises(df_config.ConfigError, match="does not exist"):
        df_config.load_config(str(cr))


def test_non_json_profile_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all {{{", encoding="utf-8")
    cr = _enterprise_cfg(tmp_path, enterprise={"seccomp_profile": str(bad)})
    with pytest.raises(df_config.ConfigError, match="not valid JSON"):
        df_config.load_config(str(cr))


def test_missing_default_action_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"syscalls": []}), encoding="utf-8")
    cr = _enterprise_cfg(tmp_path, enterprise={"seccomp_profile": str(bad)})
    with pytest.raises(df_config.ConfigError, match="defaultAction"):
        df_config.load_config(str(cr))


def test_missing_syscalls_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"defaultAction": "SCMP_ACT_ALLOW"}), encoding="utf-8")
    cr = _enterprise_cfg(tmp_path, enterprise={"seccomp_profile": str(bad)})
    with pytest.raises(df_config.ConfigError, match="syscalls"):
        df_config.load_config(str(cr))


def test_non_dict_json_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    cr = _enterprise_cfg(tmp_path, enterprise={"seccomp_profile": str(bad)})
    with pytest.raises(df_config.ConfigError, match="JSON object"):
        df_config.load_config(str(cr))


def test_enterprise_block_must_be_object(tmp_path):
    cr = _enterprise_cfg(tmp_path, enterprise=["not", "an", "object"])
    with pytest.raises(df_config.ConfigError, match="enterprise must be"):
        df_config.load_config(str(cr))


def test_seccomp_profile_must_be_non_empty_string(tmp_path):
    cr = _enterprise_cfg(tmp_path, enterprise={"seccomp_profile": ""})
    with pytest.raises(df_config.ConfigError, match="non-empty path"):
        df_config.load_config(str(cr))


def test_non_enterprise_tier_ignores_enterprise_block(tmp_path):
    # A non-enterprise tier never even looks at `enterprise.seccomp_profile`
    # (cfg["_enterprise"] stays None) -- back-compat, no behavior change.
    cr = tmp_path / "control"
    write_config(cr, enterprise={"seccomp_profile": str(tmp_path / "nope.json")})
    cfg = df_config.load_config(str(cr))
    assert cfg["_enterprise"] is None


# ---------------------------------------------------------------------------
# df_container.probe_seccomp -- fully injected fake-runner matrix
# ---------------------------------------------------------------------------

class _FakeProc:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


def _marker(mount_denied, unshare_denied, ptrace_denied, write_ok):
    result = {
        "mount_denied": mount_denied,
        "unshare_denied": unshare_denied,
        "ptrace_denied": ptrace_denied,
        "write_ok": write_ok,
    }
    return "DF-SECCOMP-PROBE " + json.dumps(result) + "\n"


def test_probe_seccomp_true_when_all_denied_and_write_ok(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(0, _marker(True, True, True, True))
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is True


def test_probe_seccomp_false_when_mount_not_denied(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(0, _marker(False, True, True, True))
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_unshare_not_denied(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(0, _marker(True, False, True, True))
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_ptrace_not_denied(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(0, _marker(True, True, False, True))
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_allowed_write_failed(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(0, _marker(True, True, True, False))
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_on_nonzero_rc_even_with_good_marker(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(1, _marker(True, True, True, True))
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_runner_raises_timeout(tmp_path):
    import subprocess as sp
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")

    def runner(*a, **k):
        raise sp.TimeoutExpired(cmd="docker run", timeout=120)

    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_runner_raises_oserror(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")

    def runner(*a, **k):
        raise OSError("docker not found")

    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_marker_missing(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(0, "no marker line here\n")
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_marker_unparseable_json(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(0, "DF-SECCOMP-PROBE not-json\n")
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_duplicate_marker_lines(tmp_path):
    # Ambiguous (two conflicting marker lines) -> False, never pick one.
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    stdout = _marker(True, True, True, True) + _marker(False, False, False, False)
    runner = lambda *a, **k: _FakeProc(0, stdout)
    assert df_container.probe_seccomp("img", str(profile), runner=runner) is False


def test_probe_seccomp_false_when_profile_path_missing(tmp_path):
    runner = lambda *a, **k: _FakeProc(0, _marker(True, True, True, True))
    assert df_container.probe_seccomp(
        "img", str(tmp_path / "does-not-exist.json"), runner=runner) is False


def test_probe_seccomp_false_on_bad_image_string(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    runner = lambda *a, **k: _FakeProc(0, _marker(True, True, True, True))
    assert df_container.probe_seccomp("-rm", str(profile), runner=runner) is False


def test_probe_seccomp_argv_shape(tmp_path):
    profile = tmp_path / "p.json"
    profile.write_text("{}", encoding="utf-8")
    seen = {}

    def runner(argv, **kwargs):
        seen["argv"] = argv
        return _FakeProc(0, _marker(True, True, True, True))

    df_container.probe_seccomp("myimage", str(profile), runner=runner)
    argv = seen["argv"]
    assert argv[0:3] == ["docker", "run", "--rm"]
    assert "--security-opt" in argv
    assert argv[argv.index("--security-opt") + 1] == f"seccomp={profile}"
    assert "--cap-add" in argv
    assert argv[argv.index("--cap-add") + 1] == "SYS_ADMIN"
    assert "myimage" in argv


# ---------------------------------------------------------------------------
# supervisor.resolve_isolation: a live-probe failure gates enterprise closed
# (self-review Q3), same discipline as the existing bad-path tests.
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


def _patch(monkeypatch, os_ok=True, dk_ok=True, seccomp_probe_ok=True):
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend", lambda: _FakeOSBackend())
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: os_ok)
    monkeypatch.setattr(supervisor.df_container, "docker_available", lambda: dk_ok)
    monkeypatch.setattr(supervisor.df_container, "probe_container", lambda *a, **k: dk_ok)
    monkeypatch.setattr(supervisor.df_container, "probe_seccomp",
                         lambda *a, **k: seccomp_probe_ok)


def test_resolve_isolation_valid_shape_but_live_probe_fails_downgrades(tmp_path, monkeypatch):
    _patch(monkeypatch, seccomp_probe_ok=False)
    j = _FakeJournal()
    cfg = {
        "assurance": "enterprise",
        "_container": {"image": "img", "network": "none", "memory": "2g", "pids": 256},
        "_enterprise": {"seccomp": df_container.DEFAULT_SECCOMP_PATH},
    }
    eff, prefix, backend, probe_passed = supervisor.resolve_isolation(
        cfg, str(tmp_path / "cr"), str(tmp_path / "ws"), j, True)
    assert eff == "hardened"
    assert any(s == "DOWNGRADE" and d.get("effective") == "hardened" for s, d in j.entries)


def test_resolve_isolation_valid_shape_but_live_probe_fails_raises_without_downgrade(tmp_path, monkeypatch):
    _patch(monkeypatch, seccomp_probe_ok=False)
    j = _FakeJournal()
    cfg = {
        "assurance": "enterprise",
        "_container": {"image": "img", "network": "none", "memory": "2g", "pids": 256},
        "_enterprise": {"seccomp": df_container.DEFAULT_SECCOMP_PATH},
    }
    with pytest.raises(supervisor.df_sandbox.SandboxError, match="enterprise"):
        supervisor.resolve_isolation(cfg, str(tmp_path / "cr"), str(tmp_path / "ws"), j, False)
    assert any(s == "PROBE_FAILED" for s, _d in j.entries)


def test_resolve_isolation_all_probes_ok_succeeds(tmp_path, monkeypatch):
    _patch(monkeypatch, seccomp_probe_ok=True)
    j = _FakeJournal()
    cfg = {
        "assurance": "enterprise",
        "_container": {"image": "img", "network": "none", "memory": "2g", "pids": 256},
        "_enterprise": {"seccomp": df_container.DEFAULT_SECCOMP_PATH},
    }
    result = supervisor.resolve_isolation(
        cfg, str(tmp_path / "cr"), str(tmp_path / "ws"), j, False)
    assert result == ("enterprise", [], df_container.ENTERPRISE_BACKEND_NAME, True)
    assert not j.entries


# ---------------------------------------------------------------------------
# LIVE probe -- requires a real docker daemon, skipif absent (mirrors
# test_enterprise_config.py's live egress probe / test_container.py).
# ---------------------------------------------------------------------------

DOCKER_LIVE = df_container.docker_available()


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_probe_seccomp_live_default_profile_denies_for_real():
    ok = df_container.probe_seccomp(df_container.DEFAULT_IMAGE, df_container.DEFAULT_SECCOMP_PATH)
    assert ok is True


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_probe_seccomp_live_strict_profile_denies_for_real():
    ok = df_container.probe_seccomp(df_container.DEFAULT_IMAGE, STRICT_PROFILE)
    assert ok is True


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_probe_seccomp_live_empty_profile_is_caught_as_loose(tmp_path):
    # A deliberately-empty allow-everything profile: defaultAction ALLOW,
    # no denials. The probe MUST catch this (mount not denied) -- proving
    # probe_seccomp isn't rubber-stamping anything that merely parses.
    loose = tmp_path / "loose.json"
    loose.write_text(json.dumps({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []}),
                      encoding="utf-8")
    ok = df_container.probe_seccomp(df_container.DEFAULT_IMAGE, str(loose))
    assert ok is False
