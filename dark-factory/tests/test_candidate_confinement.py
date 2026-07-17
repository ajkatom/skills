"""M29b (DF-02 host-read half): default-deny CANDIDATE sandbox at standard.

Three layers, mirroring the M27 candidate_network test split:
- unit: profile construction (exact port pinning, clause ordering, tier/config
  validation, Linux legacy passthrough) -- no sandbox needed;
- live (macOS sandbox-exec): the confinement probe against a real workspace,
  port-pinning non-vacuity through a wrapped child, and the HONESTY property
  (whatever the machine measures for keychain/DNS, the report's residuals and
  the qualified derivation must MATCH it -- the tests assert consistency with
  measured reality, never a wished-for outcome);
- e2e (macOS): a real supervisor.py standard run converges under default-deny
  with the sealed manifest host_isolation field, and the allow_host_read
  opt-out is honestly marked unqualified.
"""
import json
import os
import socket
import subprocess
import sys

import pytest

import df_config
import df_sandbox
import supervisor
from test_supervisor import FAKE, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")

_macos = df_sandbox.BACKENDS["darwin"]
_linux = df_sandbox.BACKENDS["linux"]

needs_live = pytest.mark.skipif(
    sys.platform != "darwin" or not _macos.available(),
    reason="live macOS sandbox-exec required")


# ---------------------------------------------------------------- unit: profile

def _profile(**kw):
    argv = _macos.wrap_candidate_prefix("/tmp/df-deny", "/tmp/df-ws", **kw)
    assert argv[:2] == ["sandbox-exec", "-p"]
    return argv[2]


def test_profile_is_default_deny_with_last_deny_root():
    p = _profile()
    assert p.startswith("(version 1)(deny default)")
    real_deny = os.path.realpath("/tmp/df-deny")
    # deny_root denies are the LAST clauses (SBPL last-match-wins: nothing
    # may override them).
    assert p.endswith(
        f'(deny file-read* (subpath "{real_deny}"))'
        f'(deny file-write* (subpath "{real_deny}"))')


def test_profile_denies_home_and_reallows_workspace_after():
    p = _profile()
    home = os.path.realpath(os.path.expanduser("~"))
    ws = os.path.realpath("/tmp/df-ws")
    home_deny = f'(deny file-read* (subpath "{home}"))'
    assert home_deny in p
    # The workspace read allow must come AFTER the $HOME deny (last match
    # wins; a workspace under $HOME must stay usable).
    assert p.index(home_deny) < p.index(f'(allow file-read* (subpath "{ws}")')


def test_profile_loopback_pins_exact_ports_never_wildcard():
    p = _profile(network="loopback", allowed_loopback_ports=[8081, 9090, 8081])
    assert '(allow network-outbound (remote ip "localhost:8081"))' in p
    assert '(allow network-outbound (remote ip "localhost:9090"))' in p
    assert 'network-outbound (remote ip "localhost:*")' not in p
    assert '(allow network* (remote ip "localhost:*"))' not in p
    # inbound for a LISTENING candidate (M20 HTTP oracle) -- bind/inbound
    # specifically, never the network*-local form M27 measured as an egress
    # regression.
    assert '(allow network-bind (local ip "localhost:*"))' in p
    assert '(allow network-inbound (local ip "localhost:*"))' in p
    assert '(allow network* (local ip "localhost:*"))' not in p
    # loopback must NOT open the DNS mach channel.
    assert df_sandbox._MACH_DNS_SERVICE not in p


def test_profile_deny_mode_has_no_network_allows_and_no_dns():
    p = _profile(network="deny")
    assert "(allow network" not in p
    assert "(deny network*)" in p
    assert df_sandbox._MACH_DNS_SERVICE not in p


def test_profile_unrestricted_opens_network_and_dns_only():
    p = _profile(network="unrestricted")
    assert "(allow network*)" in p
    assert f'(allow mach-lookup (global-name "{df_sandbox._MACH_DNS_SERVICE}"))' in p
    # keychain stays closed in EVERY mode.
    assert df_sandbox._MACH_KEYCHAIN_SERVICE not in p


def test_profile_carves_out_system_data_leaves():
    # Finding 1/2: keychain FILES + brew service confs/DB data sit inside the
    # broad /Library and /opt/homebrew|/usr/local reads but are not $HOME, so
    # they need explicit last-match-wins carve-outs.
    p = _profile()
    carve = ('(deny file-read* (subpath "/Library/Keychains") '
             '(subpath "/opt/homebrew/etc") (subpath "/opt/homebrew/var") '
             '(subpath "/usr/local/etc") (subpath "/usr/local/var"))')
    assert carve in p
    # ordering: the carve-out deny comes AFTER the broad system read allow it
    # narrows, and (like every other deny that must not be re-opened) nothing
    # re-allows those exact subpaths afterward.
    assert p.index('(allow file-read* (subpath "/usr")') < p.index(carve)
    assert '(allow file-read* (subpath "/Library/Keychains"' not in p
    assert '(allow file-read* (subpath "/opt/homebrew/etc"' not in p


def test_profile_scratch_dirs_are_read_write():
    p = _profile(scratch_dirs=("/tmp/df-scratch",))
    real = os.path.realpath("/tmp/df-scratch")
    assert f'(subpath "{real}")' in p
    # present in both a read and a write allow
    read_part = p[p.index("(allow file-read* (subpath"):]
    assert f'(subpath "{real}")' in read_part


def test_profile_rejects_bad_modes_and_ports():
    with pytest.raises(df_sandbox.SandboxError):
        _profile(network="nope")
    for bad in (0, 65536, True, "80", None):
        with pytest.raises(df_sandbox.SandboxError):
            _profile(network="loopback", allowed_loopback_ports=[bad])


def test_linux_wrap_candidate_prefix_is_legacy_passthrough():
    # Honest legacy: identical argv to the M27 wrapper, ports/scratch ignored.
    a = _linux.wrap_candidate_prefix("/tmp/d", "/tmp/w", network="deny",
                                     allowed_loopback_ports=[1234],
                                     scratch_dirs=("/tmp/s",))
    b = _linux.wrap_prefix("/tmp/d", "/tmp/w", network="deny")
    assert a == b


# ---------------------------------------------------------------- unit: config

def _cfg_dict(tmp_path, assurance, **extra):
    cr = tmp_path / "cr"
    (cr / "scenarios").mkdir(parents=True)
    (cr / "scenarios" / "s0.json").write_text(json.dumps({
        "ir_version": "0.1", "id": "BHV-1-S1", "behavior_id": "BHV-1",
        "title": "t", "given": "g",
        "when": {"run": ["true"], "timeout_s": 5},
        "then": {"exit_code": 0},
    }), encoding="utf-8")
    (cr / "spec.md").write_text("# s", encoding="utf-8")
    cfg = {
        "config_version": "0.1", "autonomy": 4, "assurance": assurance,
        "feedback": "ids", "max_iterations": 2,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": FAKE, "timeout_s": 30}},
        "budget": {"billing": "subscription"}, "checkpoint": "auto",
    }
    cfg.update(extra)
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return df_config.load_config(str(cr))


def test_config_default_deny_is_the_default_at_standard(tmp_path):
    cfg = _cfg_dict(tmp_path, "standard")
    assert cfg["candidate_host_read"] == "default_deny"


def test_config_cooperative_defaults_to_allow_host_read(tmp_path):
    cfg = _cfg_dict(tmp_path, "cooperative")
    assert cfg["candidate_host_read"] == "allow_host_read"


def test_config_explicit_optout_accepted_at_standard(tmp_path):
    cfg = _cfg_dict(tmp_path, "standard", candidate_host_read="allow_host_read")
    assert cfg["candidate_host_read"] == "allow_host_read"


def test_config_default_deny_rejected_at_cooperative(tmp_path):
    with pytest.raises(df_config.ConfigError):
        _cfg_dict(tmp_path, "cooperative", candidate_host_read="default_deny")


def test_config_bad_value_rejected(tmp_path):
    with pytest.raises(df_config.ConfigError):
        _cfg_dict(tmp_path, "standard", candidate_host_read="definitely_not_a_mode")


# ------------------------------------------------------- unit: supervisor bits

def test_host_isolation_qualified_derivation():
    q = supervisor._host_isolation_qualified
    assert q("default_deny", True, [df_sandbox.RESIDUAL_METADATA]) is True
    assert q("default_deny", True, [df_sandbox.RESIDUAL_METADATA,
                                    df_sandbox.RESIDUAL_NET_UNRESTRICTED]) is True
    assert q("default_deny", True, [df_sandbox.RESIDUAL_KEYCHAIN_OPEN]) is False
    assert q("default_deny", True, [df_sandbox.RESIDUAL_DNS_OPEN]) is False
    assert q("default_deny", False, []) is False
    assert q("allow_host_read_optout", True, []) is False
    assert q("legacy_allow_host_read", True, []) is False


def test_candidate_prefix_for_twins_passthrough_outside_default_deny():
    base = ["some", "prefix"]
    for hi in (None, {}, {"mode": "allow_host_read_optout"},
               {"mode": "legacy_allow_host_read"}, {"mode": "none"}):
        assert supervisor._candidate_prefix_for_twins(
            {"_control_root": "/x", "candidate_network": "loopback"},
            hi, "/tmp/w", base, {"DF_TWIN_A": "127.0.0.1:1234"}) is base


@pytest.mark.skipif(sys.platform != "darwin", reason="uses the real macOS backend")
def test_candidate_prefix_for_twins_pins_this_pass_ports(tmp_path):
    cfg = {"_control_root": str(tmp_path / "cr"), "candidate_network": "loopback"}
    hi = {"mode": "default_deny"}
    twin_env = {"DF_TWIN_A": "127.0.0.1:4501", "DF_TWIN_B": "127.0.0.1:4502",
                "DF_TWIN_BROKEN": "not-an-endpoint"}
    argv = supervisor._candidate_prefix_for_twins(cfg, hi, str(tmp_path / "ws"),
                                                  ["base"], twin_env)
    profile = argv[2]
    assert '(allow network-outbound (remote ip "localhost:4501"))' in profile
    assert '(allow network-outbound (remote ip "localhost:4502"))' in profile
    # the unparsable endpoint is SKIPPED (fail closed), never a wildcard
    assert 'localhost:*"))' not in profile.split("network-bind")[0]


# -------------------------------------------------------------------- live

@needs_live
def test_probe_passes_and_reports_measured_truth(tmp_path):
    """The HONESTY test: whatever this machine measures, the residual list
    and check transcript must agree with each other -- for keychain, DNS
    (per network mode) and the structural metadata residual."""
    ws = tmp_path / "ws"; ws.mkdir()
    dr = tmp_path / "deny"; dr.mkdir()
    for mode in ("deny", "loopback", "unrestricted"):
        ok, rep = df_sandbox.probe_candidate_confinement(
            _macos, str(dr), str(ws), mode)
        assert ok, rep
        assert rep["mode"] == "default_deny"
        checks, residuals = rep["checks"], rep["residuals"]
        # honesty couplings (measured truth, not aspiration):
        assert (checks["keychain"] == "DF-KC-DENIED") == (
            df_sandbox.RESIDUAL_KEYCHAIN_OPEN not in residuals)
        if mode in ("deny", "loopback"):
            assert (checks["dns"] == "DF-DNS-DENIED") == (
                df_sandbox.RESIDUAL_DNS_OPEN not in residuals)
        else:
            assert df_sandbox.RESIDUAL_NET_UNRESTRICTED in residuals
        assert df_sandbox.RESIDUAL_METADATA in residuals
        # core file isolation is unconditionally proven when ok:
        assert checks["control_root_read"] == "DF-READ-DENIED"
        assert checks["outside_read"] == "DF-READ-DENIED"
        assert checks["home_read"] == "DF-HOME-DENIED"
        assert checks["workspace_write"] == "DF-WS-WRITE-OK"
        assert checks["outside_write"] == "DF-WRITE-DENIED"
        assert checks["subprocess_spawn"] == "DF-SPAWN-OK"
        if mode == "loopback":
            assert checks["net_loopback_allowed_port"] == "DF-NET-LOOPBACK-ALLOWED"
            assert checks["net_loopback_other_port"] == "DF-PORT-DENIED"


@needs_live
def test_port_pinning_is_nonvacuous_through_a_wrapped_child(tmp_path):
    """Direct regression net for the pinning itself, independent of the
    probe's own plumbing: one wrapper, two live listeners, only the pinned
    port reachable."""
    ws = tmp_path / "ws"; ws.mkdir()
    dr = tmp_path / "deny"; dr.mkdir()
    a = socket.socket(); a.bind(("127.0.0.1", 0)); a.listen(1)
    b = socket.socket(); b.bind(("127.0.0.1", 0)); b.listen(1)
    try:
        ap, dp = a.getsockname()[1], b.getsockname()[1]
        prefix = _macos.wrap_candidate_prefix(str(dr), str(ws), network="loopback",
                                              allowed_loopback_ports=[ap])
        code = ("import socket, sys\n"
                "def c(p):\n"
                "    try:\n"
                "        socket.create_connection(('127.0.0.1', p), timeout=3).close()\n"
                "        return 'OK'\n"
                "    except OSError:\n"
                "        return 'DENIED'\n"
                f"print(c({ap}), c({dp}))\n")
        proc = subprocess.run(prefix + [sys.executable, "-c", code],
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "OK DENIED"
    finally:
        a.close(); b.close()


@needs_live
def test_system_data_carveouts_deny_real_sensitive_files(tmp_path):
    """Finding 1/2 regression net: the actual world-readable sensitive files
    (keychains, brew service dir) must be DENIED inside the wrapper even
    though the broad /Library and /opt/homebrew reads nominally cover them.
    Non-vacuous: each target is asserted readable UNWRAPPED first (else there
    is nothing to prove on this host, and it is skipped)."""
    ws = tmp_path / "ws"; ws.mkdir()
    dr = tmp_path / "deny"; dr.mkdir()
    prefix = _macos.wrap_candidate_prefix(str(dr), str(ws), network="deny")

    def readable_unwrapped(p):
        try:
            if os.path.isdir(p):
                os.listdir(p)
            else:
                with open(p, "rb") as fh:
                    fh.read(1)
            return True
        except OSError:
            return False

    targets = [t for t in df_sandbox._SYSTEM_DATA_PROBE_TARGETS if readable_unwrapped(t)]
    if not targets:
        pytest.skip("no sensitive-data targets present on this host")
    code = ("import os, sys\n"
            "for p in sys.argv[1:]:\n"
            "    try:\n"
            "        (os.listdir(p) if os.path.isdir(p) else open(p, 'rb').read(1))\n"
            "        print(p, 'LEAKED')\n"
            "    except PermissionError:\n"
            "        print(p, 'DENIED')\n"
            "    except Exception as e:\n"
            "        print(p, 'OTHER', type(e).__name__)\n")
    proc = subprocess.run(prefix + [sys.executable, "-c", code, *targets],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    for line in proc.stdout.splitlines():
        assert line.endswith("DENIED"), f"sensitive path not denied: {line!r}"

    # and the probe's own check must reflect the same reality:
    ok, rep = df_sandbox.probe_candidate_confinement(_macos, str(dr), str(ws), "deny")
    assert ok, rep
    assert rep["checks"]["system_data_carveout"] == "DF-SYSDATA-DENIED"
    assert df_sandbox.RESIDUAL_SYSTEM_DATA_OPEN not in rep["residuals"]


@needs_live
def test_probe_fails_closed_if_carveout_removed(monkeypatch, tmp_path):
    """The carve-out can't silently regress: strip the deny clause and the
    probe must return ok=False with the disqualifying system-data residual."""
    ws = tmp_path / "ws"; ws.mkdir()
    dr = tmp_path / "deny"; dr.mkdir()
    # need at least one real target to make the negative test non-vacuous
    if not any(os.path.exists(t) for t in df_sandbox._SYSTEM_DATA_PROBE_TARGETS):
        pytest.skip("no sensitive-data targets present on this host")
    orig = _macos.wrap_candidate_prefix
    clause = ('(deny file-read* (subpath "/Library/Keychains") '
              '(subpath "/opt/homebrew/etc") (subpath "/opt/homebrew/var") '
              '(subpath "/usr/local/etc") (subpath "/usr/local/var"))')

    def stripped(deny_root, workspace, **kw):
        argv = orig(deny_root, workspace, **kw)
        assert clause in argv[2], "carve-out clause string drifted -- update this test"
        argv[2] = argv[2].replace(clause, "")
        return argv

    monkeypatch.setattr(_macos, "wrap_candidate_prefix", stripped)
    ok, rep = df_sandbox.probe_candidate_confinement(_macos, str(dr), str(ws), "deny")
    assert ok is False
    assert rep["checks"]["system_data_carveout"].startswith("DF-SYSDATA-LEAKED")
    assert df_sandbox.RESIDUAL_SYSTEM_DATA_OPEN in rep["residuals"]


@needs_live
def test_home_canary_denied_workspace_writable(tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    dr = tmp_path / "deny"; dr.mkdir()
    prefix = _macos.wrap_candidate_prefix(str(dr), str(ws), network="deny")
    home = os.path.expanduser("~")
    code = ("import os, sys\n"
            "home, ws = sys.argv[1], sys.argv[2]\n"
            "try:\n"
            "    os.listdir(home)\n"
            "    print('HOME-LEAKED')\n"
            "except PermissionError:\n"
            "    print('HOME-DENIED')\n"
            "open(os.path.join(ws, 'out.txt'), 'w').write('x')\n"
            "print('WS-OK')\n")
    proc = subprocess.run(prefix + [sys.executable, "-c", code, home, str(ws)],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["HOME-DENIED", "WS-OK"]
    assert (ws / "out.txt").read_text() == "x"


# -------------------------------------------------------------------- e2e

def _std_control(tmp_path, **cfg_extra):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["assurance"] = "standard"
    cfg.update(cfg_extra)
    p.write_text(json.dumps(cfg))
    return cr


def _run_supervisor(cr):
    proc = subprocess.run([sys.executable, SUP, "run", "--control-root", str(cr)],
                          capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text())
    return manifest, run_dir


@needs_live
def test_e2e_standard_run_is_default_deny_and_sealed(tmp_path):
    manifest, run_dir = _run_supervisor(_std_control(tmp_path))
    assert manifest["outcome"] == "COMPLETE_QUALIFIED"
    hi = manifest["host_isolation"]
    assert hi["mode"] == "default_deny"
    assert hi["probed"] is True and hi["passed"] is True
    # qualified must be DERIVED from the measured residuals, honestly:
    assert hi["qualified"] == supervisor._host_isolation_qualified(
        hi["mode"], hi["passed"], hi["residuals"])
    states = [json.loads(l)["state"] for l in
              (run_dir / "journal.jsonl").read_text().splitlines()]
    assert "HOST_ISOLATION" in states


@needs_live
def test_e2e_optout_is_marked_unqualified(tmp_path):
    manifest, _ = _run_supervisor(
        _std_control(tmp_path, candidate_host_read="allow_host_read"))
    assert manifest["outcome"] == "COMPLETE_QUALIFIED"
    hi = manifest["host_isolation"]
    assert hi["mode"] == "allow_host_read_optout"
    assert hi["qualified"] is False
    assert df_sandbox.RESIDUAL_HOST_READ_OPEN in hi["residuals"]
