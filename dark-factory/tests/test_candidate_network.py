import json
import os
import sys

import pytest

import df_config
import df_sandbox
import supervisor
from test_config import write_config
from test_supervisor import FAKE, MARKER, setup_control

IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform == "linux"


def test_wrap_prefix_default_network_is_byte_identical(tmp_path):
    backend = df_sandbox.current_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    legacy = backend.wrap_prefix(str(deny), str(ws))
    explicit = backend.wrap_prefix(str(deny), str(ws), network="unrestricted")
    assert legacy == explicit


def test_wrap_prefix_rejects_unknown_network_mode(tmp_path):
    backend = df_sandbox.current_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    with pytest.raises(df_sandbox.SandboxError):
        backend.wrap_prefix(str(deny), str(ws), network="bogus")


@pytest.mark.skipif(not IS_MAC, reason="macOS sandbox-exec backend")
def test_macos_deny_and_loopback_modify_profile(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    deny_argv = backend.wrap_prefix(str(deny), str(ws), network="deny")
    loop_argv = backend.wrap_prefix(str(deny), str(ws), network="loopback")
    assert "(deny network*)" in deny_argv[-1]
    assert "(deny network*)" in loop_argv[-1]
    assert "localhost" in loop_argv[-1]


@pytest.mark.skipif(not IS_LINUX, reason="Linux bwrap backend")
def test_linux_deny_adds_unshare_net_and_loopback_raises(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._LinuxBackend()
    argv = backend.wrap_prefix(str(deny), str(ws), network="deny")
    assert "--unshare-net" in argv
    with pytest.raises(df_sandbox.SandboxError):
        backend.wrap_prefix(str(deny), str(ws), network="loopback")


def test_probe_unrestricted_passes_without_spawning(tmp_path):
    backend = df_sandbox.current_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(tmp_path), str(tmp_path), "unrestricted")
    assert ok is True


@pytest.mark.skipif(not IS_MAC, reason="live macOS sandbox probe")
def test_probe_deny_live_macos(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "deny")
    assert ok is True, reason


@pytest.mark.skipif(not IS_MAC, reason="live macOS sandbox probe")
def test_probe_loopback_live_macos(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "loopback")
    assert ok is True, reason


@pytest.mark.skipif(not IS_LINUX, reason="live bwrap probe")
def test_probe_deny_live_linux(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._LinuxBackend()
    if not backend.available():
        pytest.skip("bwrap not installed")
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "deny")
    assert ok is True, reason


def test_probe_rejects_unknown_network_mode(tmp_path):
    backend = df_sandbox.current_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(tmp_path), str(tmp_path), "bogus")
    assert ok is False


def test_probe_false_for_none_or_unavailable_backend(tmp_path):
    ok, reason = df_sandbox.probe_network_denial(
        None, str(tmp_path), str(tmp_path), "deny")
    assert ok is False


# ---------------------------------------------------------------------------
# df_config: `candidate_network` field (M27 Task 2, spec §7.4)
# ---------------------------------------------------------------------------

def _twindir(cr, n=1):
    d = cr / "twins"
    d.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (d / f"t{i}.json").write_text("{}", encoding="utf-8")


def test_candidate_network_default_is_unrestricted(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)  # default assurance: cooperative
    cfg = df_config.load_config(str(cr))
    assert cfg["candidate_network"] == "unrestricted"


@pytest.mark.parametrize("mode", ["unrestricted", "deny", "loopback"])
def test_candidate_network_valid_values_accepted_at_standard(tmp_path, mode):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard", candidate_network=mode)
    cfg = df_config.load_config(str(cr))
    assert cfg["candidate_network"] == mode


def test_candidate_network_bogus_value_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard", candidate_network="bogus")
    with pytest.raises(df_config.ConfigError, match="candidate_network"):
        df_config.load_config(str(cr))


def test_candidate_network_bool_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard", candidate_network=True)
    with pytest.raises(df_config.ConfigError, match="candidate_network"):
        df_config.load_config(str(cr))


def test_candidate_network_restricted_at_cooperative_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="cooperative", candidate_network="deny")
    with pytest.raises(df_config.ConfigError, match="cooperative has no sandbox"):
        df_config.load_config(str(cr))


def test_candidate_network_restricted_at_cooperative_loopback_also_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="cooperative", candidate_network="loopback")
    with pytest.raises(df_config.ConfigError, match="cooperative has no sandbox"):
        df_config.load_config(str(cr))


def test_candidate_network_deny_plus_twins_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard", candidate_network="deny",
                 twins={"enabled": True})
    _twindir(cr)
    with pytest.raises(df_config.ConfigError, match="unreachable"):
        df_config.load_config(str(cr))


def test_candidate_network_loopback_plus_twins_at_standard_accepted(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard", candidate_network="loopback",
                 twins={"enabled": True})
    _twindir(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["candidate_network"] == "loopback"
    assert cfg["_twins"]["enabled"] is True


def test_candidate_network_unrestricted_plus_twins_at_standard_accepted(tmp_path):
    # unrestricted is exempt from the deny+twins refusal even with twins on.
    cr = tmp_path / "control"
    write_config(cr, assurance="standard", candidate_network="unrestricted",
                 twins={"enabled": True})
    _twindir(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["candidate_network"] == "unrestricted"


# ---------------------------------------------------------------------------
# supervisor: candidate-ONLY network wrapper wiring (M27 Task 2)
# ---------------------------------------------------------------------------

GREET_PY = (
    "import sys\n"
    "if len(sys.argv) != 2:\n"
    "    print('usage: greet.py <name>', file=sys.stderr); sys.exit(2)\n"
    "print(f'Hello, {sys.argv[1]}!')\n"
)


class _FakeNetworkBackend:
    """A host-independent stand-in for the real OS backend: `available()` is
    forced True (so tests don't depend on bwrap/sandbox-exec actually being
    installed) but `wrap_prefix` DELEGATES to the real `_LinuxBackend` logic
    (pure Python argv construction, no bwrap binary needed to just build the
    list) so the candidate/builder wrapper argvs genuinely differ when a
    network restriction is requested -- not just a fake sentinel value.
    """
    name = "fake-network-backend"

    def __init__(self):
        self._real = df_sandbox._LinuxBackend()

    def available(self):
        return True

    def wrap_prefix(self, deny_root, workspace, network="unrestricted"):
        return self._real.wrap_prefix(deny_root, workspace, network=network)


def _patch_standard_backend(monkeypatch, network_ok=True, network_reason="ok"):
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend",
                        lambda: _FakeNetworkBackend())
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: True)
    monkeypatch.setattr(supervisor.df_sandbox, "probe_network_denial",
                        lambda *a, **k: (network_ok, network_reason))


class _FakeMacBackend:
    """Same rationale as `_FakeNetworkBackend` (host-independent, `available()`
    forced True, `wrap_prefix` delegates to a REAL backend's pure-Python argv
    construction) but delegates to `_MacOSBackend` instead of `_LinuxBackend`.
    Needed specifically for `candidate_network: "loopback"`: the real
    `_LinuxBackend.wrap_prefix` intentionally RAISES SandboxError for
    "loopback" (bwrap's own network namespace has no stable loopback
    semantics -- see df_sandbox.py / test_linux_deny_adds_unshare_net_and_
    loopback_raises above), whereas sandbox-exec's SBPL profile can express
    it. Using the macOS backend's real (if-unreachable-on-this-host) logic
    keeps this a genuine argv, not a fake sentinel, while staying host-
    independent (no @skipif needed)."""
    name = "fake-macos-backend"

    def __init__(self):
        self._real = df_sandbox._MacOSBackend()

    def available(self):
        return True

    def wrap_prefix(self, deny_root, workspace, network="unrestricted"):
        return self._real.wrap_prefix(deny_root, workspace, network=network)


def _patch_standard_macos_backend(monkeypatch, network_ok=True, network_reason="ok"):
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend",
                        lambda: _FakeMacBackend())
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: True)
    monkeypatch.setattr(supervisor.df_sandbox, "probe_network_denial",
                        lambda *a, **k: (network_ok, network_reason))


def _standard_control(tmp_path, **cfg_overrides):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "standard"
    cfg.update(cfg_overrides)
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cr


def _fake_invoke_capture(captured_builder):
    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, **kw):
        assert role == "builder"
        captured_builder.append(list(exec_prefix) if exec_prefix else [])
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None
    return fake_invoke


def _fake_run_all_capture(captured_verify):
    """Captures the exec_wrapper argv WITHOUT actually spawning any real
    subprocess through it: the real `wrap_prefix(..., network=...)` output
    (via _FakeNetworkBackend, delegating to the REAL _LinuxBackend logic) is
    a genuine bwrap argv, which this (possibly non-Linux, possibly
    bwrap-less) test host cannot actually execute. These wiring tests only
    care about WHICH wrapper argv reaches run_all vs invoke_adapter -- Task
    1's own df_sandbox tests already cover wrap_prefix/probe_network_denial
    correctness against a real sandbox. Always reports a clean pass so the
    loop converges in one iteration regardless of cohort.
    """
    def fake_run_all(scenarios_dir, workspace, exec_wrapper=None, env_extra=None, cohort=None,
                     observer_files=None, extra_scenarios_dir=None, verify_digests=None):
        captured_verify.append(list(exec_wrapper) if exec_wrapper else [])
        return {"results": [], "all_pass": True, "count": 0}
    return fake_run_all


def test_candidate_wrapper_unrestricted_identical_to_builder_prefix(tmp_path, monkeypatch):
    cr = _standard_control(tmp_path)  # candidate_network absent -> "unrestricted"
    _patch_standard_backend(monkeypatch)
    captured_builder, captured_verify = [], []
    monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke_capture(captured_builder))
    monkeypatch.setattr(supervisor, "run_all", _fake_run_all_capture(captured_verify))

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured_builder, "builder invoke_adapter was never called"
    assert captured_verify, "verifier run_all was never called"
    assert captured_verify[0] == captured_builder[0]


def test_candidate_wrapper_deny_differs_from_builder_prefix(tmp_path, monkeypatch):
    cr = _standard_control(tmp_path, candidate_network="deny")
    _patch_standard_backend(monkeypatch)
    captured_builder, captured_verify = [], []
    monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke_capture(captured_builder))
    monkeypatch.setattr(supervisor, "run_all", _fake_run_all_capture(captured_verify))

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert captured_builder, "builder invoke_adapter was never called"
    assert captured_verify, "verifier run_all was never called"
    assert captured_verify[0] != captured_builder[0]
    assert "--unshare-net" in captured_verify[0]
    assert "--unshare-net" not in captured_builder[0]

    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["candidate_network"] == "deny"


def test_candidate_network_probe_failure_exits_2_before_build(tmp_path, monkeypatch):
    cr = _standard_control(tmp_path, candidate_network="deny")
    _patch_standard_backend(monkeypatch, network_ok=False, network_reason="x")
    called = []

    def fake_invoke(*a, **k):
        called.append(1)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 2
    assert called == [], "builder must never be invoked when the network probe fails"

    run_id = os.listdir(cr / "runs")[0]
    states = [json.loads(l)["state"] for l in
              (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    assert "PROBE_FAILED" in states


def test_candidate_network_deny_plus_http_scenario_gate_refused(tmp_path, monkeypatch):
    cr = _standard_control(tmp_path, candidate_network="deny")
    http_sc = {
        "ir_version": "0.3", "id": "BHV-501-S1", "behavior_id": "BHV-501",
        "title": f"{MARKER} http", "given": f"{MARKER} service",
        "when": {
            "http": {
                "start": ["python3", "svc.py"],
                "port_env": "PORT",
                "ready_path": "/health",
                "request": {"method": "GET", "path": "/echo"},
            },
            "timeout_s": 10,
        },
        "then": {"http_status": 200, "body_contains": "ok"},
    }
    (cr / "scenarios" / "http.json").write_text(json.dumps(http_sc), encoding="utf-8")

    called = []

    def fake_invoke(*a, **k):
        called.append(1)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 2
    assert called == [], "builder must never be invoked on a candidate_network gate refusal"

    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "GATE_FAILED"


def test_candidate_network_loopback_plus_http_scenario_passes_gate(tmp_path, monkeypatch):
    """M27 Task 2 pre-build gate (supervisor.py ~1560): ONLY candidate_network
    == "deny" refuses a run with an http scenario -- "deny" blocks 127.0.0.1
    too, but "loopback" keeps 127.0.0.1 reachable (where the candidate's own
    http server binds), so a loopback + http combo must run PAST the gate.
    Mirrors test_candidate_network_deny_plus_http_scenario_gate_refused above
    but flips deny -> loopback and expects the run to proceed into the build
    stage instead of being refused with CANDIDATE_NETWORK_GATE_FAILED.
    """
    cr = _standard_control(tmp_path, candidate_network="loopback")
    http_sc = {
        "ir_version": "0.3", "id": "BHV-501-S1", "behavior_id": "BHV-501",
        "title": f"{MARKER} http", "given": f"{MARKER} service",
        "when": {
            "http": {
                "start": ["python3", "svc.py"],
                "port_env": "PORT",
                "ready_path": "/health",
                "request": {"method": "GET", "path": "/echo"},
            },
            "timeout_s": 10,
        },
        "then": {"http_status": 200, "body_contains": "ok"},
    }
    (cr / "scenarios" / "http.json").write_text(json.dumps(http_sc), encoding="utf-8")

    # Use the macOS-delegating fake backend (not the Linux one): the real
    # Linux bwrap backend refuses to build a "loopback" argv at all, which
    # would confound this test with an unrelated SandboxError. The gate
    # under test (supervisor.py ~1560) only inspects cfg["candidate_network"]
    # and scenario content -- it never touches the backend -- so which real
    # backend's wrap_prefix logic we delegate to is immaterial to what this
    # test proves.
    _patch_standard_macos_backend(monkeypatch)
    captured_builder, captured_verify = [], []
    monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke_capture(captured_builder))
    monkeypatch.setattr(supervisor, "run_all", _fake_run_all_capture(captured_verify))

    rc = supervisor.run(str(cr), None)

    run_id = os.listdir(cr / "runs")[0]
    entries = [json.loads(l) for l in
               (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    states = [e["state"] for e in entries]
    assert "CANDIDATE_NETWORK_GATE_FAILED" not in states, (
        "loopback + http must NOT trigger the deny+http pre-build gate")
    assert captured_builder, (
        "builder must have been invoked -- loopback+http should run past the gate "
        "into the build stage, not be refused before it")
    assert rc == 0


def test_candidate_network_restricted_downgrade_to_cooperative_fails_closed(tmp_path, monkeypatch):
    """M27 Task 2 runtime-downgrade fail-closed guard (resolve_candidate_prefix,
    supervisor.py ~1148-1154, called from both the fresh-run (~1721) and
    resume (~2746) call sites): a run CONFIGURED with a RESTRICTED
    candidate_network ("deny") at a CONFIGURED standard assurance tier can
    still resolve to the EFFECTIVE "cooperative" tier at RUNTIME when
    --allow-downgrade is set and the standard-tier OS sandbox probe fails.
    df_config's static load-time validation forbids restricted + configured-
    cooperative, but it cannot see a runtime downgrade reached AFTER load --
    and cooperative has no sandbox to enforce "deny", so the guard must fail
    closed (SandboxError -> clean exit 2), NEVER silently run the candidate
    unrestricted under an unqualified cooperative tier.

    Forces the standard->cooperative downgrade the same way
    test_standard_tier.py::test_standard_downgrades_with_flag does: fail the
    denial probe and hand back a real (if platform-mismatched) backend
    object, so resolve_isolation's `ok` check is False and --allow-downgrade
    takes the cooperative branch.
    """
    cr = _standard_control(tmp_path, candidate_network="deny")
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: False)
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend",
                        lambda: df_sandbox.BACKENDS["linux"])
    # Force the CANDIDATE network probe to pass so the only thing that can
    # possibly refuse this run is the runtime-downgrade guard under test --
    # not an incidental probe failure from running a Linux bwrap backend
    # object on a non-Linux test host (BACKENDS["linux"] here is a real
    # backend object used only to make resolve_isolation's initial `ok`
    # check False, per test_standard_tier.py's own pattern; it is not meant
    # to be live-probed).
    monkeypatch.setattr(supervisor.df_sandbox, "probe_network_denial",
                        lambda *a, **k: (True, "forced-ok-for-guard-isolation"))
    called = []

    def fake_invoke(*a, **k):
        called.append(1)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None, allow_downgrade=True)
    assert rc == 2
    assert called == [], ("builder must never be invoked when the candidate_network "
                          "runtime-downgrade guard fires (no build under an "
                          "unrestricted/unenforced candidate)")

    run_id = os.listdir(cr / "runs")[0]
    entries = [json.loads(l) for l in
               (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    states = [e["state"] for e in entries]
    assert "DOWNGRADE" in states, "standard -> cooperative downgrade should have happened first"
    assert "PROBE_FAILED" in states, ("the candidate_network guard's fail-closed refusal "
                                      "should have journaled PROBE_FAILED")
