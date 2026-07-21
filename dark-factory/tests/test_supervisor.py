import json
import os
import socket

import pytest

import supervisor

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE = os.path.join(HERE, "fixtures", "fake_builder")
STUBBORN = os.path.join(HERE, "fixtures", "fake_builder_stubborn")
MARKER = "HOLDOUT-MARKER-93e1"

# M47 RA-08(a): a genuinely-qualified standard+ run now requires a CONFINED
# candidate network (deny/loopback) -- an unrestricted candidate egress is
# DISQUALIFYING (code CANDIDATE_EGRESS_OPEN). Two shared helpers below let the
# former COMPLETE_QUALIFIED tests keep asserting a QUALIFIED run without turning
# the default suite into a network-dependent one:
#
#   * IN-PROCESS tests set candidate_network="deny"/"loopback" and call
#     stub_network_probe(monkeypatch) so the egress-denial baseline probe passes
#     WITHOUT reaching outside localhost. The probe is NOT weakened -- its real
#     behavior is covered by test_candidate_network.py / test_e2e_candidate_
#     network.py's live tests; here we isolate the QUALIFICATION wiring from the
#     network round-trip so it stays hermetic.
#   * SUBPROCESS tests (which can't monkeypatch the child) use the `needs_network`
#     marker + external_reachable(): a real qualified run at deny/loopback DOES
#     connect outside localhost via the egress probe, so those are honest
#     external-network tests gated behind DF_ALLOW_NETWORK_TESTS.
NETWORK_TESTS_ENABLED = bool(os.environ.get("DF_ALLOW_NETWORK_TESTS"))
needs_network = pytest.mark.skipif(
    not NETWORK_TESTS_ENABLED,
    reason="reaches outside localhost to prove candidate-egress denial; "
           "set DF_ALLOW_NETWORK_TESTS=1 to run")


def external_reachable():
    """Baseline the egress-denial probe itself requires (same host/port). Only
    called from opt-in `needs_network` tests, so the hermetic default (which
    skips them) never opens this connection."""
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()
        return True
    except OSError:
        return False


def stub_network_probe(monkeypatch):
    """Make the candidate egress-denial probes pass without any network I/O, so
    an IN-PROCESS qualified-standard run at candidate_network="deny" stays
    hermetic. Both probes take a REAL external baseline connect at network=="deny"
    (the honest non-vacuity half): `probe_network_denial` on the allow-host-read
    path and `probe_candidate_confinement` on the default-deny path. We stub
    BOTH here -- the sandbox profile itself is still built and enforced; only the
    external baseline round-trip is substituted. The probes' real behavior is
    covered by test_candidate_network.py / test_e2e_candidate_network.py's live
    tests, so this only isolates the QUALIFICATION wiring from the network."""
    monkeypatch.setattr(supervisor.df_sandbox, "probe_network_denial",
                        lambda *a, **k: (True, "network probe stubbed (hermetic test)"))
    monkeypatch.setattr(supervisor.df_sandbox, "probe_candidate_confinement",
                        lambda *a, **k: (True, {"mode": "default_deny", "residuals": []}))


class _FakeDenyBackend:
    """A default-deny-capable sandbox double for IN-PROCESS qualified-standard
    convergence tests that fake resolve_isolation. Stubbing the probes alone is
    NOT enough on a host without the real primitive (GitHub's ubuntu runners
    ship no bwrap): resolve_candidate_prefix would still build a REAL candidate
    wrapper via df_sandbox.current_backend(), so every scenario dispatch either
    fail-closes before the loop ("no sandbox backend available", exit 2) or
    crashes on the missing binary and the run caps out. This double keeps the
    qualification WIRING identical (supports_default_deny, mode "default_deny",
    the soft process_group_escape residual -- same qualified host_isolation the
    macOS host backend produces) while the candidate runs unwrapped. The real
    profiles stay covered by test_candidate_confinement.py and the live tests,
    which skip honestly where the OS primitive is absent."""
    name = "fake-standard-backend"
    supports_default_deny = True
    provides_pid_namespace = False

    def available(self):
        return True

    def wrap_prefix(self, control_root, workspace, network=None, **kw):
        return []

    def wrap_candidate_prefix(self, control_root, workspace, network=None,
                              allowed_loopback_ports=None, **kw):
        return []


def stub_candidate_sandbox(monkeypatch):
    """Everything an in-process qualified-standard run needs to stay hermetic
    on ANY host: the network/confinement probes (stub_network_probe) plus a
    backend double so no real sandbox binary is ever exec'd. Pair with a faked
    supervisor.resolve_isolation for the builder half."""
    stub_network_probe(monkeypatch)
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend",
                        lambda: _FakeDenyBackend())

TOY_SPEC = """# greet CLI
Create an executable python file `greet.py` in the workspace root.
- `python3 greet.py <name>` prints exactly `Hello, <name>!` and exits 0.
- `python3 greet.py` with no arguments prints `usage: greet.py <name>` to stderr and exits 2.
"""


def scenario(sid, bid, run, then, title):
    return {
        "ir_version": "0.1", "id": sid, "behavior_id": bid,
        "title": title, "given": f"{MARKER} workspace has greet.py",
        "when": {"run": run, "timeout_s": 10}, "then": then,
    }


def setup_control(tmp_path, adapter, max_iterations=5, checkpoint=None):
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    config = {
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": max_iterations,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": adapter, "timeout_s": 30}},
        "budget": {"billing": "subscription"},
    }
    if checkpoint is not None:
        config["checkpoint"] = checkpoint
    (cr / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (cr / "spec.md").write_text(TOY_SPEC, encoding="utf-8")
    scs = [
        scenario("BHV-001-S1", "BHV-001", ["python3", "greet.py", "World"],
                 {"exit_code": 0, "stdout_equals": "Hello, World!"},
                 f"{MARKER} greets World"),
        scenario("BHV-001-S2", "BHV-001", ["python3", "greet.py", "Alon"],
                 {"exit_code": 0, "stdout_equals": "Hello, Alon!"},
                 f"{MARKER} greets Alon"),
        scenario("BHV-002-S1", "BHV-002", ["python3", "greet.py"],
                 {"exit_code": 2, "stderr_contains": "usage:"},
                 f"{MARKER} usage error"),
    ]
    for i, sc in enumerate(scs):
        (cr / "scenarios" / f"s{i}.json").write_text(json.dumps(sc), encoding="utf-8")
    return cr


def read_journal(cr):
    runs = os.listdir(cr / "runs")
    assert len(runs) == 1
    lines = (cr / "runs" / runs[0] / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in lines.strip().splitlines()], runs[0]


def test_converging_run_exits_zero_and_journals(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    # M7: the pre-build gate (GATE_PASSED) now runs between INIT and SNAPSHOT.
    assert states[0] == "INIT" and states[1] == "GATE_PASSED" and states[2] == "SNAPSHOT"
    assert "CONVERGED" in states and states[-1] == "CONVERGED"
    # two iterations: buggy then fixed
    assert states.count("BUILD") == 2 and states.count("FEEDBACK") == 1


def test_builder_model_identity_sealed_into_manifest(tmp_path):
    # DF-R4-09 (M55): an operator-ASSERTED roles.builder.model_identity is sealed
    # VERBATIM into the terminal manifest's `builder_identity`, so an auditor can
    # compare all three roles' declared identities from the manifest alone.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["roles"]["builder"]["model_identity"] = "anthropic/claude-opus-4"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    assert supervisor.run(str(cr), None) == 0
    _entries, run_id = read_journal(cr)
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    # Verbatim, operator-asserted (not verified) identity on the sealed manifest.
    assert manifest["builder_identity"] == {"model_identity": "anthropic/claude-opus-4"}


def test_builder_identity_absent_is_none_backcompat(tmp_path):
    # Absent roles.builder.model_identity -> builder_identity is None (byte-
    # identical manifest surface to pre-M55).
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.run(str(cr), None) == 0
    _entries, run_id = read_journal(cr)
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["builder_identity"] is None


def test_stubborn_run_hits_cap_with_exit_3(tmp_path):
    cr = setup_control(tmp_path, STUBBORN, max_iterations=2, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 3
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states[-1] == "CAP_REACHED" and states.count("BUILD") == 2
    # cap message names failing behaviors, not scenario content
    cap = entries[-1]["data"]
    assert cap["failing_behaviors"] == ["BHV-001"]


def test_lock_prevents_concurrent_runs(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    lock = supervisor.acquire_lock(str(cr))
    try:
        with pytest.raises(supervisor.LockError):
            supervisor.acquire_lock(str(cr))
    finally:
        supervisor.release_lock(lock)
    # released -> can acquire again
    supervisor.release_lock(supervisor.acquire_lock(str(cr)))


def test_stale_lock_is_reclaimed(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    cr_lock = cr / ".lock"
    cr_lock.write_text("999999999", encoding="utf-8")  # dead pid
    lock = supervisor.acquire_lock(str(cr))
    supervisor.release_lock(lock)


def test_adapter_hard_failure_aborts_with_exit_2(tmp_path):
    cr = setup_control(tmp_path, "/bin/false")  # exits nonzero, no protocol output
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    entries, _ = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BUILD_ERROR"


def test_prompt_contains_spec_and_feedback_but_never_scenarios(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    supervisor.run(str(cr), None)
    _, run_id = read_journal(cr)
    run_dir = cr / "runs" / run_id
    p1 = (run_dir / "prompt_iter_1.md").read_text(encoding="utf-8")
    p2 = (run_dir / "prompt_iter_2.md").read_text(encoding="utf-8")
    assert "greet.py" in p1 and MARKER not in p1
    assert "BHV-001" in p2 and MARKER not in p2  # iteration 2 carries ID feedback
    assert "Hello, <name>!" in p1  # spec text is fine — it is SHARED


def test_live_pid_lock_is_not_reclaimed(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    cr_lock = cr / ".lock"
    cr_lock.write_text(str(os.getpid()), encoding="utf-8")  # this process — alive
    with pytest.raises(supervisor.LockError):
        supervisor.acquire_lock(str(cr))


def test_run_on_locked_control_root_exits_2(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    lock = supervisor.acquire_lock(str(cr))
    try:
        assert supervisor.run(str(cr), None) == 2
    finally:
        supervisor.release_lock(lock)


def test_adapter_missing_status_aborts_with_exit_2(tmp_path):
    bad_adapter = tmp_path / "bad_adapter.py"
    bad_adapter.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({\"adapter_protocol\": \"0.1\"}))\n",
        encoding="utf-8",
    )
    os.chmod(str(bad_adapter), 0o755)
    cr = setup_control(tmp_path, str(bad_adapter))
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    entries, _ = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BUILD_ERROR"


def test_bad_project_src_exits_2(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    bad_src = tmp_path / "proj"
    bad_src.mkdir()
    (bad_src / "ok.txt").write_text("fine", encoding="utf-8")
    os.mkfifo(bad_src / "pipe")  # special file -> SnapshotError
    assert supervisor.run(str(cr), str(bad_src)) == 2
    entries, _ = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BUILD_ERROR"


def test_invalid_scenario_ir_exits_2(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    # clobber one scenario with structurally invalid IR (missing required keys)
    import json
    bad = next((cr / "scenarios").glob("*.json"))
    bad.write_text(json.dumps({"ir_version": "0.1"}), encoding="utf-8")
    assert supervisor.run(str(cr), None) == 2
    entries, _ = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BUILD_ERROR"
