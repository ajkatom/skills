"""M27 Task 3 (spec §7.4) live e2e: candidate_network actually bites through
the REAL run path, not just through df_sandbox's isolated probe.

Mirrors test_e2e_standard.py's control-root scaffolding (a real subprocess
supervisor.py run at assurance: standard) but the scenario's candidate
program attempts a genuine outbound TCP connect instead of just printing a
greeting -- so the restriction has something live to bite.

Test A (restriction bites, converges): candidate_network: "deny" -> the
candidate's connect attempt is denied by the OS sandbox wrapper supervisor.py
puts around the CANDIDATE (never the builder) at verify time; the scenario
expects stdout "DENIED" and the run CONVERGES. This proves denial through
the full run path: config load -> resolve_candidate_prefix -> live
probe_network_denial -> run_all(exec_wrapper=candidate_prefix) -> the
wrapped candidate process itself.

Test B (non-vacuity twin): the SAME control-root scaffolding, same builder,
same scenario shape, but candidate_network absent ("unrestricted") -> the
candidate CAN connect, expected stdout "CONNECTED", also converges. Without
this twin, Test A's "DENIED" could just as easily mean "the network was down"
or "the probe script is broken" -- Test B is the control that isolates the
restriction as the actual cause.

Both tests need real internet reachability to be non-vacuous (the same
fail-closed baseline df_sandbox.probe_network_denial requires): if the
external target isn't reachable from this host, SKIP rather than fail --
that mirrors the probe's own fail-closed discipline and is honest about an
offline/firewalled CI host, not a bug in the restriction.

macOS only: the sandbox-exec profile that provides "deny" is the backend
under test here, matching df_sandbox.py's own live-probe tests (see
test_candidate_network.py's test_probe_deny_live_macos /
test_probe_loopback_live_macos). Linux's bwrap --unshare-net "deny" path is
exercised by Task 1/2's unit + wiring tests already; a live Linux e2e
exercising the real external-connect proof through this same run path can
follow later -- not built here.
"""
import json
import os
import socket
import subprocess
import sys

import pytest

import df_sandbox

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
NETWORK_PROBE_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_network_probe")

SPEC = """# network probe
Create an executable python file `network_probe.py` in the workspace root
that attempts a TCP connection to 1.1.1.1:443 and:
- prints exactly `CONNECTED` and exits 0 if the connection succeeds
- prints exactly `DENIED` and exits 0 if the connection raises an OSError
"""


def _network_probe_scenario(expected_stdout):
    return {
        "ir_version": "0.1",
        "id": "BHV-701-S1",
        "behavior_id": "BHV-701",
        "title": f"network probe reports {expected_stdout}",
        "given": "workspace has network_probe.py",
        "when": {"run": ["python3", "network_probe.py"], "timeout_s": 15},
        "then": {"exit_code": 0, "stdout_equals": expected_stdout},
    }


def _setup_control(tmp_path, expected_stdout, candidate_network=None):
    """Same control-root scaffolding shape as test_e2e_standard.py /
    test_supervisor.setup_control (config.json, spec.md, scenarios/*.json,
    a builder adapter) but with the network-probe builder + scenario instead
    of the toy greet.py fixture -- assurance: standard from the start (this
    e2e only exercises the standard-tier live sandbox path)."""
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    config = {
        "config_version": "0.1", "autonomy": 4, "assurance": "standard",
        "feedback": "ids", "max_iterations": 3,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": NETWORK_PROBE_BUILDER, "timeout_s": 30}},
        "budget": {"billing": "subscription"},
        "checkpoint": "auto",
    }
    if candidate_network is not None:
        config["candidate_network"] = candidate_network
    (cr / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (cr / "spec.md").write_text(SPEC, encoding="utf-8")
    (cr / "scenarios" / "s0.json").write_text(
        json.dumps(_network_probe_scenario(expected_stdout)), encoding="utf-8")
    return cr


def _external_reachable():
    """Same baseline non-vacuity check df_sandbox.probe_network_denial does
    (same host/port), performed unwrapped from the test process itself,
    before ever spawning the real supervisor subprocess -- an offline/
    firewalled test host has nothing for this e2e to prove either way."""
    try:
        socket.create_connection(
            (df_sandbox._NET_PROBE_EXTERNAL_HOST, df_sandbox._NET_PROBE_EXTERNAL_PORT),
            timeout=3,
        ).close()
        return True
    except OSError:
        return False


def _run_and_assert_converged(cr, expected_candidate_network):
    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "COMPLETE_QUALIFIED" and manifest["qualified"] is True
    assert manifest["denial_probe_passed"] is True
    assert manifest["candidate_network"] == expected_candidate_network

    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    states = [json.loads(l)["state"] for l in lines]
    assert "CONVERGED" in states, f"run did not converge -- states={states}"
    return manifest


@pytest.mark.skipif(sys.platform != "darwin", reason="live macOS sandbox-exec candidate-network e2e")
def test_candidate_network_deny_bites_through_real_run_path(tmp_path):
    if not _external_reachable():
        pytest.skip("no external reachability for a non-vacuous candidate-network e2e")

    cr = _setup_control(tmp_path, expected_stdout="DENIED", candidate_network="deny")
    _run_and_assert_converged(cr, expected_candidate_network="deny")


@pytest.mark.skipif(sys.platform != "darwin", reason="live macOS sandbox-exec candidate-network e2e")
def test_candidate_network_unrestricted_is_the_nonvacuous_twin(tmp_path):
    if not _external_reachable():
        pytest.skip("no external reachability for a non-vacuous candidate-network e2e")

    cr = _setup_control(tmp_path, expected_stdout="CONNECTED", candidate_network=None)
    _run_and_assert_converged(cr, expected_candidate_network="unrestricted")
