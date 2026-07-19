"""M10-3 e2e: hardened tier convergence + barrier proof, L5 lights-off, and
fail-closed refusal without Docker. Driven as real supervisor CLI subprocess
calls, matching test_e2e_final_exam.py / test_e2e_security.py's pattern.

  (a) live hardened convergence + barrier proof: a hardened run with the
      `fake_builder_snoop` fixture (a hostile-builder simulation that tries to
      read past its own workspace) converges exit 0, with a manifest recording
      tier/qualified/sandbox_backend/container correctly and a verifiable HMAC
      signature — and `snoop.txt` proves the control root (scenarios + a
      planted canary) was genuinely unreachable from inside the container,
      not merely unread. A companion sanity test proves the snoop instrument
      itself works (finds real content when run uncontained on the host), so
      its empty-handed result inside the container is not vacuous.
  (b) live L5 lights-off: `autonomy: 5` at hardened converges a two-iteration
      build/feedback/build loop in one unattended CLI call with NO checkpoint
      pause; the same `autonomy: 5` under `assurance: standard` is rejected at
      config load (no docker/build ever runs for that half).
  (c) refusal without docker (NO skipif — runs on every machine, docker or
      not): shadowing `docker` on PATH with a fake that always fails makes
      `docker_available()` False regardless of the host's real Docker
      install; the hardened run refuses closed (exit 2, message mentions
      hardened + docker). `--allow-downgrade` then converges at whatever
      tier the OS sandbox actually supports on this host, journaling
      DOWNGRADE and recording `qualified` honestly for the effective tier.
"""
import json
import os
import subprocess
import sys
import uuid

import pytest

import df_container
import df_sandbox
from test_supervisor import FAKE, MARKER, external_reachable, needs_network, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_SNOOP = os.path.join(HERE, "fixtures", "fake_builder_snoop")
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")

DOCKER_LIVE = df_container.docker_available()


@pytest.fixture(scope="session", autouse=True)
def _prepull_image():
    """Mirrors test_container.py's session pre-pull: the first live hardened
    test must not absorb a cold image download inside its own (tighter) CLI
    subprocess timeout. No-op when docker is absent."""
    if DOCKER_LIVE:
        subprocess.run(
            ["docker", "pull", "-q", df_container.DEFAULT_IMAGE],
            capture_output=True, timeout=600,
        )
    yield


def _run(cr, *args, env=None, timeout=180):
    return subprocess.run(
        [sys.executable, SUP, *args, "--control-root", str(cr)],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


def _journal(cr, run_id):
    lines = (cr / "runs" / run_id / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in lines.strip().splitlines()]


def _make_hardened(cr, tmp_path, **cfg_overrides):
    """Mutate a setup_control() control root into a hardened config. The audit
    signing key (hardened forces audit.signing default True) is pointed into a
    THIRD tmp directory — a sibling of both control_root (tmp_path/control)
    and workspace_root (tmp_path/ws) — since df_config requires the key
    directory be disjoint from both."""
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "hardened"
    cfg["audit"] = {"key_path": str(tmp_path / "audit_keys" / "audit.key")}
    cfg.update(cfg_overrides)
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cfg


def _plant_canary(cr, token):
    canary = cr / ".probe-canary-e2e-plant"
    canary.write_text(token, encoding="utf-8")
    return canary


# ---------------------------------------------------------------------------
# (a) live hardened convergence + barrier proof
# ---------------------------------------------------------------------------

@needs_network
@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_live_hardened_convergence_and_barrier(tmp_path):
    if not external_reachable():
        pytest.skip("no external reachability for the candidate egress-denial probe")
    cr = setup_control(tmp_path, FAKE_SNOOP, checkpoint="auto")
    # M47 RA-08(a): confine candidate egress so the hardened run QUALIFIES (the
    # candidate verify runs under the HOST sandbox, so the deny probe reaches the
    # host network -> external -> gated behind DF_ALLOW_NETWORK_TESTS).
    _make_hardened(cr, tmp_path, candidate_network="deny")

    canary_token = "DF-E2E-CANARY-" + uuid.uuid4().hex
    _plant_canary(cr, canary_token)

    proc = _run(cr, "run", timeout=240)
    assert proc.returncode == 0, proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    workspace = tmp_path / "ws" / run_id

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["tier"] == "hardened"
    assert manifest["qualified"] is True
    assert manifest["sandbox_backend"] == df_container.BACKEND_NAME
    assert manifest["denial_probe_passed"] is True
    assert manifest["container"]["image"] == df_container.DEFAULT_IMAGE
    assert manifest["container"]["network"] == "none"
    assert manifest["audit_signing"] is True

    key_path = tmp_path / "audit_keys" / "audit.key"
    ver = subprocess.run(
        [sys.executable, SUP, "verify-manifest", "--run-dir", str(run_dir),
         "--key-path", str(key_path)],
        capture_output=True, text=True,
    )
    assert ver.returncode == 0, ver.stdout + ver.stderr
    assert "OK" in ver.stdout

    # Barrier proof: snoop.txt exists (the builder ran and wrote it, so this
    # is not a vacuous "file never appeared") but contains NEITHER the
    # planted canary token NOR any scenario content (MARKER is embedded in
    # every scenario's title/given by setup_control) — the container simply
    # cannot see those paths.
    snoop = workspace / "snoop.txt"
    assert snoop.exists(), "snoop.txt missing — builder never ran, proof would be vacuous"
    text = snoop.read_text(encoding="utf-8")
    assert canary_token not in text
    assert MARKER not in text

    # The correct artifact still got built despite the failed snoop.
    assert (workspace / "greet.py").exists()


def test_fake_builder_snoop_finds_scenarios_when_run_uncontained(tmp_path):
    """Non-vacuousness sanity check for the barrier proof above: run
    fake_builder_snoop directly on the HOST (no container at all) in a
    workdir laid out exactly like a real dark-factory run (workspace_root and
    control_root as sibling directories under the same parent — precisely
    what setup_control produces) and confirm it DOES find and dump the
    scenario content + canary token.

    This proves the snoop instrument itself works: an instrument that never
    finds anything would "pass" the barrier test above even with zero
    isolation, which would make that test meaningless. This test shows the
    positive case, so the container's negative (empty) result is a real
    proof of denial-by-construction, not an artifact of a broken probe.
    """
    control_scenarios = tmp_path / "control" / "scenarios"
    control_scenarios.mkdir(parents=True)
    marker_text = "HOLDOUT-MARKER-SANITY-CHECK"
    (control_scenarios / "s1.json").write_text(
        json.dumps({"title": marker_text}), encoding="utf-8")
    canary_token = "DF-SANITY-CANARY-" + uuid.uuid4().hex
    (tmp_path / "control" / ".probe-canary-sanity").write_text(
        canary_token, encoding="utf-8")

    workdir = tmp_path / "ws" / "invocation1"
    workdir.mkdir(parents=True)

    proc = subprocess.run(
        [sys.executable, FAKE_SNOOP],
        input=json.dumps({"workdir": str(workdir)}),
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr

    snoop_text = (workdir / "snoop.txt").read_text(encoding="utf-8")
    assert marker_text in snoop_text, (
        "sanity check failed: snoop did not find scenario content when run "
        "uncontained — the barrier test above would be vacuous"
    )
    assert canary_token in snoop_text, (
        "sanity check failed: snoop did not find the canary when run "
        "uncontained — the barrier test above would be vacuous"
    )
    # And it still builds the correct artifact regardless.
    assert (workdir / "greet.py").exists()


# ---------------------------------------------------------------------------
# (b) live L5 lights-off + config-level autonomy-5 gate
# ---------------------------------------------------------------------------

@needs_network
@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_live_l5_lights_off_no_pause(tmp_path):
    # FAKE (not the snoop fixture): a two-iteration buggy-then-fixed builder,
    # so a real feedback round happens mid-run — proving autonomy 5 doesn't
    # pause even at an iteration boundary that checkpoint:pause would stop at.
    if not external_reachable():
        pytest.skip("no external reachability for the candidate egress-denial probe")
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # M47 RA-08(a): confine candidate egress so the hardened L5 run QUALIFIES.
    _make_hardened(cr, tmp_path, autonomy=5, candidate_network="deny")

    proc = _run(cr, "run", timeout=240)
    assert proc.returncode == 0, proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    assert not (run_dir / "state.json").exists()

    entries = _journal(cr, run_id)
    states = [e["state"] for e in entries]
    assert "CHECKPOINT" not in states
    assert states[-1] == "CONVERGED"
    assert states.count("BUILD") == 2  # buggy then fixed, both unattended

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["tier"] == "hardened"
    assert manifest["qualified"] is True


def test_autonomy_5_with_standard_assurance_rejected_at_load(tmp_path):
    """No skipif — purely a config-load rejection; no docker/build ever runs."""
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "standard"
    cfg["autonomy"] = 5
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    proc = _run(cr, "run")
    assert proc.returncode == 2
    assert "autonomy 5" in proc.stderr
    # ConfigError is raised before any run_dir is ever created.
    assert not (cr / "runs").exists()


# ---------------------------------------------------------------------------
# (c) refusal without docker (no skipif — must run on docker-less machines)
# ---------------------------------------------------------------------------

def _stub_docker_path(tmp_path):
    """Build a PATH override that shadows `docker` with a fake binary that
    always exits 1 (a daemon-unreachable simulation), PREPENDED in front of
    the real PATH so every other tool the run needs (python3, sh, sandbox-exec,
    etc.) stays reachable — only `docker` is shadowed."""
    stub_dir = tmp_path / "stubbin"
    stub_dir.mkdir()
    fake_docker = stub_dir / "docker"
    fake_docker.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake_docker.chmod(0o755)
    return str(stub_dir) + os.pathsep + os.environ.get("PATH", "")


def test_refusal_without_docker_then_allow_downgrade(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _make_hardened(cr, tmp_path)

    env = dict(os.environ)
    env["PATH"] = _stub_docker_path(tmp_path)

    # First: no --allow-downgrade -> fail closed, exit 2, no silent success.
    proc = _run(cr, "run", env=env)
    assert proc.returncode == 2
    stderr_lower = proc.stderr.lower()
    assert "hardened" in stderr_lower
    assert "docker" in stderr_lower

    # Second: --allow-downgrade -> converges at whatever tier the OS sandbox
    # actually supports on THIS host (not hardcoded — some CI hosts may lack
    # even the OS sandbox, in which case cooperative is the honest landing).
    # Identify the second run by set-diff, NOT by sorting names: invocation ids
    # have 1-second timestamp resolution + a random suffix, so back-to-back
    # runs in the same second sort in random order (was a real flake).
    runs_before = set(os.listdir(cr / "runs")) if (cr / "runs").exists() else set()
    proc2 = _run(cr, "run", "--allow-downgrade", env=env, timeout=240)
    assert proc2.returncode == 0, proc2.stderr

    new_runs = set(os.listdir(cr / "runs")) - runs_before
    assert len(new_runs) == 1, f"expected exactly one new run, got {sorted(new_runs)}"
    run_id = new_runs.pop()
    run_dir = cr / "runs" / run_id

    entries = _journal(cr, run_id)
    downgrades = [e for e in entries if e["state"] == "DOWNGRADE"]
    assert downgrades, "expected a DOWNGRADE journal entry"
    assert downgrades[0]["data"]["requested"] == "hardened"
    effective = downgrades[0]["data"]["effective"]

    os_backend = df_sandbox.current_backend()
    os_available = os_backend is not None and os_backend.available()
    expected_effective = "standard" if os_available else "cooperative"
    assert effective == expected_effective

    # Note: manifest["tier"] always echoes the CONFIGURED assurance
    # ("hardened") — same convention as the standard-tier downgrade tests
    # (test_standard_tier.py) — so the effective tier is read from the journal
    # DOWNGRADE entry above, not from manifest["tier"].
    # M47 RA-08(a): the downgraded run keeps candidate_network unrestricted
    # (the default), so its candidate egress is OPEN -> a standard landing seals
    # the distinct CANDIDATE_EGRESS_OPEN (unqualified), and a cooperative landing
    # is COMPLETE_UNQUALIFIED. Either way the DOWNGRADE is the point here; the
    # qualified claim is now honestly False without a confined candidate network.
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["qualified"] is False
    assert manifest["outcome"] == (
        "CANDIDATE_EGRESS_OPEN" if effective == "standard" else "COMPLETE_UNQUALIFIED"
    )
