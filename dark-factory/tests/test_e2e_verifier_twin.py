"""M21 Task 2 (final): e2e proof that a verifier-only twin implementation
(`verify_launch`) genuinely defeats a builder that overfits the build-time
twin's specific behavior, and that the manifest's `twins` field records the
verify-only-impl flag + fidelity label.

The SAME control root (spec, twin def with BOTH `launch` and `verify_launch`,
scenario set) is used for both the honest-builder run (a) and the
overfit-builder run (b) -- only the builder adapter differs -- so this is a
real A/B proof, not two unrelated fixtures:

  (a) honest builder: value.py CALLS the twin at DF_TWIN_VALUEGEN and prints
      whatever the currently-running instance serves -> at verify the
      verify-phase twin (verify_launch) is running, so it correctly serves
      the VERIFY marker -> the scenario passes -> the run converges.
  (b) overfit builder: value.py HARDCODES the build-phase twin's fixed
      marker (as if the builder observed the build-time twin's response
      once and overfit that exact string) -> at verify the running twin is
      the DIFFERENT verify_launch instance, but the builder's hardcoded
      output never changes -> the scenario fails `wrong_output` every
      iteration -> the run never converges -> CAP_REACHED / exit 3.

This proves verify_launch defeats overfitting a mock the builder can't see
at verify -- generalizing M12's variant seeds ("same process, unpredictable
per-request tokens") to "a different process entirely".
"""
import json
import os
import subprocess
import sys

from test_supervisor import setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
MARKER_SERVER = os.path.join(HERE, "fixtures", "twin_marker_server")
FAKE_HONEST_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_calls_twin_value")
FAKE_OVERFIT_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_hardcodes_twin_value")
FAKE_PROBE_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_probes_twin_at_build")

MARKER = "HOLDOUT-MARKER-verifiertwin-7a3c"

# Must match fake_builder_hardcodes_twin_value.BUILD_MARKER exactly -- the
# overfit builder's hardcoded string IS this constant, baked into the fixture
# file (not read from env), so the two must be kept in lockstep by hand.
BUILD_MARKER = "TWIN-BUILD-FIXED-b7e2a1"
VERIFY_MARKER = "TWIN-VERIFY-DIFFERENT-f4d9c3"
FIDELITY = "dev mock, fixed-value responder (M21 verify_launch e2e)"


def _dev_scenario():
    return {
        "ir_version": "0.1", "id": "BHV-001-S1", "behavior_id": "BHV-001",
        "title": f"{MARKER} prints the twin's currently-served value",
        "given": f"{MARKER} workspace has value.py backed by the valuegen twin",
        "when": {"run": ["python3", "value.py"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_contains": VERIFY_MARKER},
    }


def _final_scenario():
    # Sealed-exam scenario, same shape as the dev one. supports_variants=True
    # on the twin def (below) forces the final exam's OWN dedicated ts.reset
    # call (see supervisor._run_loop) to actually run -- exercising that
    # phase="verify" wiring too, not just the dev-cohort verify reset.
    return {
        "ir_version": "0.1", "id": "BHV-002-S1", "behavior_id": "BHV-002",
        "title": f"{MARKER} sealed final exam also sees the verify impl",
        "given": f"{MARKER} final-cohort check the verify twin is still live",
        "cohort": "final",
        "when": {"run": ["python3", "value.py"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_contains": VERIFY_MARKER},
    }


def _verifier_twin_control(tmp_path, adapter):
    cr = setup_control(tmp_path, adapter, checkpoint="auto")
    (cr / "spec.md").write_text(
        f"# {MARKER} value CLI (verifier-only twin impl)\n"
        "Create an executable python file `value.py` in the workspace root that "
        "reads the valuegen twin's endpoint from env `DF_TWIN_VALUEGEN` and prints "
        "the body of `GET http://$DF_TWIN_VALUEGEN/value`, exiting 0.\n",
        encoding="utf-8")
    for old in (cr / "scenarios").glob("*.json"):
        old.unlink()
    (cr / "scenarios" / "s0.json").write_text(json.dumps(_dev_scenario()), encoding="utf-8")
    (cr / "scenarios" / "s1.json").write_text(json.dumps(_final_scenario()), encoding="utf-8")
    (cr / "twins").mkdir()
    (cr / "twins" / "valuegen.json").write_text(json.dumps({
        "twin_version": "0.1", "name": "valuegen",
        "launch": ["python3", MARKER_SERVER, BUILD_MARKER],
        "verify_launch": ["python3", MARKER_SERVER, VERIFY_MARKER],
        "fidelity": FIDELITY,
        "supports_variants": True,
    }), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"] = {"enabled": True, "startup_timeout_s": 20}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def _journal(cr):
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines], run_dir


def _no_twin_orphans():
    out = subprocess.run(["pgrep", "-f", "twin_marker_server"], capture_output=True, text=True)
    return out.stdout.strip() == ""


def _workspace_from_journal(entries):
    for e in entries:
        if e["state"] == "SNAPSHOT":
            return e["data"]["workspace"]
    return None


# ---------------------------------------------------------------------------
# (a) honest builder converges: uses the verify impl's value at verify
# ---------------------------------------------------------------------------

def test_honest_builder_converges_using_verify_impl_value(tmp_path):
    cr = _verifier_twin_control(tmp_path, FAKE_HONEST_BUILDER)

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr

    entries, run_dir = _journal(cr)
    states = [e["state"] for e in entries]
    assert "CONVERGED" in states
    assert "TWIN_ERROR" not in states

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["twins"] == [{
        "name": "valuegen",
        "fidelity": FIDELITY,
        "verify_only_impl": True,
        "supports_variants": True,
    }]
    # Final exam ran (sealed BHV-002-S1) and passed -- proving the final
    # exam's OWN dedicated reset also swapped in the verify impl, not just
    # dev-cohort's.
    assert manifest["final_exam"] == {"ran": True, "passed": True, "count": 1}

    assert _no_twin_orphans()


# ---------------------------------------------------------------------------
# (b) overfit builder rejected: build-phase marker never matches verify's
# ---------------------------------------------------------------------------

def test_overfit_builder_rejected_cap_reached(tmp_path):
    cr = _verifier_twin_control(tmp_path, FAKE_OVERFIT_BUILDER)

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 3, proc.stderr

    entries, run_dir = _journal(cr)
    states = [e["state"] for e in entries]
    assert states[-1] == "CAP_REACHED"
    assert "CONVERGED" not in states

    # The overfit builder's hardcoded BUILD_MARKER output never matches the
    # VERIFY_MARKER the verify-phase twin actually serves -- a plain output
    # mismatch (wrong_output), NOT a twin-evidence failure (this scenario
    # never asserts twin_observed/stdout_echoes_twin).
    feedback_files = sorted(
        f for f in os.listdir(run_dir) if f.startswith("feedback_iter_")
    )
    assert feedback_files, "no feedback was ever produced -- vacuous check"
    saw_wrong_output = False
    for fn in feedback_files:
        fb = json.loads((run_dir / fn).read_text(encoding="utf-8"))
        for failure in fb["failures"]:
            if failure["behavior_id"] == "BHV-001" and "wrong_output" in failure["taxonomy"]:
                saw_wrong_output = True
    assert saw_wrong_output, "expected wrong_output taxonomy for BHV-001 in some feedback round"

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["twins"] == [{
        "name": "valuegen",
        "fidelity": FIDELITY,
        "verify_only_impl": True,
        "supports_variants": True,
    }]
    # Dev never converged, so the sealed final exam never ran.
    assert manifest["final_exam"] == {"ran": False, "passed": None, "count": 0}

    # Barrier: neither marker string leaks into any builder-visible prompt or
    # feedback file (both are control-plane-only -- prompts never carry twin
    # response data, and feedback is behavior_id+taxonomy only).
    for fn in sorted(os.listdir(run_dir)):
        if fn.startswith("prompt_iter_") or fn.startswith("feedback_iter_"):
            data = open(run_dir / fn, "rb").read()
            assert BUILD_MARKER.encode() not in data
            assert VERIFY_MARKER.encode() not in data

    assert _no_twin_orphans()


# ---------------------------------------------------------------------------
# (c) barrier: the BUILDER's env comes from the BUILD-phase start, never
#     the verify impl
# ---------------------------------------------------------------------------

def test_builder_env_is_build_phase_endpoint_not_verify(tmp_path):
    # fake_builder_probes_twin_at_build reads DF_TWIN_VALUEGEN from its OWN
    # build-time process env and immediately GETs /value against it,
    # recording the raw response into build_time_twin_value.txt. This is a
    # direct, non-vacuous proof that build_env_extra (what invoke_adapter
    # hands the builder) came from ts.start(..., phase="build") -- if it had
    # somehow come from the verify-phase twin instead, this file would
    # contain VERIFY_MARKER, not BUILD_MARKER.
    cr = _verifier_twin_control(tmp_path, FAKE_PROBE_BUILDER)

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    entries, run_dir = _journal(cr)
    assert "CONVERGED" in [e["state"] for e in entries]

    workspace = _workspace_from_journal(entries)
    assert workspace is not None
    probe_path = os.path.join(workspace, "build_time_twin_value.txt")
    assert os.path.exists(probe_path), "build-time probe file was never written"
    observed_at_build = open(probe_path, encoding="utf-8").read()
    assert observed_at_build == BUILD_MARKER, (
        f"builder's build-time env exposed {observed_at_build!r}, expected the "
        f"BUILD-phase marker {BUILD_MARKER!r} -- the barrier is broken if this "
        f"ever equals VERIFY_MARKER"
    )
    assert observed_at_build != VERIFY_MARKER

    assert _no_twin_orphans()
