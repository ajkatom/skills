"""M12 Task 4 (final): e2e proof that the twin-evidence oracle actually
discriminates a hardcoder from a genuine twin-caller, that a converging run
carries a FRESH verifier-only variant seed on every pass (non-vacuously --
distinct tokens actually observed), and that the evidence channel itself is
write-protected at standard tier (Task 1's fix).

The SAME control root (spec, twin def with `supports_variants: true`,
scenario set) is used for both the hardcoder run (a) and the honest-builder
run (b) -- only the builder adapter differs -- so this is a real A/B proof,
not two unrelated fixtures.
"""
import json
import os
import subprocess
import sys

import pytest

import df_sandbox
from test_supervisor import setup_control, terminal_state
from test_supervisor_twins import GREETER, _no_twin_orphans

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
FAKE_TWIN_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_twin")
FAKE_BUILDER_HARDCODE = os.path.join(HERE, "fixtures", "fake_builder_hardcode")

MARKER = "HOLDOUT-MARKER-twinevidence-93e1"


def _dev_scenario():
    return {
        "ir_version": "0.1", "id": "BHV-001-S1", "behavior_id": "BHV-001",
        "title": f"{MARKER} greets World via twin, with evidence",
        "given": f"{MARKER} workspace has greet.py backed by the greeter twin",
        "when": {"run": ["python3", "greet.py", "World"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_contains": "Hello, World!",
                 "stdout_echoes_twin": {"twin": "greeter"}},
    }


def _final_scenario():
    # Sealed-exam scenario that ALSO calls the twin. It greets the SAME name
    # ("World") as the dev scenario ON PURPOSE: the twin's token is
    # sha256(seed + path)[:12], so holding the path constant across the two
    # passes means the ONLY variable left that can make the dev-verify token
    # differ from the final-exam token is the per-pass DF_TWIN_VARIANT_SEED.
    # A differing name here would make the tokens differ by path alone and
    # render the fresh-per-pass-seed assertion vacuous.
    return {
        "ir_version": "0.1", "id": "BHV-002-S1", "behavior_id": "BHV-002",
        "title": f"{MARKER} sealed final exam also talks to the twin",
        "given": f"{MARKER} final-cohort check the twin is called again post-convergence",
        "cohort": "final",
        "when": {"run": ["python3", "greet.py", "World"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_contains": "Hello, World!",
                 "stdout_echoes_twin": {"twin": "greeter"}},
    }


def _twin_evidence_control(tmp_path, adapter):
    cr = setup_control(tmp_path, adapter, checkpoint="auto")
    (cr / "spec.md").write_text(
        f"# {MARKER} greet CLI (twin-backed, with evidence)\n"
        "Create an executable python file `greet.py` in the workspace root that "
        "reads the greeter twin's endpoint from env `DF_TWIN_GREETER` and prints "
        "the body of `GET http://$DF_TWIN_GREETER/greet/<name>`, exiting 0.\n",
        encoding="utf-8")
    for old in (cr / "scenarios").glob("*.json"):
        old.unlink()
    (cr / "scenarios" / "s0.json").write_text(json.dumps(_dev_scenario()), encoding="utf-8")
    (cr / "scenarios" / "s1.json").write_text(json.dumps(_final_scenario()), encoding="utf-8")
    (cr / "twins").mkdir()
    (cr / "twins" / "greeter.json").write_text(json.dumps(
        {"twin_version": "0.1", "name": "greeter", "launch": ["python3", GREETER],
         "fidelity": "dev mock", "supports_variants": True}), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"] = {"enabled": True, "startup_timeout_s": 20}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def _journal(cr):
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines], run_dir


def _workspace_from_journal(entries):
    for e in entries:
        if e["state"] == "SNAPSHOT":
            return e["data"]["workspace"]
    return None


def _builder_visible_files(run_dir, workspace):
    """Every file the builder itself could plausibly have seen or received:
    the audit copy of each prompt + the working copy actually read by the
    adapter, and every feedback projection (per-iteration audit copy + the
    workspace copy). Deliberately EXCLUDES verifier_report_iter_*.json /
    final_exam_report.json (control-plane only, carries raw observed
    stdout/twin data -- never shown to the builder) and the twins/ observer
    logs themselves.
    """
    paths = []
    for fn in sorted(os.listdir(run_dir)):
        if fn.startswith("prompt_iter_") or fn.startswith("feedback_iter_"):
            paths.append(os.path.join(run_dir, fn))
    for fn in ("DARK_FACTORY_PROMPT.md", "feedback.json"):
        p = os.path.join(workspace, fn)
        if os.path.exists(p):
            paths.append(p)
    return paths


# ---------------------------------------------------------------------------
# (a) hardcoder rejected
# ---------------------------------------------------------------------------

def test_hardcoder_rejected_no_twin_evidence_cap_reached(tmp_path):
    cr = _twin_evidence_control(tmp_path, FAKE_BUILDER_HARDCODE)

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 3, proc.stderr

    entries, run_dir = _journal(cr)
    states = [e["state"] for e in entries]
    assert terminal_state(entries)["state"] == "CAP_REACHED"
    assert "CONVERGED" not in states

    workspace = _workspace_from_journal(entries)
    assert workspace is not None

    # The taxonomy the builder was told about must be no_twin_evidence, for
    # a scenario whose stdout literally matched (stdout_contains passed) --
    # proving the failure came specifically from the twin-evidence check,
    # not from wrong output/exit-code masking it.
    feedback_files = sorted(
        f for f in os.listdir(run_dir) if f.startswith("feedback_iter_")
    )
    assert feedback_files, "no feedback was ever produced -- vacuous check"
    saw_no_twin_evidence = False
    for fn in feedback_files:
        fb = json.loads((run_dir / fn).read_text(encoding="utf-8"))
        for failure in fb["failures"]:
            if failure["behavior_id"] == "BHV-001" and "no_twin_evidence" in failure["taxonomy"]:
                saw_no_twin_evidence = True
    assert saw_no_twin_evidence, "expected no_twin_evidence taxonomy for BHV-001 in some feedback round"

    # The barrier holds: every builder-visible prompt/feedback file contains
    # ONLY behavior_id + taxonomy -- no variant token, no seed value/name.
    visible = _builder_visible_files(run_dir, workspace)
    assert visible, "no builder-visible files found -- vacuous check"
    for p in visible:
        data = open(p, "rb").read()
        assert b"vt-" not in data, f"variant token leaked into {p}"
        assert b"DF_TWIN_VARIANT_SEED" not in data, f"seed env-var name leaked into {p}"

    assert _no_twin_orphans()


# ---------------------------------------------------------------------------
# (b) honest builder converges + fresh-per-pass seed (non-vacuous)
# ---------------------------------------------------------------------------

def test_honest_builder_converges_with_fresh_seed_per_pass(tmp_path):
    cr = _twin_evidence_control(tmp_path, FAKE_TWIN_BUILDER)

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
    assert manifest["twin_evidence"]["variants"] is True
    assert manifest["twin_evidence"]["observed_assertions"] == 2

    # Non-vacuous fresh-seed proof: read the twin's OWN observation ndjson
    # log directly (the evidence channel, not anything the builder produced)
    # and confirm at least 2 DISTINCT tokens were recorded -- one from the
    # dev-verify pass (BHV-001-S1's call) and one from the sealed final-exam
    # pass (BHV-002-S1's call). Both passes greet the SAME name ("World"), so
    # the token input path is identical between them; the tokens can therefore
    # differ ONLY because each pass received its OWN fresh DF_TWIN_VARIANT_SEED.
    # If the seed were reused (or absent) across passes, the tokens would
    # collide (identical path + identical seed) instead of differing -- so this
    # assertion isolates seed-freshness rather than path variation.
    obs_path = run_dir / "twins" / "greeter.observations.ndjson"
    assert obs_path.exists()
    tokens = []
    for line in obs_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        tok = obj.get("token")
        if tok:
            tokens.append(tok)
    assert len(tokens) >= 2, f"expected >=2 recorded tokens (one per pass), got {tokens}"
    assert len(set(tokens)) >= 2, f"seeds did not vary across passes -- tokens collided: {tokens}"

    assert _no_twin_orphans()


# ---------------------------------------------------------------------------
# (c) evidence channel is write-protected (standard tier)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_evidence_channel_write_denied_at_standard_tier(tmp_path):
    b = df_sandbox.current_backend()
    if not (b and b.available()):
        pytest.skip("no OS sandbox primitive")

    cr = _twin_evidence_control(tmp_path, FAKE_TWIN_BUILDER)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "standard"
    (cr / "config.json").write_text(json.dumps(cfg))

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr

    entries, run_dir = _journal(cr)
    assert "CONVERGED" in [e["state"] for e in entries]
    m = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert m["qualified"] is True
    assert m["denial_probe_passed"] is True

    workspace = _workspace_from_journal(entries)
    assert workspace is not None

    obs_path = run_dir / "twins" / "greeter.observations.ndjson"
    assert obs_path.exists()
    before = obs_path.read_bytes()

    # Take the SAME wrap_prefix the run itself used (control_root, workspace)
    # and try to append a forged observation line to the run's REAL observer
    # file -- a real path under run_dir. Task 1's write-denial fix must
    # reject this: the append fails AND the on-disk bytes are unchanged.
    pref = b.wrap_prefix(str(cr), workspace)
    forge_code = (
        "import sys\n"
        "path = sys.argv[1]\n"
        "with open(path, 'a', encoding='utf-8') as f:\n"
        "    f.write('{\\\"event\\\":\\\"FORGED\\\",\\\"detail\\\":\\\"probe\\\"}\\n')\n"
    )
    denied = subprocess.run(
        pref + [sys.executable, "-c", forge_code, str(obs_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert denied.returncode != 0, (
        f"forged append under the sandbox unexpectedly SUCCEEDED: "
        f"stdout={denied.stdout!r} stderr={denied.stderr!r}"
    )

    after = obs_path.read_bytes()
    assert after == before, "evidence channel bytes changed despite a denied write attempt"

    assert _no_twin_orphans()
