"""M86 (post-R10 adversarial audit): the brownfield-GENERATED regression cohort
(`<run_dir>/generated-scenarios/BHV-REGRESS-*.json`) was OUTSIDE the RA-05 seal.

`_scenario_set_hash` hashes only `control_root/scenarios/*.json`, and the generated
cohort is written AFTER the run-start seal — so RA-05's `SCENARIO_BUNDLE_CHANGED`
immutability check never covered it. A same-user control-root writer could WEAKEN or
DELETE a generated regression scenario across a pause (to make a build that broke
original behavior converge + qualify), and resume reused the tampered cohort verbatim.

Fix: the generated cohort's hash is sealed into state.json (M77-anchored into the
signed chain) at each pause, and re-verified on resume — RA-05 immutability extended to
the generated guard.
"""
import json
import os
import shutil

import supervisor
from test_supervisor import FAKE, setup_control
from test_brownfield_config import LEGACY_APP_FIXTURE, set_brownfield
from test_e2e_brownfield import SPEC_TEXT, ADD_OK_PROBE, ADD_BAD_PROBE, _double_scenario


def _brownfield_paused(tmp_path):
    cr = setup_control(tmp_path, FAKE, max_iterations=3, checkpoint="pause")
    (cr / "spec.md").write_text(SPEC_TEXT, encoding="utf-8")
    for old in (cr / "scenarios").glob("*.json"):
        old.unlink()
    (cr / "scenarios" / "double.json").write_text(
        json.dumps(_double_scenario()), encoding="utf-8")
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = tmp_path / "app_src"
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "app.py")
    assert supervisor.run(str(cr), str(src)) == supervisor.PAUSED
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    return cr, run_dir


def _states(run_dir):
    return [json.loads(l)["state"]
            for l in (run_dir / "journal.jsonl").read_text().splitlines()]


def _guards(run_dir):
    return sorted((run_dir / "generated-scenarios").glob("BHV-REGRESS-*.json"))


def test_generated_cohort_is_sealed_into_state(tmp_path):
    cr, run_dir = _brownfield_paused(tmp_path)
    assert _guards(run_dir)  # a generated regression cohort exists
    st = json.loads((run_dir / "state.json").read_text())
    assert st.get("generated_set_sha256")  # and its hash is sealed in the checkpoint


def test_weakening_a_generated_guard_is_refused_on_resume(tmp_path):
    cr, run_dir = _brownfield_paused(tmp_path)
    victim = _guards(run_dir)[0]
    sc = json.loads(victim.read_text())
    sc["then"] = {"exit_code": 0}  # weaken to a non-discriminating assertion
    victim.write_text(json.dumps(sc), encoding="utf-8")
    assert supervisor.resume(str(cr), "continue") == 2
    assert "GENERATED_BUNDLE_CHANGED" in _states(run_dir)


def test_deleting_a_generated_guard_is_refused_on_resume(tmp_path):
    cr, run_dir = _brownfield_paused(tmp_path)
    _guards(run_dir)[0].unlink()  # remove a regression guard entirely
    assert supervisor.resume(str(cr), "continue") == 2
    assert "GENERATED_BUNDLE_CHANGED" in _states(run_dir)


def test_dispatch_crash_state_carries_the_seal(tmp_path, monkeypatch):
    # Independent-audit regression: the crash-safe per-dispatch save (chain_append=False)
    # must ALSO seal the cohort — else a mid-dispatch crash leaves generated_set_sha256
    # None, and a later resume SILENTLY SKIPS the check, reopening the bypass. Crash
    # right after the dispatch save and confirm the on-disk DISPATCH state carries the
    # seal and a subsequent tamper is still caught.
    cr = setup_control(tmp_path, FAKE, max_iterations=3, checkpoint="pause")
    (cr / "spec.md").write_text(SPEC_TEXT, encoding="utf-8")
    for old in (cr / "scenarios").glob("*.json"):
        old.unlink()
    (cr / "scenarios" / "double.json").write_text(
        json.dumps(_double_scenario()), encoding="utf-8")
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = tmp_path / "app_src"
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "app.py")

    monkeypatch.setattr(supervisor, "invoke_adapter",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash mid-dispatch")))
    try:
        supervisor.run(str(cr), str(src))
    except RuntimeError:
        pass
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    st = json.loads((run_dir / "state.json").read_text())
    assert str(st.get("phase", "")).startswith("DISPATCH")  # crashed at the dispatch save
    assert st.get("generated_set_sha256")  # the dispatch save SEALED the cohort (the fix)

    _guards(run_dir)[0].unlink()  # attacker weakens the guard during the crash window
    monkeypatch.undo()
    assert supervisor.resume(str(cr), "continue") == 2
    assert "GENERATED_BUNDLE_CHANGED" in _states(run_dir)


def test_untampered_generated_cohort_resumes_cleanly(tmp_path):
    # No false-refusal: an unedited cohort resumes and is journaled verified.
    cr, run_dir = _brownfield_paused(tmp_path)
    rc = supervisor.resume(str(cr), "continue")
    assert rc != 2
    st = _states(run_dir)
    assert "GENERATED_BUNDLE_CHANGED" not in st
    assert "GENERATED_BUNDLE_VERIFIED" in st
