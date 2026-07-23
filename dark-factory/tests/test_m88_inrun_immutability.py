"""M88 (DF-R12-03): scenario-set immutability must hold across the WHOLE run, not
only across a pause.

M86 sealed the brownfield-generated cohort but re-checked it only on `resume`; the
acceptance set was re-checked only before the FINAL exam. In an uninterrupted
auto/H3/H4 run a same-user control-root writer could weaken a hidden guard in the
no-pause window between builder dispatch and the DEV verify load, converging a
build that broke captured/holdout behavior.

Fix: `_scenario_immutability_drift` recomputes BOTH sealed digests immediately
before every verifier load (dev verify AND final exam); drift fails closed
(`GENERATED_BUNDLE_DRIFT` / `SCENARIO_BUNDLE_DRIFT`). These tests invert the R12
reproduction: mutate AFTER dispatch, BEFORE verify, in an uninterrupted run, and
assert the run refuses instead of converging.
"""
import json
import os
import shutil

import supervisor
from test_supervisor import FAKE, setup_control
from test_brownfield_config import LEGACY_APP_FIXTURE, set_brownfield
from test_e2e_brownfield import (
    ADD_BAD_PROBE, ADD_OK_PROBE, FAKE_BUILDER_BREAK, SPEC_TEXT,
    _brownfield_control, _double_scenario,
)


def _states(run_dir):
    return [json.loads(l)["state"]
            for l in (run_dir / "journal.jsonl").read_text().splitlines()]


def _mutate_after_dispatch(fn):
    """Wrap invoke_adapter so `fn(run_dir)` fires right after the builder returns
    (the exact no-pause window between dispatch and the dev verify load)."""
    original = supervisor.invoke_adapter

    def wrapped(*args, **kwargs):
        result = original(*args, **kwargs)
        fn()
        return result
    return wrapped


def test_generated_guard_weakened_after_dispatch_is_refused(tmp_path, monkeypatch):
    cr = _brownfield_control(tmp_path, FAKE_BUILDER_BREAK, max_iterations=1)
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = tmp_path / "app_src"
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "app.py")

    def weaken():
        run_dir = next((cr / "runs").iterdir())
        victim = next((run_dir / "generated-scenarios").glob("BHV-REGRESS-0-*.json"))
        sc = json.loads(victim.read_text())
        sc["then"] = {"exit_code": 0}  # non-discriminating: passes the regressed build
        victim.write_text(json.dumps(sc), encoding="utf-8")

    monkeypatch.setattr(supervisor, "invoke_adapter", _mutate_after_dispatch(weaken))
    rc = supervisor.run(str(cr), str(src))

    run_dir = next((cr / "runs").iterdir())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    # Fail-closed: refused, not converged.
    assert rc != 0
    assert manifest["outcome"] == "GENERATED_BUNDLE_DRIFT"
    assert manifest["qualified"] is False
    assert "GENERATED_BUNDLE_DRIFT" in _states(run_dir)
    assert "CONVERGED" not in _states(run_dir)


def test_acceptance_scenario_weakened_after_dispatch_is_refused(tmp_path, monkeypatch):
    # Generalization: the SAME window exposes hand-authored dev-cohort acceptance
    # scenarios, which were only re-checked before the final exam (never before the
    # dev verify that decides convergence).
    cr = _brownfield_control(tmp_path, FAKE_BUILDER_BREAK, max_iterations=1)
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = tmp_path / "app_src"
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "app.py")

    def weaken_acceptance():
        # Weaken the hand-authored dev scenario (`double.json`) in the control root.
        victim = cr / "scenarios" / "double.json"
        sc = json.loads(victim.read_text())
        sc["then"] = {"exit_code": 0}
        victim.write_text(json.dumps(sc), encoding="utf-8")

    monkeypatch.setattr(supervisor, "invoke_adapter",
                        _mutate_after_dispatch(weaken_acceptance))
    rc = supervisor.run(str(cr), str(src))

    run_dir = next((cr / "runs").iterdir())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert rc != 0
    assert manifest["outcome"] == "SCENARIO_BUNDLE_DRIFT"
    assert manifest["qualified"] is False
    assert "SCENARIO_BUNDLE_DRIFT" in _states(run_dir)


def test_untampered_uninterrupted_brownfield_run_still_converges(tmp_path):
    # No false-refusal: an honest builder that does NOT touch scenarios converges.
    from test_e2e_brownfield import FAKE_BUILDER_EXTEND
    cr = _brownfield_control(tmp_path, FAKE_BUILDER_EXTEND, max_iterations=1)
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = tmp_path / "app_src"
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "app.py")

    rc = supervisor.run(str(cr), str(src))
    run_dir = next((cr / "runs").iterdir())
    st = _states(run_dir)
    assert rc == 0
    assert "CONVERGED" in st
    assert "GENERATED_BUNDLE_DRIFT" not in st
    assert "SCENARIO_BUNDLE_DRIFT" not in st
