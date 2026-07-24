"""M91 (DF-R12-03 residual): close the in-run scenario-immutability TOCTOU.

M88 checks the sealed digests immediately before the verifier load, then `run_all`
re-reads the files — a micro-window a concurrent writer could race (pass the check,
swap the bytes before the read). M91 moves the verification INTO `load_scenarios`:
each file is read as raw bytes once, parsed AND hashed from those same bytes, and the
per-directory digest is compared to the run-start seal before any scenario runs. The
bytes hashed ARE the bytes executed, so the window is gone. A mismatch raises
`ScenarioBundleDrift`, which the supervisor maps to a fail-closed terminal.
"""
import json
import os
import shutil

import supervisor
from run_scenarios import load_scenarios, run_all, ScenarioBundleDrift
from test_supervisor import FAKE, setup_control
from test_brownfield_config import LEGACY_APP_FIXTURE, set_brownfield
from test_e2e_brownfield import (
    ADD_BAD_PROBE, ADD_OK_PROBE, FAKE_BUILDER_BREAK, _brownfield_control, _double_scenario,
)


def _scn_dir(tmp_path, name="scenarios"):
    d = tmp_path / name
    d.mkdir()
    (d / "double.json").write_text(json.dumps(_double_scenario()), encoding="utf-8")
    return d


def test_load_scenarios_verifies_the_exact_bytes_it_loads(tmp_path):
    d = _scn_dir(tmp_path)
    sealed = supervisor._scenario_set_hash(str(d))
    # matching seal → loads; None → no check
    assert load_scenarios(str(d), verify_digests={"scenarios": sealed})
    assert load_scenarios(str(d), verify_digests={"scenarios": None})
    # tamper, then load with the OLD seal → drift raised from the load itself
    victim = d / "double.json"
    sc = json.loads(victim.read_text())
    sc["then"] = {"exit_code": 0}
    victim.write_text(json.dumps(sc), encoding="utf-8")
    try:
        load_scenarios(str(d), verify_digests={"scenarios": sealed})
        assert False, "expected ScenarioBundleDrift"
    except ScenarioBundleDrift as e:
        assert e.kind == "scenarios"
        assert e.expected == sealed and e.actual != sealed


def test_dotfile_json_does_not_cause_false_drift(tmp_path):
    # Independent-audit LOW: the seal (_scenario_set_hash) and the loader must enumerate
    # the SAME set. A stray leading-dot `.json` (which glob/load ignore) must NOT make the
    # seal differ from the load-time digest → no spurious ScenarioBundleDrift.
    d = _scn_dir(tmp_path)
    (d / ".editor-backup.json").write_text('{"junk": true}', encoding="utf-8")
    sealed = supervisor._scenario_set_hash(str(d))
    # the sealed digest must exactly match what the loader verifies against (no drift)
    assert load_scenarios(str(d), verify_digests={"scenarios": sealed})


def test_run_all_fails_closed_on_generated_bundle_drift(tmp_path):
    d = _scn_dir(tmp_path)
    gen = tmp_path / "generated"
    gen.mkdir()
    g = _double_scenario()
    g["id"] = "BHV-REGRESS-9-x"
    g["behavior_id"] = "BHV-REGRESS-9"
    (gen / "BHV-REGRESS-9-x.json").write_text(json.dumps(g), encoding="utf-8")
    sealed_gen = supervisor._scenario_set_hash(str(gen))
    # tamper the generated cohort after sealing
    (gen / "BHV-REGRESS-9-x.json").write_text(json.dumps(dict(g, then={"exit_code": 0})),
                                              encoding="utf-8")
    ws = tmp_path / "ws"
    ws.mkdir()
    try:
        run_all(str(d), str(ws), extra_scenarios_dir=str(gen),
                verify_digests={"scenarios": None, "generated": sealed_gen})
        assert False, "expected ScenarioBundleDrift"
    except ScenarioBundleDrift as e:
        assert e.kind == "generated"


def test_toctou_backstop_catches_swap_the_precheck_missed(tmp_path, monkeypatch):
    # The point of M91: even if the M88 pre-check passed (here forced to return None,
    # simulating a writer that raced the check→load window), the LOAD-TIME verification
    # still fails closed. Weaken a generated guard after dispatch; the pre-check is
    # neutralized, yet the run refuses at the dev-verify load.
    cr = _brownfield_control(tmp_path, FAKE_BUILDER_BREAK, max_iterations=1)
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = tmp_path / "app_src"
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "app.py")

    # Neutralize the M88 pre-check to isolate the M91 load-time backstop.
    monkeypatch.setattr(supervisor, "_scenario_immutability_drift", lambda: None,
                        raising=False)

    original = supervisor.invoke_adapter

    def weaken_after_dispatch(*a, **k):
        result = original(*a, **k)
        run_dir = next((cr / "runs").iterdir())
        victim = next((run_dir / "generated-scenarios").glob("BHV-REGRESS-0-*.json"))
        sc = json.loads(victim.read_text())
        sc["then"] = {"exit_code": 0}
        victim.write_text(json.dumps(sc), encoding="utf-8")
        return result

    monkeypatch.setattr(supervisor, "invoke_adapter", weaken_after_dispatch)
    rc = supervisor.run(str(cr), str(src))
    run_dir = next((cr / "runs").iterdir())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert rc != 0
    assert manifest["outcome"] == "GENERATED_BUNDLE_DRIFT"  # caught at the LOAD, not the pre-check


def test_untampered_run_still_converges_with_load_verification(tmp_path):
    from test_e2e_brownfield import FAKE_BUILDER_EXTEND
    cr = _brownfield_control(tmp_path, FAKE_BUILDER_EXTEND, max_iterations=1)
    set_brownfield(cr, {"mode": "brownfield", "probes": [ADD_OK_PROBE, ADD_BAD_PROBE]})
    src = tmp_path / "app_src"
    src.mkdir()
    shutil.copy(LEGACY_APP_FIXTURE, src / "app.py")
    rc = supervisor.run(str(cr), str(src))
    run_dir = next((cr / "runs").iterdir())
    states = [json.loads(l)["state"]
              for l in (run_dir / "journal.jsonl").read_text().splitlines()]
    assert rc == 0
    assert "CONVERGED" in states
    assert "GENERATED_BUNDLE_DRIFT" not in states
