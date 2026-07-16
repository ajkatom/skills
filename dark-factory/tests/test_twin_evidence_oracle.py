"""M12 Task 3: oracle IR v0.2 twin-evidence assertions, `no_twin_evidence`
taxonomy, gate compatibility, and the supervisor's verify-pass variant seed.

Sections:
  A. evaluate_then unit matrix (pure function, fabricated `observed` dicts)
  B. load-time OracleError (unknown twin name / empty contains)
  C. run_all offset-delta attribution (live twin_greeter)
  D. df_gates.is_discriminating with twin assertions
  E. id_feedback.TAXONOMY
  F. supervisor: verify-pass seed presence/absence + barrier + manifest
  G. carry-over: raw seed never appears in twin response/observation logs
"""
import json
import os
import urllib.request

import pytest

import df_gates
import df_twins
import id_feedback
import run_scenarios
import supervisor
from run_scenarios import OracleError
from test_supervisor import setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
GREETER = os.path.join(HERE, "fixtures", "twin_greeter")
FAKE = os.path.join(HERE, "fixtures", "fake_builder")
FAKE_TWIN_BUILDER = os.path.join(HERE, "fixtures", "fake_builder_twin")


# ---------------------------------------------------------------------------
# A. evaluate_then unit matrix
# ---------------------------------------------------------------------------

def test_twin_observed_hit():
    then = {"twin_observed": {"twin": "greeter", "contains": "/greet/Alice"}}
    observed = {"exit_code": 0, "stdout": "", "stderr": "",
                "twin_observations": {"greeter": ['{"event":"GET","detail":"/greet/Alice"}']}}
    assert run_scenarios.evaluate_then(then, observed) is None


def test_twin_observed_miss():
    then = {"twin_observed": {"twin": "greeter", "contains": "/greet/Alice"}}
    observed = {"exit_code": 0, "stdout": "", "stderr": "",
                "twin_observations": {"greeter": ['{"event":"GET","detail":"/greet/Bob"}']}}
    assert run_scenarios.evaluate_then(then, observed) == "no_twin_evidence"


def test_twin_observed_absent_observations_key_fails_closed():
    then = {"twin_observed": {"twin": "greeter", "contains": "anything"}}
    observed = {"exit_code": 0, "stdout": "ok", "stderr": ""}  # no twin_observations key at all
    assert run_scenarios.evaluate_then(then, observed) == "no_twin_evidence"


def test_twin_observed_unknown_twin_name_in_observations_fails_closed():
    then = {"twin_observed": {"twin": "greeter", "contains": "x"}}
    observed = {"exit_code": 0, "stdout": "", "stderr": "",
                "twin_observations": {"other_twin": ["x present here"]}}
    assert run_scenarios.evaluate_then(then, observed) == "no_twin_evidence"


def test_stdout_echoes_twin_token_present():
    then = {"stdout_echoes_twin": {"twin": "greeter"}}
    observed = {"exit_code": 0, "stdout": "Hello, World! [vt-abc123456789]", "stderr": "",
                "twin_tokens": {"greeter": ["vt-abc123456789"]}}
    assert run_scenarios.evaluate_then(then, observed) is None


def test_stdout_echoes_twin_none_recorded_fails():
    then = {"stdout_echoes_twin": {"twin": "greeter"}}
    observed = {"exit_code": 0, "stdout": "Hello, World!", "stderr": "",
                "twin_tokens": {"greeter": []}}
    assert run_scenarios.evaluate_then(then, observed) == "no_twin_evidence"


def test_stdout_echoes_twin_absent_tokens_key_fails_closed():
    then = {"stdout_echoes_twin": {"twin": "greeter"}}
    observed = {"exit_code": 0, "stdout": "Hello, World!", "stderr": ""}  # no twin_tokens key
    assert run_scenarios.evaluate_then(then, observed) == "no_twin_evidence"


def test_stdout_echoes_twin_token_not_echoed_fails():
    then = {"stdout_echoes_twin": {"twin": "greeter"}}
    observed = {"exit_code": 0, "stdout": "Hello, World! (no token here)", "stderr": "",
                "twin_tokens": {"greeter": ["vt-abc123456789"]}}
    assert run_scenarios.evaluate_then(then, observed) == "no_twin_evidence"


def test_priority_wrong_exit_code_beats_no_twin_evidence():
    then = {"exit_code": 0, "twin_observed": {"twin": "greeter", "contains": "x"}}
    observed = {"exit_code": 3, "stdout": "", "stderr": "", "twin_observations": {}}
    assert run_scenarios.evaluate_then(then, observed) == "wrong_exit_code"


def test_priority_wrong_output_beats_no_twin_evidence():
    then = {"stdout_equals": "expected", "twin_observed": {"twin": "greeter", "contains": "x"}}
    observed = {"exit_code": 0, "stdout": "wrong", "stderr": "", "twin_observations": {}}
    assert run_scenarios.evaluate_then(then, observed) == "wrong_output"


def test_both_twin_assertions_pass_together():
    then = {"exit_code": 0, "stdout_contains": "Hello",
            "twin_observed": {"twin": "greeter", "contains": "/greet/World"},
            "stdout_echoes_twin": {"twin": "greeter"}}
    observed = {
        "exit_code": 0, "stdout": "Hello, World! [vt-deadbeefcafe]", "stderr": "",
        "twin_observations": {"greeter": ['{"event":"GET","detail":"/greet/World","token":"vt-deadbeefcafe"}']},
        "twin_tokens": {"greeter": ["vt-deadbeefcafe"]},
    }
    assert run_scenarios.evaluate_then(then, observed) is None


# ---------------------------------------------------------------------------
# B. load-time OracleError (unknown twin name / empty contains)
# ---------------------------------------------------------------------------

def _write_scenario(d, name, **kw):
    sc = {
        "ir_version": "0.1", "id": kw.pop("id", "BHV-001-S1"),
        "behavior_id": kw.pop("behavior_id", "BHV-001"),
        "title": "t", "given": "g",
        "when": kw.pop("when", {"run": ["python3", "-c", "pass"], "timeout_s": 10}),
        "then": kw.pop("then", {"exit_code": 0}),
    }
    sc.update(kw)
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(sc), encoding="utf-8")
    return sc


def test_load_rejects_empty_twin_observed_contains(tmp_path):
    d = tmp_path / "scen"
    _write_scenario(d, "a.json", then={"twin_observed": {"twin": "greeter", "contains": ""}})
    with pytest.raises(OracleError, match="twin_observed"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_empty_twin_observed_twin_name(tmp_path):
    d = tmp_path / "scen"
    _write_scenario(d, "a.json", then={"twin_observed": {"twin": "", "contains": "x"}})
    with pytest.raises(OracleError, match="twin_observed"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_malformed_twin_observed_shape(tmp_path):
    d = tmp_path / "scen"
    _write_scenario(d, "a.json", then={"twin_observed": {"twin": "greeter"}})  # missing contains
    with pytest.raises(OracleError, match="twin_observed"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_empty_stdout_echoes_twin_twin_name(tmp_path):
    d = tmp_path / "scen"
    _write_scenario(d, "a.json", then={"stdout_echoes_twin": {"twin": ""}})
    with pytest.raises(OracleError, match="stdout_echoes_twin"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_malformed_stdout_echoes_twin_shape(tmp_path):
    d = tmp_path / "scen"
    _write_scenario(d, "a.json", then={"stdout_echoes_twin": {"twin": "greeter", "extra": 1}})
    with pytest.raises(OracleError, match="stdout_echoes_twin"):
        run_scenarios.load_scenarios(str(d))


def test_run_all_rejects_unknown_twin_name_before_any_scenario_runs(tmp_path):
    d = tmp_path / "scen"
    ws = tmp_path / "ws"
    ws.mkdir()
    marker = ws / "a-ran.txt"
    # a.json sorts first and, if executed, would prove it (touches a marker
    # file). b.json references a twin no `observer_files` knows about.
    (ws / "touch.py").write_text(
        f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    _write_scenario(d, "a.json", id="BHV-001-S1", behavior_id="BHV-001",
                    when={"run": ["python3", "touch.py"], "timeout_s": 10},
                    then={"exit_code": 0})
    _write_scenario(d, "b.json", id="BHV-002-S1", behavior_id="BHV-002",
                    then={"twin_observed": {"twin": "ghost", "contains": "x"}})
    with pytest.raises(OracleError, match="ghost"):
        run_scenarios.run_all(str(d), str(ws), observer_files={"greeter": "/nonexistent"})
    assert not marker.exists(), "a.json ran despite b.json's load-time error — not 'before any scenario runs'"


def test_run_all_unknown_twin_in_final_cohort_errors_on_a_dev_run(tmp_path):
    # A cohort="final" scenario referencing an unknown twin must raise on a
    # cohort="dev" run_all -- the name-existence check runs over the FULL,
    # unfiltered scenario set (all cohorts) before the cohort filter, so a
    # final-cohort typo can't hide until the sealed final exam eventually
    # runs (after dev converges -- possibly never).
    d = tmp_path / "scen"
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "ok.py").write_text('print("ok")\n', encoding="utf-8")
    _write_scenario(d, "dev.json", id="BHV-001-S1", behavior_id="BHV-001", cohort="dev",
                    when={"run": ["python3", "ok.py"], "timeout_s": 10},
                    then={"exit_code": 0, "stdout_equals": "ok"})
    _write_scenario(d, "final.json", id="BHV-002-S1", behavior_id="BHV-002", cohort="final",
                    then={"twin_observed": {"twin": "ghost", "contains": "x"}})
    with pytest.raises(OracleError, match="ghost"):
        run_scenarios.run_all(str(d), str(ws), cohort="dev",
                              observer_files={"greeter": "/nonexistent"})


def test_run_all_with_observer_files_none_makes_any_twin_assertion_error(tmp_path):
    d = tmp_path / "scen"
    ws = tmp_path / "ws"
    ws.mkdir()
    _write_scenario(d, "a.json", then={"stdout_echoes_twin": {"twin": "greeter"}})
    with pytest.raises(OracleError, match="greeter"):
        run_scenarios.run_all(str(d), str(ws))  # observer_files defaults to None


def test_run_all_without_twin_assertions_is_unaffected_by_missing_observer_files(tmp_path):
    d = tmp_path / "scen"
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "ok.py").write_text('print("ok")\n', encoding="utf-8")
    _write_scenario(d, "a.json", when={"run": ["python3", "ok.py"], "timeout_s": 10},
                    then={"exit_code": 0, "stdout_equals": "ok"})
    rep = run_scenarios.run_all(str(d), str(ws))  # no twins configured, no twin assertions
    assert rep["all_pass"] is True


# ---------------------------------------------------------------------------
# C. run_all offset-delta attribution (live twin_greeter)
# ---------------------------------------------------------------------------

def _write_twin_def(twins_dir, name="greeter", **over):
    twins_dir.mkdir(parents=True, exist_ok=True)
    d = {"twin_version": "0.1", "name": name, "launch": ["python3", GREETER],
         "fidelity": "dev mock"}
    d.update(over)
    (twins_dir / f"{name}.json").write_text(json.dumps(d), encoding="utf-8")
    return d


def _call_twin_script(ws, filename="call_twin.py"):
    (ws / filename).write_text(
        "import os, sys, urllib.request\n"
        "name = sys.argv[1]\n"
        "url = f\"http://{os.environ['DF_TWIN_GREETER']}/greet/{name}\"\n"
        "print(urllib.request.urlopen(url, timeout=5).read().decode())\n",
        encoding="utf-8",
    )


class _LiveTwin:
    """Test harness: starts a real twin_greeter via TwinSet, tears it down."""

    def __init__(self, tmp_path, supports_variants=False):
        self.tmp_path = tmp_path
        self.supports_variants = supports_variants
        self.ts = df_twins.TwinSet()

    def __enter__(self):
        twins_dir = self.tmp_path / "twins"
        _write_twin_def(twins_dir, supports_variants=self.supports_variants)
        self.run_dir = self.tmp_path / "run"
        self.run_dir.mkdir()
        defs = df_twins.load_defs(str(twins_dir))
        extra = {"DF_TWIN_VARIANT_SEED": "carry-over-seed-marker"} if self.supports_variants else None
        self.env = self.ts.start(defs, str(self.run_dir), 20, extra_env=extra)
        return self

    def __exit__(self, *exc):
        self.ts.stop()


def test_offset_delta_attributes_only_this_scenarios_calls(tmp_path):
    with _LiveTwin(tmp_path) as twin:
        d = tmp_path / "scen"
        ws = tmp_path / "ws"
        ws.mkdir()
        _call_twin_script(ws)
        _write_scenario(d, "s0.json", id="BHV-001-S1", behavior_id="BHV-001",
                        when={"run": ["python3", "call_twin.py", "Alice"], "timeout_s": 10},
                        then={"exit_code": 0, "twin_observed": {"twin": "greeter", "contains": "/greet/Alice"}})
        _write_scenario(d, "s1.json", id="BHV-002-S1", behavior_id="BHV-002",
                        when={"run": ["python3", "call_twin.py", "Bob"], "timeout_s": 10},
                        then={"exit_code": 0, "twin_observed": {"twin": "greeter", "contains": "/greet/Bob"}})
        rep = run_scenarios.run_all(str(d), str(ws), env_extra=twin.env,
                                    observer_files=twin.ts.observer_files)
        assert rep["all_pass"] is True, rep
        alice_obs = rep["results"][0]["observed"]["twin_observations"]["greeter"]
        bob_obs = rep["results"][1]["observed"]["twin_observations"]["greeter"]
        assert any("/greet/Alice" in l for l in alice_obs)
        assert not any("/greet/Bob" in l for l in alice_obs), "Alice's delta leaked Bob's call"
        assert any("/greet/Bob" in l for l in bob_obs)
        assert not any("/greet/Alice" in l for l in bob_obs), "Bob's delta leaked Alice's call"


def test_offset_delta_empty_when_scenario_makes_zero_twin_calls(tmp_path):
    with _LiveTwin(tmp_path) as twin:
        d = tmp_path / "scen"
        ws = tmp_path / "ws"
        ws.mkdir()
        _call_twin_script(ws)
        (ws / "no_call.py").write_text('print("no-twin-call")\n', encoding="utf-8")
        _write_scenario(d, "s0.json", id="BHV-001-S1", behavior_id="BHV-001",
                        when={"run": ["python3", "call_twin.py", "Carol"], "timeout_s": 10},
                        then={"exit_code": 0, "twin_observed": {"twin": "greeter", "contains": "/greet/Carol"}})
        _write_scenario(d, "s1.json", id="BHV-002-S1", behavior_id="BHV-002",
                        when={"run": ["python3", "no_call.py"], "timeout_s": 10},
                        then={"exit_code": 0, "stdout_equals": "no-twin-call"})
        rep = run_scenarios.run_all(str(d), str(ws), env_extra=twin.env,
                                    observer_files=twin.ts.observer_files)
        assert rep["all_pass"] is True, rep
        # zero-call scenario gets an EMPTY delta, not the previous scenario's.
        assert rep["results"][1]["observed"]["twin_observations"]["greeter"] == []
        assert rep["results"][1]["observed"]["twin_tokens"]["greeter"] == []


def test_stdout_echoes_twin_passes_with_live_seeded_twin(tmp_path):
    with _LiveTwin(tmp_path, supports_variants=True) as twin:
        d = tmp_path / "scen"
        ws = tmp_path / "ws"
        ws.mkdir()
        _call_twin_script(ws)
        _write_scenario(d, "s0.json", then={"exit_code": 0, "stdout_echoes_twin": {"twin": "greeter"}},
                        when={"run": ["python3", "call_twin.py", "Dave"], "timeout_s": 10})
        rep = run_scenarios.run_all(str(d), str(ws), env_extra=twin.env,
                                    observer_files=twin.ts.observer_files)
        assert rep["all_pass"] is True, rep


def test_stdout_echoes_twin_fails_without_seed_no_tokens_recorded(tmp_path):
    with _LiveTwin(tmp_path, supports_variants=False) as twin:
        d = tmp_path / "scen"
        ws = tmp_path / "ws"
        ws.mkdir()
        _call_twin_script(ws)
        _write_scenario(d, "s0.json", then={"exit_code": 0, "stdout_echoes_twin": {"twin": "greeter"}},
                        when={"run": ["python3", "call_twin.py", "Eve"], "timeout_s": 10})
        rep = run_scenarios.run_all(str(d), str(ws), env_extra=twin.env,
                                    observer_files=twin.ts.observer_files)
        assert rep["all_pass"] is False
        assert rep["results"][0]["taxonomy"] == "no_twin_evidence"


# ---------------------------------------------------------------------------
# D. df_gates.is_discriminating with twin assertions
# ---------------------------------------------------------------------------

def test_is_discriminating_true_for_twin_observed():
    assert df_gates.is_discriminating(
        {"twin_observed": {"twin": "greeter", "contains": "x"}}) is True


def test_is_discriminating_true_for_stdout_echoes_twin():
    assert df_gates.is_discriminating({"stdout_echoes_twin": {"twin": "greeter"}}) is True


def test_is_discriminating_true_for_combined_output_and_twin_assertion():
    assert df_gates.is_discriminating(
        {"exit_code": 0, "twin_observed": {"twin": "greeter", "contains": "x"}}) is True


# ---------------------------------------------------------------------------
# E. id_feedback.TAXONOMY
# ---------------------------------------------------------------------------

def test_taxonomy_includes_no_twin_evidence():
    assert id_feedback.TAXONOMY == (
        "wrong_exit_code", "wrong_output", "timeout", "crash", "no_twin_evidence")


def test_taxonomy_no_twin_evidence_is_a_valid_feedback_value():
    report = {"results": [
        {"id": "BHV-001-S1", "behavior_id": "BHV-001", "pass": False,
         "taxonomy": "no_twin_evidence", "observed": {}},
    ]}
    fb = id_feedback.project_feedback(report)
    id_feedback.validate_feedback(fb)  # must not raise
    assert fb["failures"][0]["taxonomy"] == ["no_twin_evidence"]


# ---------------------------------------------------------------------------
# F. supervisor: verify-pass seed presence/absence + barrier + manifest
# ---------------------------------------------------------------------------

class _RecordingTwinSet:
    """Fakes TwinSet's lifecycle surface, recording every start()/reset()
    call's extra_env (as a plain dict, decoupled from the real object) into
    module-level lists the test can inspect after the run completes."""

    START_CALLS = []
    RESET_CALLS = []

    def __init__(self):
        self.observer_files = {}
        self.env = {"DF_TWIN_GREETER": "127.0.0.1:9"}

    def start(self, defs, run_dir, timeout, extra_env=None, phase="build"):
        _RecordingTwinSet.START_CALLS.append(dict(extra_env or {}))
        return self.env

    def reset(self, defs, run_dir, timeout, extra_env=None, phase="verify"):
        _RecordingTwinSet.RESET_CALLS.append(dict(extra_env or {}))
        return self.env

    def stop(self):
        pass


def _twin_control_for_seed_test(tmp_path, supports_variants):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # An extra FINAL-cohort scenario, trivially passing and unrelated to
    # greet.py, so a final exam actually runs once dev converges.
    final_sc = {
        "ir_version": "0.1", "id": "BHV-999-S1", "behavior_id": "BHV-999",
        "title": "t", "given": "g", "cohort": "final",
        "when": {"run": ["python3", "-c", "print('ok')"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_equals": "ok"},
    }
    (cr / "scenarios" / "s9.json").write_text(json.dumps(final_sc), encoding="utf-8")
    (cr / "twins").mkdir()
    (cr / "twins" / "greeter.json").write_text(json.dumps(
        {"twin_version": "0.1", "name": "greeter", "launch": ["python3", GREETER],
         "fidelity": "dev mock", "supports_variants": supports_variants}), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"] = {"enabled": True, "startup_timeout_s": 20}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def test_seed_present_at_verify_reset_only_when_supports_variants(tmp_path, monkeypatch):
    _RecordingTwinSet.START_CALLS = []
    _RecordingTwinSet.RESET_CALLS = []
    monkeypatch.setattr(supervisor.df_twins, "TwinSet", _RecordingTwinSet)
    cr = _twin_control_for_seed_test(tmp_path, supports_variants=True)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    # fake_builder converges in 2 iterations: build starts twins ONCE.
    assert len(_RecordingTwinSet.START_CALLS) == 1
    assert _RecordingTwinSet.START_CALLS[0] == {}, "build-phase start() must NEVER carry a seed"

    # supports_variants=True: 3 seeded resets -- iter1 dev (fails), iter2 dev
    # (passes), iter2 final exam (its OWN fresh seed, distinct from dev's).
    assert len(_RecordingTwinSet.RESET_CALLS) == 3
    seeds = [r.get("DF_TWIN_VARIANT_SEED") for r in _RecordingTwinSet.RESET_CALLS]
    assert all(s is not None for s in seeds), f"expected a seed on every reset, got {seeds}"
    assert len(set(seeds)) == 3, "every verify pass (dev x2, final x1) must get its OWN fresh seed"
    # The final-exam seed is distinct from the dev-verify seed of the same
    # converging iteration (index 1 = iter2 dev, index 2 = iter2 final).
    assert seeds[1] != seeds[2], "final exam reused dev-verify's seed"


def test_seedless_final_exam_does_no_extra_reset_when_supports_variants_false(tmp_path, monkeypatch):
    _RecordingTwinSet.START_CALLS = []
    _RecordingTwinSet.RESET_CALLS = []
    monkeypatch.setattr(supervisor.df_twins, "TwinSet", _RecordingTwinSet)
    cr = _twin_control_for_seed_test(tmp_path, supports_variants=False)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    assert _RecordingTwinSet.START_CALLS == [{}]
    # 2 resets ONLY -- iter1 dev, iter2 dev. The final exam does NOT reset:
    # with no supports_variants twin, a restart would be pure churn, so it
    # reuses dev-verify's running twins (byte-identical to the pre-M12 path).
    assert len(_RecordingTwinSet.RESET_CALLS) == 2
    assert all(r == {} for r in _RecordingTwinSet.RESET_CALLS), \
        "no supports_variants twin -> extra_env must be exactly None/{} (today's behavior)"


def test_builder_captured_env_never_has_seed(tmp_path, monkeypatch):
    monkeypatch.setattr(supervisor.df_twins, "TwinSet", _RecordingTwinSet)
    _RecordingTwinSet.START_CALLS = []
    _RecordingTwinSet.RESET_CALLS = []
    cr = _twin_control_for_seed_test(tmp_path, supports_variants=True)

    builder_envs = []
    real_invoke = supervisor.invoke_adapter

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None):
        if role == "builder":
            builder_envs.append(dict(env_extra or {}))
            builder_envs[-1].update(dict(env_full or {}) if env_full else {})
        return real_invoke(adapter, role, workdir, prompt_file, timeout_s,
                           exec_prefix=exec_prefix, env_extra=env_extra, env_full=env_full)

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert builder_envs, "builder was never invoked — vacuous check"
    for env in builder_envs:
        assert "DF_TWIN_VARIANT_SEED" not in env


def test_manifest_twin_evidence_none_when_twins_disabled(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    run_id = os.listdir(cr / "runs")[0]
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["twin_evidence"] is None


def test_manifest_twin_evidence_shape_on_converged_live_twin(tmp_path):
    cr = setup_control(tmp_path, FAKE_TWIN_BUILDER, checkpoint="auto")
    (cr / "spec.md").write_text(
        "# greet CLI (twin-backed)\nCreate greet.py that calls the greeter twin.\n",
        encoding="utf-8")
    for old in (cr / "scenarios").glob("*.json"):
        old.unlink()
    twin_sc = {
        "ir_version": "0.1", "id": "BHV-001-S1", "behavior_id": "BHV-001",
        "title": "t", "given": "g",
        "when": {"run": ["python3", "greet.py", "World"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_contains": "Hello, World!",
                 "twin_observed": {"twin": "greeter", "contains": "/greet/World"}},
    }
    (cr / "scenarios" / "s0.json").write_text(json.dumps(twin_sc), encoding="utf-8")
    (cr / "twins").mkdir()
    (cr / "twins" / "greeter.json").write_text(json.dumps(
        {"twin_version": "0.1", "name": "greeter", "launch": ["python3", GREETER],
         "fidelity": "dev mock", "supports_variants": True}), encoding="utf-8")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["twins"] = {"enabled": True, "startup_timeout_s": 20}
    (cr / "config.json").write_text(json.dumps(cfg))

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    run_id = os.listdir(cr / "runs")[0]
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["twin_evidence"] == {"variants": True, "observed_assertions": 1}


def test_manifest_twin_evidence_present_on_aborted_build_error(tmp_path, monkeypatch):
    # Force a build-error abort (bad adapter) after GATE_PASSED, with twins
    # enabled -- twin_evidence must still be a dict (computed at GATE_PASSED
    # time, before the build even starts), not absent/None.
    cr = _twin_control_for_seed_test(tmp_path, supports_variants=False)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["roles"]["builder"]["adapter"] = os.path.join(HERE, "fixtures", "fake_cli_fail")
    (cr / "config.json").write_text(json.dumps(cfg))

    rc = supervisor.run(str(cr), None)
    assert rc == 2
    run_id = os.listdir(cr / "runs")[0]
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["outcome"] == "ABORTED_BUILD_ERROR"
    assert manifest["twin_evidence"] == {"variants": False, "observed_assertions": 0}


def test_resume_threads_twin_evidence_and_fresh_seed_across_pause(tmp_path, monkeypatch):
    _RecordingTwinSet.START_CALLS = []
    _RecordingTwinSet.RESET_CALLS = []
    monkeypatch.setattr(supervisor.df_twins, "TwinSet", _RecordingTwinSet)
    cr = _twin_control_for_seed_test(tmp_path, supports_variants=True)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["checkpoint"] = "pause"
    (cr / "config.json").write_text(json.dumps(cfg))

    rc1 = supervisor.run(str(cr), None)
    assert rc1 == supervisor.PAUSED
    reset_calls_before_resume = len(_RecordingTwinSet.RESET_CALLS)
    assert reset_calls_before_resume >= 1

    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == 0
    assert len(_RecordingTwinSet.RESET_CALLS) > reset_calls_before_resume, \
        "resume must perform its OWN fresh reset(s), not reuse the pre-pause one"
    seeds = [r.get("DF_TWIN_VARIANT_SEED") for r in _RecordingTwinSet.RESET_CALLS]
    assert len(set(seeds)) == len(seeds), "every reset across the pause/resume boundary is unique"

    run_id = os.listdir(cr / "runs")[0]
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["twin_evidence"] == {"variants": True, "observed_assertions": 0}


def test_seed_never_appears_in_journal_manifest_or_prompt_bytes(tmp_path, monkeypatch):
    seeds_seen = []
    real_uuid4 = supervisor.uuid.uuid4

    class _Marked:
        def __init__(self, n):
            self.hex = f"seedmarker{n:04d}deadbeefcafefeed"

    counter = {"n": 0}

    def fake_uuid4():
        counter["n"] += 1
        m = _Marked(counter["n"])
        seeds_seen.append(m.hex)
        return m

    monkeypatch.setattr(supervisor.uuid, "uuid4", fake_uuid4)
    cr = _twin_control_for_seed_test(tmp_path, supports_variants=True)

    rc = supervisor.run(str(cr), None)
    assert rc == 0
    assert len(seeds_seen) >= 2, "vacuous check — no seeds were ever generated"

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    checked_any = False
    for root, _dirs, files in os.walk(run_dir):
        for fn in files:
            checked_any = True
            with open(os.path.join(root, fn), "rb") as f:
                data = f.read()
            for seed in seeds_seen:
                assert seed.encode() not in data, \
                    f"raw seed leaked into {os.path.join(root, fn)}"
    assert checked_any, "run_dir was empty — vacuous proof"


# ---------------------------------------------------------------------------
# G. carry-over: raw seed never appears in twin response/observation logs
# ---------------------------------------------------------------------------

def test_raw_seed_never_appears_in_twin_response_or_observation(tmp_path):
    seed = "RAW-SEED-VALUE-MUST-NEVER-LEAK-93e1"
    twins_dir = tmp_path / "twins"
    _write_twin_def(twins_dir, supports_variants=True)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        defs = df_twins.load_defs(str(twins_dir))
        env = ts.start(defs, str(run_dir), 20, extra_env={"DF_TWIN_VARIANT_SEED": seed})
        host, port = env["DF_TWIN_GREETER"].split(":")
        body = urllib.request.urlopen(f"http://{host}:{port}/greet/World", timeout=5).read().decode()
        assert "vt-" in body
        assert seed not in body, "the raw seed leaked into the twin's response body"

        obs_path = ts.observer_files["greeter"]
        with open(obs_path, encoding="utf-8") as f:
            obs_text = f.read()
        assert "vt-" in obs_text
        assert seed not in obs_text, "the raw seed leaked into the observation log"
    finally:
        ts.stop()
