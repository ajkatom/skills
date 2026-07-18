"""M42 Task 2 unit tests for the sharpness battery (df_gates.sharpness).

The battery ISOLATES each asserted dimension and requires the `then` to reject a
near-miss on EVERY one -- strictly stronger than the old single compound mutant,
which passed as long as ANY channel differed. These tests pin:
  - the concrete near-miss the OLD single-mutant check MISSED but the battery
    kills (an inert sub-assertion riding alongside a real one);
  - genuinely sharp CLI/HTTP/twin scenarios still pass;
  - per-mutant survivor reporting (kinds are barrier-safe category labels);
  - HONEST scope: it mutates the OBSERVATION, not the built code.
"""
import df_gates
import run_scenarios


# --- the concrete near-miss the old check missed ---------------------------

def _old_single_mutant_passes(then):
    """Reconstruct the PRE-M42 single-compound-mutant check to demonstrate what
    it accepted. (The old is_discriminating built ONE mutant that perturbed
    exit_code AND stdout AND stderr AND twins at once.)"""
    if df_gates._is_http_then(then):
        mutant = {"http_status": (then.get("http_status", 0) + 1) or 599,
                  "body": "\x00MUTANT", "json": {"__mutant__": True}}
        return run_scenarios.evaluate_http(then, mutant) is not None
    mutant = {
        "exit_code": (then["exit_code"] + 1) if "exit_code" in then else 999999,
        "stdout": "\x00DF-MUTANT-\x00", "stderr": "\x00DF-MUTANT-\x00",
        "twin_observations": {}, "twin_tokens": {},
    }
    return run_scenarios.evaluate_then(then, mutant) is not None


def test_battery_kills_inert_subassertion_old_check_missed():
    # {"exit_code": 0, "stdout_contains": ""} : the stdout check asserts NOTHING
    # (every output contains ""). The OLD compound mutant also flipped the exit
    # code, so evaluate_then returned "wrong_exit_code" -> the old check called
    # this DISCRIMINATING. The battery isolates the stdout dimension (holding
    # exit_code correct) and exposes the inert assertion as a survivor.
    then = {"exit_code": 0, "stdout_contains": ""}
    assert _old_single_mutant_passes(then) is True        # old check: passed it
    rep = df_gates.sharpness(then)
    assert rep["passed"] is False                          # battery: flags it
    assert "stdout_contains:empty" in rep["survivors"]


def test_same_channel_sibling_cannot_mask_inert_coassertion():
    # Regression (adversarial review, Finding 1): the battery attributes each
    # mutant's kill to the DIMENSION UNDER TEST (it evaluates against the `then`
    # reduced to that one assertion). Before the fix, a sharp SIBLING assertion
    # on the SAME channel killed the inert-exposing mutant for the wrong reason
    # -- fail-open. Each of these must now be flagged, with the inert
    # sub-assertion named in `survivors`.
    cases = [
        ({"stdout_equals": "x", "stdout_contains": ""}, "stdout_contains:empty"),
        ({"stderr_equals": "boom", "stderr_contains": ""}, "stderr_contains:empty"),
        ({"stdout_contains": "", "stdout_echoes_twin": {"twin": "T"}}, "stdout_contains:empty"),
    ]
    for then, survivor in cases:
        rep = df_gates.sharpness(then)
        assert rep["passed"] is False, (then, rep)
        assert survivor in rep["survivors"], (then, rep)


def test_genuinely_sharp_multi_assertion_still_passes():
    # The attribution fix must NOT flag a `then` whose every assertion is sharp,
    # including belt-and-suspenders empty-stderr and same-channel echo combos.
    for then in (
        {"exit_code": 0, "stdout_equals": "Hello, World!"},
        {"exit_code": 0, "stdout_contains": "200", "stderr_equals": ""},
        {"stdout_equals": "hi", "stdout_echoes_twin": {"twin": "T"}},
        {"http_status": 200, "body_contains": "created", "json_contains": {"id": 7}},
    ):
        assert df_gates.sharpness(then)["passed"] is True, then


def test_equals_empty_is_sharp_not_flagged():
    # `stderr_equals: ""` = "assert no error output" is a LEGITIMATE, common
    # assertion, NOT a tautology: it rejects any non-empty output. The empty
    # mutant would be the identity (== the asserted value), so it is not
    # generated; whitespace/char-changed/appended near-misses all die.
    rep = df_gates.sharpness({"exit_code": 0, "stderr_equals": ""})
    assert rep["passed"] is True, rep
    # And a real combined scenario (strong stdout + belt-and-suspenders empty
    # stderr) passes -- the pattern the kv example uses.
    rep2 = df_gates.sharpness(
        {"exit_code": 0, "stdout_contains": '200\n{"status": "ok"}', "stderr_equals": ""})
    assert rep2["passed"] is True, rep2


# --- genuinely sharp scenarios still pass ----------------------------------

def test_sharp_cli_scenarios_pass():
    for then in (
        {"exit_code": 0, "stdout_equals": "Hello, World!"},
        {"exit_code": 2, "stderr_contains": "greet.py <name>"},
        {"exit_code": 0},                                  # exit-code-only is sharp
        {"stdout_equals": "line1\nline2\n"},
    ):
        rep = df_gates.sharpness(then)
        assert rep["passed"] is True, (then, rep)
        assert rep["killed"] == rep["total"] and rep["survivors"] == []


def test_sharp_http_scenarios_pass():
    for then in (
        {"http_status": 201},
        {"http_status": 200, "json_contains": {"ok": True, "id": 7}},
        {"body_contains": "created id=42"},
        {"json_path": {"items[0].id": 9}},
        {"json_equals": {"a": 1, "b": "x"}},
    ):
        rep = df_gates.sharpness(then)
        assert rep["passed"] is True, (then, rep)


def test_sharp_twin_scenario_passes():
    rep = df_gates.sharpness({"twin_observed": {"twin": "greeter", "contains": "abc"}})
    assert rep["passed"] is True
    # single-char contains is still sharp (no_evidence + wrong_token kill it)
    rep1 = df_gates.sharpness({"twin_observed": {"twin": "greeter", "contains": "x"}})
    assert rep1["passed"] is True


# --- inert HTTP assertions are flagged -------------------------------------

def test_inert_http_assertions_flagged():
    r1 = df_gates.sharpness({"http_status": 200, "json_contains": {}})
    assert r1["passed"] is False and "json_contains:value_changed" in r1["survivors"]
    r2 = df_gates.sharpness({"body_contains": ""})
    assert r2["passed"] is False and "body_contains:empty" in r2["survivors"]


# --- survivor reporting + manifest summary ---------------------------------

def test_survivor_kinds_are_category_labels_not_values():
    # A survivor kind names the SHAPE that survived, never the asserted value --
    # so it is barrier-safe to feed back to an author.
    rep = df_gates.sharpness({"exit_code": 0, "stdout_contains": ""})
    for kind in rep["survivors"]:
        assert ":" in kind
        assert "Hello" not in kind  # no holdout value ever appears in a kind


def test_validate_oracle_and_manifest_use_the_battery():
    scs = [
        {"id": "BHV-001-S1", "then": {"exit_code": 0, "stdout_equals": "X!"}},
        {"id": "BHV-001-S2", "then": {"exit_code": 0, "stdout_contains": ""}},
    ]
    inert = df_gates.validate_oracle(scs)
    assert inert == ["BHV-001-S2"]                 # the non-sharp one, by id
    surv = df_gates.sharpness_survivors(scs)
    assert set(surv) == {"BHV-001-S2"}
    mf = df_gates.sharpness_manifest([scs[0]])     # only the sharp one
    assert mf["scenarios"] == 1 and mf["weakest"] == [] and mf["min_killed"] >= 1


def test_is_discriminating_shim_matches_battery():
    assert df_gates.is_discriminating({"exit_code": 0, "stdout_equals": "hi"}) is True
    assert df_gates.is_discriminating({"exit_code": 0, "stdout_contains": ""}) is False
