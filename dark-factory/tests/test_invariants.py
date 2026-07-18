"""M43a Task 2: df_invariants — the fixed invariant vocabulary.

Tested: every invariant holds on a conforming observation set and rejects a
violating one (CLI and HTTP shapes); repeat-requiring invariants fail CLOSED
when the repeat evidence is missing; aliases (never_crashes/sorted) share
behavior with their canonical form; validation rejects unknown names/args and
out-of-range references; and invariant discrimination flags a vacuous
configuration (round_trip over an empty-capable var) while passing real ones.
"""
import pytest

import df_invariants


def cli(exit_code=0, stdout="", stderr=""):
    return {"exit_code": exit_code, "stdout": stdout, "stderr": stderr}


def http(status=200, body="", json_obs=None):
    return {"http_status": status, "body": body, "json": json_obs}


def ev(name, case_vars, steps, repeat=None, args=None):
    inv = {"name": name}
    if args is not None:
        inv["args"] = args
    return df_invariants.evaluate_invariant(
        inv, case_vars, {"steps": steps, "repeat": repeat or []})


GEN = {"vars": {"k": {"kind": "string", "charset": "alnum", "min_len": 1, "max_len": 8},
                "v": {"kind": "string", "charset": "alnum", "min_len": 4, "max_len": 8}},
       "cases": 10, "seed": 5}


# --- validation -------------------------------------------------------------

def test_validate_accepts_every_vocabulary_name():
    for name in df_invariants.INVARIANT_NAMES:
        inv = {"name": name}
        if df_invariants.canonical_name(name) == "round_trip":
            inv["args"] = {"value": "v"}
        df_invariants.validate_invariant(inv, GEN, 2, "t")


@pytest.mark.parametrize("inv,fragment", [
    ({"name": "always_true"}, "invariant.name"),
    ({"name": "robust", "args": {"bogus": 1}}, "unknown arg"),
    ({"name": "robust", "extra": 1}, "unknown key"),
    ({"name": "round_trip"}, "value"),
    ({"name": "round_trip", "args": {"value": "nope"}}, "declared"),
    ({"name": "round_trip", "args": {"value": "v", "observe_step": 5}}, "observe_step"),
    ({"name": "round_trip", "args": {"value": "v", "observe_step": -1}}, "observe_step"),
    ({"name": "robust", "args": {"allowed_exits": []}}, "allowed_exits"),
    ({"name": "robust", "args": {"allowed_exits": ["0"]}}, "allowed_exits"),
    ({"name": "error_contract", "args": {"error_contains": ""}}, "error_contains"),
    ({"name": "monotonic", "args": {"order": "up"}}, "order"),
])
def test_validate_rejects_bad_invariants(inv, fragment):
    with pytest.raises(df_invariants.InvariantError, match=fragment):
        df_invariants.validate_invariant(inv, GEN, 2, "t")


# --- round_trip -------------------------------------------------------------

def test_round_trip_holds_when_value_reflected():
    ok, _ = ev("round_trip", {"v": "abcd"},
               [cli(0, "ok"), cli(0, "value=abcd\n")],
               args={"value": "v", "observe_step": 1})
    assert ok


def test_round_trip_violated_when_value_absent():
    ok, detail = ev("round_trip", {"v": "abcd"},
                    [cli(0, "ok"), cli(0, "value=zzzz\n")],
                    args={"value": "v", "observe_step": 1})
    assert not ok and "v" in detail


def test_round_trip_reads_http_body():
    ok, _ = ev("round_trip", {"v": "abcd"},
               [http(200, body='{"value": "abcd"}')],
               args={"value": "v", "observe_step": 0})
    assert ok


# --- idempotent / deterministic (repeat evidence) ---------------------------

def test_idempotent_holds_on_identical_repeat():
    ok, _ = ev("idempotent", {}, [cli(0, "state=1")], repeat=[cli(0, "state=1")])
    assert ok


def test_idempotent_violated_on_changed_repeat():
    ok, _ = ev("idempotent", {}, [cli(0, "state=1")], repeat=[cli(0, "state=2")])
    assert not ok


def test_idempotent_fails_closed_without_repeat_evidence():
    ok, detail = ev("idempotent", {}, [cli(0, "state=1")], repeat=[])
    assert not ok and "repeat" in detail


def test_deterministic_holds_and_violates():
    steps = [cli(0, "a"), cli(0, "b")]
    ok, _ = ev("deterministic", {}, steps, repeat=[cli(0, "a"), cli(0, "b")])
    assert ok
    ok, _ = ev("deterministic", {}, steps, repeat=[cli(0, "a"), cli(0, "X")])
    assert not ok
    ok, _ = ev("deterministic", {}, steps, repeat=[cli(0, "a")])  # short => closed
    assert not ok


# --- robust / never_crashes -------------------------------------------------

@pytest.mark.parametrize("name", ["robust", "never_crashes"])
def test_robust_holds_on_clean_exits(name):
    ok, _ = ev(name, {}, [cli(0, "ok"), cli(2, "", "rejected"), http(404)])
    assert ok


@pytest.mark.parametrize("bad,fragment", [
    (cli(None), "exit code"),
    (cli(-11), "abnormally"),
    (cli(139), "abnormally"),
    (cli(0, "", "Traceback (most recent call last):\n  boom"), "stack trace"),
    (http(500), "HTTP 500"),
    (http(None), "no HTTP response"),
])
def test_robust_rejects_crash_shapes(bad, fragment):
    ok, detail = ev("robust", {}, [cli(0, "ok"), bad])
    assert not ok and fragment in detail


def test_robust_allowed_exits_is_enforced():
    ok, _ = ev("robust", {}, [cli(3)], args={"allowed_exits": [0, 2]})
    assert not ok
    ok, _ = ev("robust", {}, [cli(2)], args={"allowed_exits": [0, 2]})
    assert ok


def test_robust_checks_repeat_observations_too():
    ok, _ = ev("robust", {}, [cli(0)], repeat=[cli(-9)])
    assert not ok


# --- error_contract ---------------------------------------------------------

def test_error_contract_holds_on_clean_cli_rejection():
    ok, _ = ev("error_contract", {}, [cli(2, "", "error: bad value\n")])
    assert ok


@pytest.mark.parametrize("obs,fragment", [
    (cli(0, "stored"), "silently accepted"),
    (cli(None), "exit code"),
    (cli(1, "", "Traceback (most recent call last):\n"), "stack trace"),
    (cli(1, "", ""), "no error message"),
])
def test_error_contract_rejects_bad_cli_shapes(obs, fragment):
    ok, detail = ev("error_contract", {}, [obs])
    assert not ok and fragment in detail


def test_error_contract_http_requires_4xx_with_error_body():
    ok, _ = ev("error_contract", {}, [http(400, '{"error": "bad"}', {"error": "bad"})])
    assert ok
    ok, _ = ev("error_contract", {}, [http(200, "{}", {})])
    assert not ok
    ok, _ = ev("error_contract", {}, [http(500, "boom")])
    assert not ok
    ok, _ = ev("error_contract", {}, [http(400, '{"ok": true}', {"ok": True})])
    assert not ok


def test_error_contract_error_contains():
    ok, _ = ev("error_contract", {}, [cli(1, "", "E42: nope")],
               args={"error_contains": "E42"})
    assert ok
    ok, _ = ev("error_contract", {}, [cli(1, "", "other")],
               args={"error_contains": "E42"})
    assert not ok


# --- monotonic / sorted -----------------------------------------------------

@pytest.mark.parametrize("name", ["monotonic", "sorted"])
def test_monotonic_holds_on_sorted_lines(name):
    ok, _ = ev(name, {}, [cli(0, "a\nb\nc\n")])
    assert ok


def test_monotonic_violated_on_unsorted():
    ok, _ = ev("monotonic", {}, [cli(0, "b\na\n")])
    assert not ok


def test_monotonic_desc_order():
    ok, _ = ev("monotonic", {}, [cli(0, "c\nb\na\n")], args={"order": "desc"})
    assert ok
    ok, _ = ev("monotonic", {}, [cli(0, "a\nb\n")], args={"order": "desc"})
    assert not ok


def test_monotonic_reads_http_json_array():
    ok, _ = ev("monotonic", {}, [http(200, "[1,2,3]", [1, 2, 3])])
    assert ok
    ok, _ = ev("monotonic", {}, [http(200, "[3,1]", [3, 1])])
    assert not ok


def test_monotonic_unorderable_fails_closed():
    ok, detail = ev("monotonic", {}, [http(200, '[1,"a"]', [1, "a"])])
    assert not ok and "orderable" in detail


# --- discrimination (the vacuous-invariant gate) ----------------------------

def test_discrimination_passes_real_configs():
    for inv in (
        {"name": "round_trip", "args": {"value": "v", "observe_step": 1}},
        {"name": "idempotent"},
        {"name": "deterministic"},
        {"name": "robust"},
        {"name": "never_crashes"},
        {"name": "error_contract"},
        {"name": "monotonic"},
        {"name": "sorted"},
    ):
        rep = df_invariants.invariant_is_discriminating(inv, GEN)
        assert rep["passed"], (inv, rep["survivors"])
        assert rep["killed"] == rep["total"] > 0
        assert rep["survivors"] == []


def test_discrimination_flags_vacuous_round_trip():
    """round_trip over a var whose generator can emit "" is vacuous for those
    cases ("" is a substring of every output) — the gate must flag it, not
    let it ride green forever."""
    vacuous_gen = {"vars": {"e": {"kind": "string", "charset": "alnum",
                                  "min_len": 0, "max_len": 2}},
                   "cases": 30, "seed": 11}
    inv = {"name": "round_trip", "args": {"value": "e", "observe_step": 0}}
    rep = df_invariants.invariant_is_discriminating(inv, vacuous_gen)
    assert not rep["passed"]
    assert "round_trip:empty_value" in rep["survivors"]


def test_vacuity_is_structural_not_probabilistic_every_seed():
    """Finding 2 regression: the empty-value vacuity is detected from the
    GENERATOR SPEC, so a round_trip over a `string{min_len:0}` value var is
    flagged for EVERY seed -- not the ~53% a 25-case sample happened to catch.
    A moderate max_len makes empty draws RARE, so a sampled battery would miss
    it on most seeds; the structural check does not."""
    for seed in range(60):
        gen = {"vars": {"e": {"kind": "string", "charset": "alnum",
                              "min_len": 0, "max_len": 40}},
               "cases": 25, "seed": seed}
        inv = {"name": "round_trip", "args": {"value": "e", "observe_step": 0}}
        rep = df_invariants.invariant_is_discriminating(inv, gen)
        assert not rep["passed"], f"seed {seed} not flagged"
        assert "round_trip:empty_value" in rep["survivors"]


@pytest.mark.parametrize("value_spec,vacuous", [
    ({"kind": "string", "charset": "alnum", "min_len": 0, "max_len": 8}, True),
    ({"kind": "string", "charset": "alnum", "min_len": 1, "max_len": 8}, False),
    ({"kind": "choice", "options": ["a", "", "c"]}, True),
    ({"kind": "choice", "options": ["a", "b"]}, False),
    ({"kind": "malformed", "base": "seed"}, True),   # the `empty` variant
    ({"kind": "int", "min": 0, "max": 9}, False),    # str(int) never ""
    ({"kind": "json", "shape": "scalar"}, False),    # json.dumps never ""
])
def test_value_var_empty_emission_detection(value_spec, vacuous):
    gen = {"vars": {"seed": {"kind": "string", "charset": "alnum",
                             "min_len": 1, "max_len": 4},
                    "v": value_spec},
           "cases": 10, "seed": 3}
    inv = {"name": "round_trip", "args": {"value": "v", "observe_step": 0}}
    rep = df_invariants.invariant_is_discriminating(inv, gen)
    assert rep["passed"] != vacuous
    assert ("round_trip:empty_value" in rep["survivors"]) == vacuous


def test_discrimination_is_deterministic():
    inv = {"name": "round_trip", "args": {"value": "v", "observe_step": 0}}
    a = df_invariants.invariant_is_discriminating(inv, GEN)
    b = df_invariants.invariant_is_discriminating(inv, GEN)
    assert a == b


def test_discrimination_error_contract_with_marker():
    inv = {"name": "error_contract", "args": {"error_contains": "E42"}}
    rep = df_invariants.invariant_is_discriminating(inv, GEN)
    assert rep["passed"]
    # The wrong-error battery entry only exists when a marker is declared.
    assert rep["total"] == 6
