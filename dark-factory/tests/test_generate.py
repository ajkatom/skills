"""M43a Task 1: df_generate — seeded, declarative, bounded generators.

The load-bearing claims tested here: generation is a PURE function of
(seed, spec) — same seed ⇒ byte-identical cases, different seed ⇒ different
cases; every kind stays inside its declared bounds; every value is a string
(substitution is literal interpolation); and validation fails CLOSED on every
malformed shape (unknown kind, out-of-bounds cases, missing/bool seed,
malformed-of-malformed) BEFORE anything runs.
"""
import json

import pytest

import df_generate


def spec(**kw):
    base = {
        "vars": {
            "n": {"kind": "int", "min": -5, "max": 20},
            "s": {"kind": "string", "charset": "alnum", "min_len": 1, "max_len": 8},
            "j": {"kind": "json", "shape": "scalar_or_object"},
            "c": {"kind": "choice", "options": ["red", "green", "blue"]},
            "m": {"kind": "malformed", "base": "s"},
        },
        "cases": 20,
        "seed": 1234,
    }
    base.update(kw)
    return base


# --- determinism (the reproducibility contract) -----------------------------

def test_same_seed_same_cases_byte_identical():
    a = df_generate.generate_cases(spec())
    b = df_generate.generate_cases(spec())
    assert a == b
    # Byte-identical through serialization too (what a manifest/replay sees).
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_different_seed_different_cases():
    a = df_generate.generate_cases(spec(seed=1))
    b = df_generate.generate_cases(spec(seed=2))
    assert a != b


def test_determinism_independent_of_var_declaration_order():
    """The stream is consumed in sorted-var order, NOT dict order — so two
    scenario files whose JSON happens to list vars differently generate the
    same cases."""
    fwd = spec()
    rev = spec()
    rev["vars"] = dict(reversed(list(fwd["vars"].items())))
    assert df_generate.generate_cases(fwd) == df_generate.generate_cases(rev)


# --- per-kind bounds + shapes ----------------------------------------------

def test_all_values_are_strings():
    for case in df_generate.generate_cases(spec()):
        assert set(case) == {"n", "s", "j", "c", "m"}
        assert all(isinstance(v, str) for v in case.values())


def test_int_kind_within_bounds():
    for case in df_generate.generate_cases(spec()):
        assert -5 <= int(case["n"]) <= 20


def test_string_kind_within_length_bounds_and_charset():
    for case in df_generate.generate_cases(spec()):
        assert 1 <= len(case["s"]) <= 8
        assert case["s"].isalnum()


def test_json_kind_emits_parseable_json():
    for case in df_generate.generate_cases(spec()):
        json.loads(case["j"])  # must not raise


def test_choice_kind_picks_a_declared_option():
    for case in df_generate.generate_cases(spec()):
        assert case["c"] in ("red", "green", "blue")


def test_bytes_charset_never_emits_nul():
    # NUL in argv is an execve error, not a robustness probe (see module
    # comment) — the bytes charset must exclude it.
    g = {"vars": {"b": {"kind": "string", "charset": "bytes",
                        "min_len": 32, "max_len": 64}},
         "cases": 50, "seed": 9}
    for case in df_generate.generate_cases(g):
        assert "\x00" not in case["b"]
        assert 32 <= len(case["b"]) <= 64


def test_malformed_is_deterministic_and_bounded():
    a = df_generate.generate_cases(spec())
    b = df_generate.generate_cases(spec())
    assert [c["m"] for c in a] == [c["m"] for c in b]
    for case in a:
        assert len(case["m"]) <= df_generate.MAX_STRING_LEN


def test_malformed_literal_base():
    g = {"vars": {"m": {"kind": "malformed", "base": '{"value": 1}'}},
         "cases": 30, "seed": 4}
    cases = df_generate.generate_cases(g)
    # Across 30 draws the variant menu is swept: at least one variant differs
    # from the base (all-identity would make the fuzz inert).
    assert any(c["m"] != '{"value": 1}' for c in cases)


# --- validation: fail-closed on every malformed shape -----------------------

@pytest.mark.parametrize("mutate,fragment", [
    (lambda g: g.pop("seed"), "seed"),
    (lambda g: g.update(seed=True), "seed"),
    (lambda g: g.update(seed="7"), "seed"),
    (lambda g: g.update(cases=0), "cases"),
    (lambda g: g.update(cases=df_generate.MAX_CASES + 1), "cases"),
    (lambda g: g.update(cases="10"), "cases"),
    (lambda g: g.update(vars={}), "vars"),
    (lambda g: g.update(vars="x"), "vars"),
    (lambda g: g.update(extra=1), "unknown"),
])
def test_validate_rejects_bad_top_level(mutate, fragment):
    g = spec()
    mutate(g)
    with pytest.raises(df_generate.GenerateError, match=fragment):
        df_generate.validate_generate(g, "t")


@pytest.mark.parametrize("varspec,fragment", [
    ({"kind": "nope"}, "kind"),
    ({"kind": "int", "min": 5, "max": 1}, "min"),
    ({"kind": "int", "min": "0", "max": 1}, "int"),
    ({"kind": "string", "charset": "hex", "max_len": 4}, "charset"),
    ({"kind": "string", "max_len": df_generate.MAX_STRING_LEN + 1}, "max_len"),
    ({"kind": "string", "min_len": 5, "max_len": 2}, "min_len"),
    ({"kind": "json", "shape": "tree"}, "shape"),
    ({"kind": "choice", "options": []}, "options"),
    ({"kind": "choice", "options": [1]}, "options"),
    ({"kind": "malformed", "base": 7}, "base"),
    ({"kind": "int", "min": 0, "max": 1, "step": 2}, "unknown"),
])
def test_validate_rejects_bad_var_spec(varspec, fragment):
    g = {"vars": {"x": varspec}, "cases": 5, "seed": 1}
    with pytest.raises(df_generate.GenerateError, match=fragment):
        df_generate.validate_generate(g, "t")


def test_validate_rejects_malformed_of_malformed():
    g = {"vars": {"a": {"kind": "malformed", "base": "hello"},
                  "b": {"kind": "malformed", "base": "a"}},
         "cases": 5, "seed": 1}
    with pytest.raises(df_generate.GenerateError, match="malformed"):
        df_generate.validate_generate(g, "t")


def test_validate_rejects_non_identifier_var_name():
    g = {"vars": {"bad-name": {"kind": "int", "min": 0, "max": 1}},
         "cases": 5, "seed": 1}
    with pytest.raises(df_generate.GenerateError, match="identifier"):
        df_generate.validate_generate(g, "t")


def test_generate_cases_validates_first():
    # A caller that skipped validate_generate is still fail-closed.
    with pytest.raises(df_generate.GenerateError):
        df_generate.generate_cases({"vars": {"x": {"kind": "nope"}}, "cases": 5})


def test_max_cases_boundary_accepted():
    g = {"vars": {"n": {"kind": "int", "min": 0, "max": 1}},
         "cases": df_generate.MAX_CASES, "seed": 3}
    assert len(df_generate.generate_cases(g)) == df_generate.MAX_CASES
