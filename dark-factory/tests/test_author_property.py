"""M43a Task 5: the author may emit property/fuzz scenarios; the critic sees
them and can demand missing robustness properties.

Covers: the author prompt carries the property vocabulary; _normalize accepts
a `property` entry (exactly-one-of run/property enforced as a collected schema
error); validate_authored runs the SAME load-time validation + invariant
discrimination over property entries (a vacuous invariant is rejected with
barrier-safe survivor labels); and the critic prompt renders a property
scenario's generative spec + names the missing-fuzz-property duty.
"""
import df_author
import df_critic

SPEC = (
    "# Store\n"
    "Build app.py storing a value; malformed input must be rejected cleanly "
    "with a non-zero exit and an error on stderr, never a crash.\n"
)
BEHAVIORS = [
    {"id": "BHV-001", "description": "stores a value"},
    {"id": "BHV-002", "description": "rejects malformed input cleanly"},
]


def _prop_raw(**kw):
    sc = {
        "behavior_id": "BHV-002", "cohort": "dev", "class": "failure",
        "property": {
            "generate": {
                "vars": {"x": {"kind": "string", "charset": "ascii_printable",
                               "min_len": 8, "max_len": 16}},
                "cases": 10, "seed": 5,
            },
            "steps": [{"run": ["python3", "app.py", "{x}"]}],
            "timeout_s": 10,
        },
        "then": {"invariant": {"name": "robust"}},
        "title": "never crashes on generated input",
    }
    sc.update(kw)
    return sc


def _run_raw(bid="BHV-001"):
    return {
        "behavior_id": bid, "cohort": "dev",
        "run": ["python3", "app.py", "plainvalue1"],
        "then": {"exit_code": 0, "stdout_equals": "stored plainvalue1"},
        "title": "stores a plain value",
    }


def test_author_prompt_carries_property_vocabulary():
    prompt = df_author.compose_author_prompt(SPEC, BEHAVIORS)
    for token in ("property", "generate", "invariant", "malformed",
                  "error_contract", "robust", "seed"):
        assert token in prompt, token


def test_normalize_accepts_property_scenario():
    ok, report, normalized = df_author.validate_authored(
        [_run_raw(), _run_raw("BHV-002"), _prop_raw()], SPEC, BEHAVIORS)
    assert ok, report
    prop = [s for s in normalized if "property" in s["when"]]
    assert len(prop) == 1
    assert prop[0]["ir_version"] == "0.4"
    assert prop[0]["id"] == "BHV-002-S2"
    assert prop[0]["class"] == "failure"


def test_normalize_rejects_run_plus_property():
    bad = _prop_raw()
    bad["run"] = ["python3", "app.py"]
    ok, report, _ = df_author.validate_authored(
        [_run_raw(), _run_raw("BHV-002"), bad], SPEC, BEHAVIORS)
    assert not ok
    assert any("exactly one of 'run' or 'property'" in e
               for e in report["schema_errors"])


def test_malformed_property_is_a_collected_schema_error():
    bad = _prop_raw()
    del bad["property"]["generate"]["seed"]
    ok, report, _ = df_author.validate_authored(
        [_run_raw(), _run_raw("BHV-002"), bad], SPEC, BEHAVIORS)
    assert not ok
    assert any("seed" in e for e in report["schema_errors"])


def test_vacuous_property_invariant_rejected_with_survivor_labels():
    vac = _prop_raw()
    vac["property"]["generate"]["vars"]["x"]["min_len"] = 0  # ""-capable
    vac["property"]["steps"] = [{"run": ["python3", "app.py", "put", "{x}"]},
                                {"run": ["python3", "app.py", "get"]}]
    vac["then"] = {"invariant": {"name": "round_trip",
                                 "args": {"value": "x", "observe_step": 1}}}
    ok, report, _ = df_author.validate_authored(
        [_run_raw(), _run_raw("BHV-002"), vac], SPEC, BEHAVIORS)
    assert not ok
    title = "never crashes on generated input"
    assert title in report["non_discriminating_titles"]
    # Barrier-safe feedback: category labels, never a generated value.
    assert "round_trip:empty_value" in report["non_sharp_survivors"][title]
    lines = "\n".join(df_author._feedback_lines(report))
    assert "round_trip:empty_value" in lines


def test_property_then_produces_no_spec_leak_false_positive():
    # A property then's strings are vocabulary names + var references ("x"),
    # which trivially appear in any spec text -- they must NOT be flagged.
    ok, report, _ = df_author.validate_authored(
        [_run_raw(), _run_raw("BHV-002"), _prop_raw()], SPEC, BEHAVIORS)
    assert ok
    assert report["spec_leak_values"] == []


def test_critic_prompt_renders_property_and_names_fuzz_duty():
    ok, _, normalized = df_author.validate_authored(
        [_run_raw(), _run_raw("BHV-002"), _prop_raw()], SPEC, BEHAVIORS)
    assert ok
    prompt = df_critic.compose_critic_prompt(SPEC, BEHAVIORS, normalized)
    assert "property:" in prompt
    assert '"seed": 5' in prompt          # the critic sees the generative spec
    assert "invariant" in prompt
    # The rules tell the critic a missing robustness property is missing_case.
    assert "no fuzz/robustness property" in prompt


def test_missing_case_kind_covers_fuzz_findings():
    # The critic's missing-robustness finding rides the EXISTING fixed kind.
    blocking, _ = df_critic.validate_critic_verdict(
        {"blocking": [{"behavior_id": "BHV-002", "kind": "missing_case",
                       "detail": "no fuzz/robustness property for BHV-002"}],
         "advisories": []},
        {"BHV-001", "BHV-002"})
    assert blocking and blocking[0]["kind"] == "missing_case"
