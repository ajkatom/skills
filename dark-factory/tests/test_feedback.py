import json

import pytest

import id_feedback

MARKER = "HOLDOUT-MARKER-93e1"


def make_report():
    return {
        "report_version": "0.1",
        "all_pass": False,
        "results": [
            {
                "id": "BHV-001-S1",
                "behavior_id": "BHV-001",
                "pass": False,
                "taxonomy": "wrong_output",
                "observed": {"exit_code": 0, "stdout": f"secret {MARKER}", "stderr": ""},
            },
            {
                "id": "BHV-001-S2",
                "behavior_id": "BHV-001",
                "pass": False,
                "taxonomy": "wrong_exit_code",
                "observed": {"exit_code": 3, "stdout": MARKER, "stderr": MARKER},
            },
            {
                "id": "BHV-002-S1",
                "behavior_id": "BHV-002",
                "pass": True,
                "taxonomy": None,
                "observed": {"exit_code": 2, "stdout": "", "stderr": f"usage {MARKER}"},
            },
        ],
    }


def test_projection_contains_only_ids_and_taxonomy():
    fb = id_feedback.project_feedback(make_report())
    assert fb == {
        "feedback_version": "0.1",
        "channel": "ids",
        "total": 3,
        "failing_count": 2,
        "failures": [
            {"behavior_id": "BHV-001", "taxonomy": ["wrong_exit_code", "wrong_output"]}
        ],
    }


def test_projection_never_leaks_observed_or_scenario_text():
    fb = id_feedback.project_feedback(make_report())
    assert MARKER not in json.dumps(fb)


def test_all_pass_produces_empty_failures():
    rep = make_report()
    for r in rep["results"]:
        r["pass"], r["taxonomy"] = True, None
    rep["all_pass"] = True
    fb = id_feedback.project_feedback(rep)
    assert fb["failing_count"] == 0 and fb["failures"] == []


def test_validate_rejects_extra_keys():
    fb = id_feedback.project_feedback(make_report())
    fb["hint"] = "the expected output is Hello"
    with pytest.raises(id_feedback.FeedbackLeakError):
        id_feedback.validate_feedback(fb)


def test_validate_rejects_bad_behavior_id():
    fb = id_feedback.project_feedback(make_report())
    fb["failures"][0]["behavior_id"] = "BHV-001 (expects Hello, World!)"
    with pytest.raises(id_feedback.FeedbackLeakError):
        id_feedback.validate_feedback(fb)


def test_validate_rejects_unknown_taxonomy():
    fb = id_feedback.project_feedback(make_report())
    fb["failures"][0]["taxonomy"] = ["expected 'Hello, World!'"]
    with pytest.raises(id_feedback.FeedbackLeakError):
        id_feedback.validate_feedback(fb)


def test_leak_error_messages_never_embed_offending_values():
    fb = id_feedback.project_feedback(make_report())
    fb["failures"][0]["behavior_id"] = f"BHV-001 {MARKER}"
    with pytest.raises(id_feedback.FeedbackLeakError) as ei:
        id_feedback.validate_feedback(fb)
    assert MARKER not in str(ei.value)
    fb = id_feedback.project_feedback(make_report())
    fb["failures"][0]["taxonomy"] = [f"secret {MARKER}"]
    with pytest.raises(id_feedback.FeedbackLeakError) as ei:
        id_feedback.validate_feedback(fb)
    assert MARKER not in str(ei.value)
