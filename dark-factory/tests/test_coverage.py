import json
import os

import pytest

import df_gates


# --- load_behaviors -------------------------------------------------------


def _write(tmp_path, name, content):
    path = tmp_path / name
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_text(json.dumps(content), encoding="utf-8")
    return path


def test_load_behaviors_valid_file_returns_list(tmp_path):
    _write(
        tmp_path,
        "behaviors.json",
        {
            "behaviors": [
                {"id": "BHV-001", "description": "does a thing"},
                {"id": "BHV-002"},
            ]
        },
    )
    result = df_gates.load_behaviors(str(tmp_path))
    assert result == [
        {"id": "BHV-001", "description": "does a thing"},
        {"id": "BHV-002"},
    ]


def test_load_behaviors_absent_file_returns_none(tmp_path):
    assert df_gates.load_behaviors(str(tmp_path)) is None


def test_load_behaviors_malformed_json_raises_gate_error(tmp_path):
    _write(tmp_path, "behaviors.json", "{not valid json")
    with pytest.raises(df_gates.GateError):
        df_gates.load_behaviors(str(tmp_path))


def test_load_behaviors_not_a_dict_raises_gate_error(tmp_path):
    _write(tmp_path, "behaviors.json", [{"id": "BHV-001"}])
    with pytest.raises(df_gates.GateError):
        df_gates.load_behaviors(str(tmp_path))


def test_load_behaviors_missing_behaviors_key_raises_gate_error(tmp_path):
    _write(tmp_path, "behaviors.json", {"not_behaviors": []})
    with pytest.raises(df_gates.GateError):
        df_gates.load_behaviors(str(tmp_path))


def test_load_behaviors_behaviors_not_a_list_raises_gate_error(tmp_path):
    _write(tmp_path, "behaviors.json", {"behaviors": {"id": "BHV-001"}})
    with pytest.raises(df_gates.GateError):
        df_gates.load_behaviors(str(tmp_path))


def test_load_behaviors_bad_id_raises_gate_error(tmp_path):
    _write(tmp_path, "behaviors.json", {"behaviors": [{"id": "bhv-1"}]})
    with pytest.raises(df_gates.GateError):
        df_gates.load_behaviors(str(tmp_path))


def test_load_behaviors_duplicate_id_raises_gate_error(tmp_path):
    _write(
        tmp_path,
        "behaviors.json",
        {"behaviors": [{"id": "BHV-001"}, {"id": "BHV-001"}]},
    )
    with pytest.raises(df_gates.GateError):
        df_gates.load_behaviors(str(tmp_path))


def test_load_behaviors_description_optional(tmp_path):
    _write(tmp_path, "behaviors.json", {"behaviors": [{"id": "BHV-001"}]})
    result = df_gates.load_behaviors(str(tmp_path))
    assert result == [{"id": "BHV-001"}]


def test_load_behaviors_entry_not_a_dict_raises_gate_error(tmp_path):
    _write(tmp_path, "behaviors.json", {"behaviors": ["BHV-001"]})
    with pytest.raises(df_gates.GateError):
        df_gates.load_behaviors(str(tmp_path))


# --- check_coverage ---------------------------------------------------


def test_check_coverage_full_coverage_passes():
    behaviors = [{"id": "BHV-001"}, {"id": "BHV-002"}]
    scenarios = [
        {"id": "BHV-001-S1", "behavior_id": "BHV-001", "cohort": "dev"},
        {"id": "BHV-001-S2", "behavior_id": "BHV-001", "cohort": "final"},
        {"id": "BHV-002-S1", "behavior_id": "BHV-002", "cohort": "dev"},
    ]
    result = df_gates.check_coverage(behaviors, scenarios)
    assert result["checked"] is True
    assert result["behaviors"] == ["BHV-001", "BHV-002"]
    assert result["uncovered_dev"] == []
    assert result["orphan_scenarios"] == []
    assert result["final_covered"] == ["BHV-001"]


def test_check_coverage_final_only_behavior_is_uncovered_dev_and_final_covered():
    behaviors = [{"id": "BHV-001"}, {"id": "BHV-002"}]
    scenarios = [
        {"id": "BHV-001-S1", "behavior_id": "BHV-001", "cohort": "dev"},
        {"id": "BHV-002-S1", "behavior_id": "BHV-002", "cohort": "final"},
    ]
    result = df_gates.check_coverage(behaviors, scenarios)
    assert result["uncovered_dev"] == ["BHV-002"]
    assert result["final_covered"] == ["BHV-002"]
    assert result["orphan_scenarios"] == []


def test_check_coverage_orphan_scenario_undeclared_behavior_id():
    behaviors = [{"id": "BHV-001"}]
    scenarios = [
        {"id": "BHV-001-S1", "behavior_id": "BHV-001", "cohort": "dev"},
        {"id": "BHV-999-S1", "behavior_id": "BHV-999", "cohort": "dev"},
    ]
    result = df_gates.check_coverage(behaviors, scenarios)
    assert result["orphan_scenarios"] == ["BHV-999-S1"]
    assert result["uncovered_dev"] == []


def test_check_coverage_behavior_with_no_scenarios_at_all_is_uncovered_dev():
    behaviors = [{"id": "BHV-001"}, {"id": "BHV-002"}]
    scenarios = [
        {"id": "BHV-001-S1", "behavior_id": "BHV-001", "cohort": "dev"},
    ]
    result = df_gates.check_coverage(behaviors, scenarios)
    assert result["uncovered_dev"] == ["BHV-002"]
    assert result["final_covered"] == []


def test_check_coverage_final_covered_lists_all_behaviors_with_final_scenario():
    behaviors = [{"id": "BHV-001"}, {"id": "BHV-002"}, {"id": "BHV-003"}]
    scenarios = [
        {"id": "BHV-001-S1", "behavior_id": "BHV-001", "cohort": "dev"},
        {"id": "BHV-001-S2", "behavior_id": "BHV-001", "cohort": "final"},
        {"id": "BHV-002-S1", "behavior_id": "BHV-002", "cohort": "final"},
        {"id": "BHV-003-S1", "behavior_id": "BHV-003", "cohort": "dev"},
    ]
    result = df_gates.check_coverage(behaviors, scenarios)
    assert result["final_covered"] == ["BHV-001", "BHV-002"]
    assert result["uncovered_dev"] == ["BHV-002"]
