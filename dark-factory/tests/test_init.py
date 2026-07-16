import copy
import json

import pytest

import df_config
import df_gates
import df_init


def _kv_answers(tmp_path, **overrides):
    """A complete answers dict for a small KV JSON HTTP API -- 5 behaviors,
    dev + final cohort scenarios, reused across the scaffold/validate tests.
    The `run` argv are never executed by these tests (build_scenarios and
    validate_scaffold only inspect scenario shape/discrimination, they don't
    run anything), so plain non-empty argv lists are enough."""
    answers = {
        "app_name": "kv-service",
        "spec_text": (
            "# KV JSON HTTP API\n\n"
            "A small HTTP service exposing a key-value store.\n\n"
            "- PUT /kv/<key> with a JSON body stores the value.\n"
            "- GET /kv/<key> returns the stored value, or 404 if absent.\n"
            "- DELETE /kv/<key> removes a key.\n"
            "- GET /kv lists all stored keys.\n"
        ),
        "assurance": "cooperative",
        "workspace_root": str(tmp_path / "workspace"),
        "control_root": str(tmp_path / "control"),
        "builder_adapter": "/bin/true",
        "behaviors": [
            {
                "id": "BHV-PUT",
                "description": "PUT /kv/<key> stores a value and returns 201",
                "scenarios": [
                    {
                        "cohort": "dev",
                        "title": "put a new key returns 201",
                        "run": ["python3", "-c", "print('status 201')"],
                        "then": {"exit_code": 0, "stdout_contains": "status 201"},
                    },
                ],
            },
            {
                "id": "BHV-GET",
                "description": "GET /kv/<key> returns the stored value",
                "scenarios": [
                    {
                        "cohort": "dev",
                        "title": "get an existing key returns its value",
                        "run": ["python3", "-c", "print('value: indigo')"],
                        "then": {"exit_code": 0, "stdout_contains": "value: indigo"},
                    },
                    {
                        "cohort": "final",
                        "title": "get an existing key returns its value (sealed)",
                        "run": ["python3", "-c", "print('value: indigo')"],
                        "then": {"exit_code": 0, "stdout_contains": "value: indigo"},
                    },
                ],
            },
            {
                "id": "BHV-404",
                "description": "GET of a missing key returns 404",
                "scenarios": [
                    {
                        "cohort": "dev",
                        "title": "get a missing key returns 404",
                        "run": ["python3", "-c", "print('status 404')"],
                        "then": {"exit_code": 0, "stdout_contains": "status 404"},
                    },
                ],
            },
            {
                "id": "BHV-DELETE",
                "description": "DELETE /kv/<key> removes a key and returns 204",
                "scenarios": [
                    {
                        "cohort": "dev",
                        "title": "delete an existing key returns 204",
                        "run": ["python3", "-c", "print('status 204')"],
                        "then": {"exit_code": 0, "stdout_contains": "status 204"},
                    },
                ],
            },
            {
                "id": "BHV-LIST",
                "description": "GET /kv lists all stored keys",
                "scenarios": [
                    {
                        "cohort": "dev",
                        "title": "list returns the stored keys",
                        "run": ["python3", "-c", "print('keys: [a, b]')"],
                        "then": {"exit_code": 0, "stdout_contains": "keys: [a, b]"},
                    },
                    {
                        "cohort": "final",
                        "title": "list returns the stored keys (sealed)",
                        "run": ["python3", "-c", "print('keys: [a, b]')"],
                        "then": {"exit_code": 0, "stdout_contains": "keys: [a, b]"},
                    },
                ],
            },
        ],
    }
    answers.update(overrides)
    return answers


# --- build_config ----------------------------------------------------------


def test_build_config_valid_answers_is_accepted_by_load_config(tmp_path):
    answers = _kv_answers(tmp_path)
    cfg = df_init.build_config(answers)

    cr = tmp_path / "control"
    cr.mkdir()
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    loaded = df_config.load_config(str(cr))
    assert loaded["assurance"] == "cooperative"
    assert loaded["autonomy"] == 4
    assert loaded["max_iterations"] == 8


def test_build_config_autonomy_5_with_cooperative_is_init_error(tmp_path):
    answers = _kv_answers(tmp_path, autonomy=5)
    with pytest.raises(df_init.InitError):
        df_init.build_config(answers)


def test_build_config_autonomy_5_with_hardened_is_allowed(tmp_path):
    answers = _kv_answers(tmp_path, autonomy=5, assurance="hardened")
    cfg = df_init.build_config(answers)
    assert cfg["autonomy"] == 5
    assert cfg["assurance"] == "hardened"


def test_build_config_workspace_not_disjoint_is_init_error(tmp_path):
    cr = str(tmp_path / "control")
    answers = _kv_answers(tmp_path, control_root=cr, workspace_root=str(tmp_path / "control" / "ws"))
    with pytest.raises(df_init.InitError, match="disjoint"):
        df_init.build_config(answers)


def test_build_config_unsupported_assurance_is_init_error(tmp_path):
    answers = _kv_answers(tmp_path, assurance="quantum-teleport")
    with pytest.raises(df_init.InitError):
        df_init.build_config(answers)


def test_build_config_max_iterations_out_of_range_is_init_error(tmp_path):
    answers = _kv_answers(tmp_path, max_iterations=99)
    with pytest.raises(df_init.InitError, match="max_iterations"):
        df_init.build_config(answers)


def test_build_config_missing_builder_adapter_is_init_error(tmp_path):
    answers = _kv_answers(tmp_path, builder_adapter="")
    with pytest.raises(df_init.InitError, match="builder_adapter"):
        df_init.build_config(answers)


# --- build_behaviors ---------------------------------------------------------


def test_build_behaviors_from_answers(tmp_path):
    answers = _kv_answers(tmp_path)
    behaviors = df_init.build_behaviors(answers)
    ids = {b["id"] for b in behaviors["behaviors"]}
    assert ids == {"BHV-PUT", "BHV-GET", "BHV-404", "BHV-DELETE", "BHV-LIST"}


# --- build_scenarios ---------------------------------------------------------


def test_build_scenarios_inert_then_is_init_error_naming_behavior(tmp_path):
    answers = _kv_answers(tmp_path)
    answers["behaviors"][0]["scenarios"][0]["then"] = {"stdout_contains": ""}
    with pytest.raises(df_init.InitError, match="BHV-PUT"):
        df_init.build_scenarios(answers)


def test_build_scenarios_good_thens_are_discriminating(tmp_path):
    answers = _kv_answers(tmp_path)
    scenarios = df_init.build_scenarios(answers)
    assert len(scenarios) == 7  # 5 behaviors, 2 with an extra final scenario
    for sc in scenarios:
        assert df_gates.is_discriminating(sc["then"])
    ids = [sc["id"] for sc in scenarios]
    assert "BHV-PUT-S1" in ids
    assert "BHV-GET-S1" in ids
    assert "BHV-GET-F1" in ids


def test_build_scenarios_behavior_missing_dev_scenario_is_init_error(tmp_path):
    answers = _kv_answers(tmp_path)
    # BHV-GET has both a dev and a final scenario; strip the dev one so the
    # behavior has zero dev-cohort coverage.
    answers["behaviors"][1]["scenarios"] = [
        s for s in answers["behaviors"][1]["scenarios"] if s["cohort"] != "dev"
    ]
    with pytest.raises(df_init.InitError, match="BHV-GET"):
        df_init.build_scenarios(answers)


# --- scaffold + validate_scaffold -------------------------------------------


def test_scaffold_then_validate_scaffold_is_ok_with_empty_report(tmp_path):
    answers = _kv_answers(tmp_path)
    control_root = answers["control_root"]

    df_init.scaffold(control_root, answers)
    ok, report = df_init.validate_scaffold(control_root)

    assert ok is True
    assert report["config_ok"] is True
    assert report["inert"] == []
    assert report["coverage"]["uncovered_dev"] == []
    assert report["coverage"]["orphan_scenarios"] == []
    assert report["spec_leak"] == []


def test_scaffold_writes_barrier_safe_spec_with_no_scenario_content(tmp_path):
    answers = _kv_answers(tmp_path)
    control_root = answers["control_root"]
    df_init.scaffold(control_root, answers)

    with open(f"{control_root}/spec.md", encoding="utf-8") as f:
        spec = f.read()
    # None of the concrete expected outputs from the scenarios appear in the
    # builder-visible spec.
    for needle in ("status 201", "value: indigo", "status 404", "status 204", "keys: [a, b]"):
        assert needle not in spec


def test_spec_leak_of_scenario_expected_output_fails_validation(tmp_path):
    answers = _kv_answers(tmp_path)
    # Leak BHV-GET's exact expected stdout into the builder-visible spec.
    answers["spec_text"] += "\nNote: GET of an existing key prints `value: indigo`.\n"
    control_root = answers["control_root"]

    df_init.scaffold(control_root, answers)
    ok, report = df_init.validate_scaffold(control_root)

    assert ok is False
    assert report["spec_leak"] != []
    assert any(leak["value"] == "value: indigo" for leak in report["spec_leak"])


def test_scaffold_refuses_to_overwrite_non_empty_dir_without_force(tmp_path):
    answers = _kv_answers(tmp_path)
    control_root = answers["control_root"]
    import os
    os.makedirs(control_root, exist_ok=True)
    with open(f"{control_root}/leftover.txt", "w", encoding="utf-8") as f:
        f.write("pre-existing content")

    with pytest.raises(df_init.InitError, match="not empty"):
        df_init.scaffold(control_root, answers)

    # Untouched: the leftover file must still be there.
    assert os.path.exists(f"{control_root}/leftover.txt")

    # With force=True it proceeds.
    forced = copy.deepcopy(answers)
    forced["force"] = True
    df_init.scaffold(control_root, forced)
    assert os.path.exists(f"{control_root}/config.json")


def test_scaffold_is_disjoint_workspace_from_control_root(tmp_path):
    answers = _kv_answers(tmp_path)
    assert answers["workspace_root"] != answers["control_root"]
    assert not answers["workspace_root"].startswith(answers["control_root"])
    assert not answers["control_root"].startswith(answers["workspace_root"])
