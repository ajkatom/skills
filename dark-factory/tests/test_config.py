import json

import pytest

import df_config


def write_config(control_root, **overrides):
    cfg = {
        "config_version": "0.1",
        "autonomy": 4,
        "assurance": "cooperative",
        "feedback": "ids",
        "max_iterations": 5,
        "workspace_root": str(control_root.parent / "ws"),
        "roles": {"builder": {"adapter": "/bin/true", "timeout_s": 60}},
        "budget": {"billing": "subscription"},
    }
    cfg.update(overrides)
    control_root.mkdir(parents=True, exist_ok=True)
    (control_root / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cfg


def test_valid_cooperative_config_loads_and_is_unqualified(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["assurance"] == "cooperative"
    assert cfg["_qualified"] is False
    assert len(cfg["_config_sha256"]) == 64


def test_unbacked_tier_is_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="hardened")
    with pytest.raises(df_config.ConfigError, match="no conforming backend"):
        df_config.load_config(str(cr))


def test_non_ids_feedback_is_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, feedback="behavioral")
    with pytest.raises(df_config.ConfigError, match="feedback"):
        df_config.load_config(str(cr))


def test_max_iterations_bounds(tmp_path):
    cr = tmp_path / "control"
    for bad in (0, 21, "5", None):
        write_config(cr, max_iterations=bad)
        with pytest.raises(df_config.ConfigError, match="max_iterations"):
            df_config.load_config(str(cr))


def test_workspace_inside_control_root_is_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, workspace_root=str(cr / "ws"))
    with pytest.raises(df_config.ConfigError, match="disjoint"):
        df_config.load_config(str(cr))


def test_control_root_inside_workspace_is_rejected(tmp_path):
    cr = tmp_path / "ws" / "control"
    write_config(cr, workspace_root=str(tmp_path / "ws"))
    with pytest.raises(df_config.ConfigError, match="disjoint"):
        df_config.load_config(str(cr))


def test_missing_builder_adapter_is_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles={"builder": {}})
    with pytest.raises(df_config.ConfigError, match="adapter"):
        df_config.load_config(str(cr))


def test_missing_config_file_is_clear(tmp_path):
    with pytest.raises(df_config.ConfigError, match="missing config"):
        df_config.load_config(str(tmp_path / "nowhere"))


def test_malformed_json_raises_config_error(tmp_path):
    cr = tmp_path / "control"
    cr.mkdir(parents=True, exist_ok=True)
    (cr / "config.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(df_config.ConfigError, match="invalid JSON"):
        df_config.load_config(str(cr))


def test_non_object_config_raises_config_error(tmp_path):
    cr = tmp_path / "control"
    cr.mkdir(parents=True, exist_ok=True)
    (cr / "config.json").write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(df_config.ConfigError, match="must be a JSON object"):
        df_config.load_config(str(cr))


def test_non_dict_roles_builder_raises_config_error(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles={"builder": "oops"})
    with pytest.raises(df_config.ConfigError, match="roles.builder"):
        df_config.load_config(str(cr))


def test_checkpoint_defaults_to_pause_at_autonomy_4(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, autonomy=4)  # no explicit checkpoint
    cfg = df_config.load_config(str(cr))
    assert cfg["_checkpoint"] == "pause"


def test_checkpoint_defaults_to_auto_at_autonomy_5(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, autonomy=5)
    cfg = df_config.load_config(str(cr))
    assert cfg["_checkpoint"] == "auto"


def test_explicit_checkpoint_overrides_default(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, autonomy=4, checkpoint="auto")
    cfg = df_config.load_config(str(cr))
    assert cfg["_checkpoint"] == "auto"


def test_invalid_checkpoint_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, checkpoint="sometimes")
    with pytest.raises(df_config.ConfigError, match="checkpoint"):
        df_config.load_config(str(cr))


def test_standard_tier_loads_and_is_qualified(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard")
    cfg = df_config.load_config(str(cr))
    assert cfg["assurance"] == "standard"
    assert cfg["_qualified"] is True


def test_hardened_tier_still_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="hardened")
    with pytest.raises(df_config.ConfigError, match="no conforming backend"):
        df_config.load_config(str(cr))
