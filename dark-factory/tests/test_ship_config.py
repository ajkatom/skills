"""M41 Task 1/6: `ship` config block validation. Absent -> None (byte-identical
today); each action shape; irreversible-without-approval -> ConfigError; approval
forces audit.signing; irreversible requires hardened+; creds-value rejection."""
import json
import sys

import pytest

import df_config

_ROLES_HARDENED = {"builder": {"adapter": sys.executable, "timeout_s": 60}}
_PUB = "ab" * 32  # 64-hex, shape-valid ed25519 pubkey


def write_config(control_root, **overrides):
    cfg = {
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": 5,
        "workspace_root": str(control_root.parent / "ws"),
        "roles": {"builder": {"adapter": "/bin/true", "timeout_s": 60}},
        "budget": {"billing": "subscription"},
    }
    cfg.update(overrides)
    control_root.mkdir(parents=True, exist_ok=True)
    (control_root / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cfg


def _hardened_extra(tmp_path):
    """Hardened tier forces audit.signing — point the key outside CR + ws."""
    return {"assurance": "hardened", "roles": _ROLES_HARDENED,
            "audit": {"key_path": str(tmp_path / "keys" / "audit.key")}}


def _rev(name="merge"):
    return {"name": name, "run": ["git", "push"], "reversible": True, "timeout_s": 60}


def _irr(name="deploy"):
    return {"name": name, "run": ["./deploy.sh"], "reversible": False,
            "rollback": ["./deploy.sh", "--rollback"], "timeout_s": 300}


def test_absent_ship_is_none(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    assert df_config.load_config(str(cr))["_ship"] is None


def test_reversible_only_loads_at_any_tier(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, ship={"actions": [_rev()]})
    cfg = df_config.load_config(str(cr))
    assert cfg["_ship"]["actions"][0]["name"] == "merge"
    assert cfg["_ship"]["approval"] == {"approvers": [], "threshold": 0}


def test_empty_actions_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, ship={"actions": []})
    with pytest.raises(df_config.ConfigError, match="ship.actions must be a non-empty list"):
        df_config.load_config(str(cr))


def test_duplicate_action_name_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, ship={"actions": [_rev("x"), _rev("x")]})
    with pytest.raises(df_config.ConfigError, match="duplicate name"):
        df_config.load_config(str(cr))


def test_reversible_is_required_no_default(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, ship={"actions": [{"name": "x", "run": ["a"], "timeout_s": 10}]})
    with pytest.raises(df_config.ConfigError, match="reversible is REQUIRED"):
        df_config.load_config(str(cr))


def test_run_must_be_nonempty_list_of_str(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, ship={"actions": [{"name": "x", "run": [], "reversible": True,
                                        "timeout_s": 10}]})
    with pytest.raises(df_config.ConfigError, match="run must be a non-empty list"):
        df_config.load_config(str(cr))


def test_timeout_bounds(tmp_path):
    cr = tmp_path / "control"
    for bad in (0, 3601, "10", True):
        write_config(cr, ship={"actions": [{"name": "x", "run": ["a"], "reversible": True,
                                            "timeout_s": bad}]})
        with pytest.raises(df_config.ConfigError, match="timeout_s"):
            df_config.load_config(str(cr))


def test_cwd_path_safety(tmp_path):
    cr = tmp_path / "control"
    for bad in ("/abs", "../escape", "a/../../b", "~/home"):
        write_config(cr, ship={"actions": [{"name": "x", "run": ["a"], "reversible": True,
                                            "timeout_s": 10, "cwd": bad}]})
        with pytest.raises(df_config.ConfigError, match="cwd"):
            df_config.load_config(str(cr))
    write_config(cr, ship={"actions": [{"name": "x", "run": ["a"], "reversible": True,
                                        "timeout_s": 10, "cwd": "sub/dir"}]})
    assert df_config.load_config(str(cr))["_ship"]["actions"][0]["cwd"] == "sub/dir"


def test_creds_inline_value_rejected(tmp_path):
    cr = tmp_path / "control"
    for banned in ("value", "token", "secret", "password"):
        write_config(cr, ship={"actions": [{"name": "x", "run": ["a"], "reversible": True,
                                            "timeout_s": 10, "creds": {banned: "s3cr3t"}}]})
        with pytest.raises(df_config.ConfigError, match="raw secret value"):
            df_config.load_config(str(cr))


def test_creds_env_must_be_names(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, ship={"actions": [{"name": "x", "run": ["a"], "reversible": True,
                                        "timeout_s": 10, "creds": {"env": ["not-a-name!"]}}]})
    with pytest.raises(df_config.ConfigError, match="env-var NAMES"):
        df_config.load_config(str(cr))
    write_config(cr, ship={"actions": [{"name": "x", "run": ["a"], "reversible": True,
                                        "timeout_s": 10, "creds": {"env": ["PROD_DEPLOY_TOKEN"]}}]})
    cfg = df_config.load_config(str(cr))
    assert cfg["_ship"]["actions"][0]["creds"]["env"] == ["PROD_DEPLOY_TOKEN"]


def test_irreversible_requires_approval_policy(tmp_path):
    cr = tmp_path / "control"
    # hardened tier but NO approval policy -> refused (unshippable dead end)
    write_config(cr, ship={"actions": [_irr()]}, **_hardened_extra(tmp_path))
    with pytest.raises(df_config.ConfigError, match="requires a ship.approval policy"):
        df_config.load_config(str(cr))


def test_irreversible_requires_hardened_tier(tmp_path):
    cr = tmp_path / "control"
    # standard tier + approval policy present, still refused: irreversible needs hardened+
    write_config(cr, assurance="standard",
                 audit={"key_path": str(tmp_path / "keys" / "audit.key")},
                 roles=_ROLES_HARDENED,
                 ship={"actions": [_irr()], "approval": {"approvers": [_PUB], "threshold": 1}})
    with pytest.raises(df_config.ConfigError, match="requires assurance: hardened"):
        df_config.load_config(str(cr))


def test_irreversible_full_policy_loads_and_forces_signing(tmp_path):
    cr = tmp_path / "control"
    extra = _hardened_extra(tmp_path)
    write_config(cr, ship={"actions": [_rev(), _irr()],
                           "approval": {"approvers": [_PUB], "threshold": 1}}, **extra)
    cfg = df_config.load_config(str(cr))
    assert cfg["_ship"]["approval"] == {"approvers": [_PUB.lower()], "threshold": 1}
    assert cfg["_audit"]["signing"] is True  # forced on by the approval policy


def test_approval_policy_with_explicit_unsigned_audit_rejected(tmp_path):
    cr = tmp_path / "control"
    # A reversible-only ship with an approval policy but audit.signing:false -> refused
    write_config(cr, assurance="standard", roles=_ROLES_HARDENED,
                 audit={"signing": False},
                 ship={"actions": [_rev()], "approval": {"approvers": [_PUB], "threshold": 1}})
    with pytest.raises(df_config.ConfigError, match="ship.approval requires audit.signing"):
        df_config.load_config(str(cr))


def test_approval_threshold_bounds(tmp_path):
    cr = tmp_path / "control"
    extra = _hardened_extra(tmp_path)
    write_config(cr, ship={"actions": [_irr()],
                           "approval": {"approvers": [_PUB], "threshold": 2}}, **extra)
    with pytest.raises(df_config.ConfigError, match="ship.approval.threshold must be an int in 1"):
        df_config.load_config(str(cr))
