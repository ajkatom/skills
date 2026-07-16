import pytest

import df_config
from test_config import write_config


def test_absent_audit_defaults_off(tmp_path):
    cr = tmp_path / "control"; write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"] == {
        "signing": False,
        "key_path": "",
        "sink": {"kind": "none", "required": False},
    }


def test_signing_true_defaults_key_path_outside(tmp_path):
    cr = tmp_path / "control"; write_config(cr, audit={"signing": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["signing"] is True
    assert cfg["_audit"]["key_path"].endswith("audit.key")


def test_signing_key_inside_control_root_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, audit={"signing": True, "key_path": str(cr / "k.key")})
    with pytest.raises(df_config.ConfigError, match="key"):
        df_config.load_config(str(cr))


def test_signing_must_be_bool(tmp_path):
    cr = tmp_path / "control"; write_config(cr, audit={"signing": "yes"})
    with pytest.raises(df_config.ConfigError, match="signing"):
        df_config.load_config(str(cr))
