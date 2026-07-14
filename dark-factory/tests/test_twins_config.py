import json

import pytest

import df_config
from test_config import write_config


def _twindir(cr, n=1):
    d = cr / "twins"; d.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (d / f"t{i}.json").write_text("{}", encoding="utf-8")


def test_absent_twins_defaults_disabled(tmp_path):
    cr = tmp_path / "control"; write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_twins"] == {"enabled": False, "startup_timeout_s": 20}


def test_enabled_requires_twin_defs(tmp_path):
    cr = tmp_path / "control"; write_config(cr, twins={"enabled": True})
    with pytest.raises(df_config.ConfigError, match="twins"):
        df_config.load_config(str(cr))


def test_enabled_with_defs_ok(tmp_path):
    cr = tmp_path / "control"; write_config(cr, twins={"enabled": True, "startup_timeout_s": 30})
    _twindir(cr, 2)
    cfg = df_config.load_config(str(cr))
    assert cfg["_twins"] == {"enabled": True, "startup_timeout_s": 30}


def test_startup_timeout_bounds(tmp_path):
    cr = tmp_path / "control"; _twindir(cr)
    for bad in (0, 121, "5", True):
        write_config(cr, twins={"enabled": True, "startup_timeout_s": bad})
        with pytest.raises(df_config.ConfigError, match="startup_timeout_s"):
            df_config.load_config(str(cr))


def test_enabled_must_be_bool(tmp_path):
    cr = tmp_path / "control"; _twindir(cr)
    write_config(cr, twins={"enabled": "yes"})
    with pytest.raises(df_config.ConfigError, match="enabled"):
        df_config.load_config(str(cr))
