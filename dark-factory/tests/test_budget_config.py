import json

import pytest

import df_config
from test_config import write_config


def _no_budget_config(control_root):
    """Write a config with no 'budget' key at all (absent block)."""
    cfg = write_config(control_root)
    cfg.pop("budget", None)
    (control_root / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cfg


def test_absent_budget_block_gets_defaults(tmp_path):
    cr = tmp_path / "control"
    _no_budget_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"] == {
        "billing": "subscription",
        "max_usd": None,
        "per_call_usd": None,
        "max_calls": None,
        "alert_at": 0.85,
        "notification_sink": "",
        "notification_durable": False,
        "notification_attempts": 3,
        "token_pricing": {},
    }


def test_valid_api_budget_with_estimate_injected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        budget={
            "billing": "api",
            "max_usd": 5.0,
            "per_call_usd": 0.5,
            "max_calls": 10,
            "alert_at": 0.9,
            "notification_sink": "https://ops.example.com/hook",
        },
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"] == {
        "billing": "api",
        "max_usd": 5.0,
        "per_call_usd": 0.5,
        "max_calls": 10,
        "alert_at": 0.9,
        "notification_sink": "https://ops.example.com/hook",
        "notification_durable": False,
        "notification_attempts": 3,
        "token_pricing": {},
    }


def test_api_max_usd_without_per_call_usd_is_allowed(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "api", "max_usd": 5.0})
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["billing"] == "api"
    assert cfg["_budget"]["max_usd"] == 5.0
    assert cfg["_budget"]["per_call_usd"] is None


def test_bad_billing_value_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "free"})
    with pytest.raises(df_config.ConfigError, match="billing"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("bad", [0, -1.0, "5"])
def test_max_usd_must_be_positive_number(tmp_path, bad):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "api", "max_usd": bad})
    with pytest.raises(df_config.ConfigError, match="max_usd"):
        df_config.load_config(str(cr))


def test_per_call_usd_zero_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "api", "per_call_usd": 0})
    with pytest.raises(df_config.ConfigError, match="per_call_usd"):
        df_config.load_config(str(cr))


def test_max_calls_zero_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"max_calls": 0})
    with pytest.raises(df_config.ConfigError, match="max_calls"):
        df_config.load_config(str(cr))


def test_max_calls_bool_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"max_calls": True})
    with pytest.raises(df_config.ConfigError, match="max_calls"):
        df_config.load_config(str(cr))


def test_alert_at_zero_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"alert_at": 0})
    with pytest.raises(df_config.ConfigError, match="alert_at"):
        df_config.load_config(str(cr))


def test_alert_at_above_one_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"alert_at": 1.5})
    with pytest.raises(df_config.ConfigError, match="alert_at"):
        df_config.load_config(str(cr))


def test_alert_at_one_is_ok(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"alert_at": 1.0})
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["alert_at"] == 1.0


def test_notification_sink_must_be_str(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"notification_sink": 123})
    with pytest.raises(df_config.ConfigError, match="notification_sink"):
        df_config.load_config(str(cr))


def test_non_dict_budget_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget="subscription")
    with pytest.raises(df_config.ConfigError, match="budget"):
        df_config.load_config(str(cr))
