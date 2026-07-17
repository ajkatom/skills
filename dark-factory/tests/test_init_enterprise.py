"""DF-04 (audit finding, High): assurance: "enterprise" `df_init` scaffolding.

Before this fix, `build_config` passed enterprise answers through as a
bare `{"assurance": "enterprise", ...}` config with none of the blocks
`df_config.load_config` REQUIRES at that tier (custody, credential_proxy,
audit.sink.required, builder_confinement.required, audit.signing) -- a
freshly `init`'d enterprise control root immediately failed `load_config`,
so a user following the documented enterprise init flow could never reach
a runnable scaffold.

Two explicit outcomes, never a broken middle:
  - every operator-only enterprise input is present in `answers` (approver
    PUBLIC keys, custody_threshold, credential_proxy, audit_sink) ->
    `build_config` generates + preflight-validates the full mandatory
    enterprise config, and a `scaffold` + `df_config.load_config` round
    trip SUCCEEDS (the core acceptance test below);
  - any of those inputs is missing -> InitError naming exactly which keys
    are missing (fail closed), UNLESS `answers.allow_dev_downgrade` is set,
    in which case the scaffold is emitted at assurance: "hardened" instead,
    with a note -- explicitly NOT enterprise-shaped-but-broken.

Reuses `_kv_answers` from test_init.py for the behaviors/scenarios half of
`answers` (irrelevant to df_config's tier composition, needed only so
`scaffold`/`validate_scaffold` round-trip tests have a complete document).
"""
import json
import os
import sys

import pytest

import df_config
import df_custody
import df_init
from test_init import _kv_answers


def _approver_pubkey():
    _priv, pub = df_custody.generate_keypair()
    return pub


def _enterprise_answers(tmp_path, **overrides):
    pubkeys = [_approver_pubkey() for _ in range(3)]
    answers = _kv_answers(
        tmp_path,
        assurance="enterprise",
        # hardened/enterprise require an absolute, EXISTING adapter path
        # (its directory is bind-mounted ro into the builder container) --
        # sys.executable always satisfies that, unlike the base fixture's
        # "/bin/true" placeholder.
        builder_adapter=sys.executable,
        approver_pubkeys=pubkeys,
        custody_threshold=2,
        credential_proxy={
            "token_env": "DF_TEST_ENTERPRISE_TOKEN",
            "allowlist": ["api.example.test"],
        },
        audit_sink={"kind": "http-append", "url": "https://sink.example.test/audit"},
    )
    answers.update(overrides)
    return answers


# --- the core DF-04 acceptance test: round-trip through load_config --------


def test_build_config_enterprise_http_sink_round_trips_through_load_config(tmp_path):
    answers = _enterprise_answers(tmp_path)
    cfg = df_init.build_config(answers)

    cr = tmp_path / "control"
    cr.mkdir()
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    loaded = df_config.load_config(str(cr))
    assert loaded["assurance"] == "enterprise"
    assert loaded["_qualified"] is True
    assert loaded["_custody"]["threshold"] == 2
    assert len(loaded["_custody"]["approvers"]) == 3
    assert loaded["_proxy"]["enabled"] is True
    assert loaded["_proxy"]["token_env"] == "DF_TEST_ENTERPRISE_TOKEN"
    assert loaded["_audit"]["signing"] is True
    assert loaded["_audit"]["sink"]["required"] is True
    assert loaded["_audit"]["sink"]["kind"] == "http-append"
    assert loaded["_confine"]["required"] is True


def test_build_config_enterprise_s3_sink_round_trips_through_load_config(tmp_path):
    answers = _enterprise_answers(
        tmp_path,
        audit_sink={
            "kind": "s3-objectlock",
            "endpoint": "https://s3.example.test",
            "bucket": "df-audit",
            "region": "us-east-1",
        },
    )
    cfg = df_init.build_config(answers)

    cr = tmp_path / "control"
    cr.mkdir()
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    loaded = df_config.load_config(str(cr))
    assert loaded["_audit"]["sink"]["kind"] == "s3-objectlock"
    assert loaded["_audit"]["sink"]["bucket"] == "df-audit"
    # Defaults apply when access_key_env/secret_key_env aren't given.
    assert loaded["_audit"]["sink"]["access_key_env"] == "DF_AUDIT_S3_ACCESS_KEY"
    assert loaded["_audit"]["sink"]["secret_key_env"] == "DF_AUDIT_S3_SECRET_KEY"


def test_scaffold_then_validate_scaffold_enterprise_is_ok(tmp_path):
    answers = _enterprise_answers(tmp_path)
    control_root = answers["control_root"]

    df_init.scaffold(control_root, answers)
    ok, report = df_init.validate_scaffold(control_root)

    assert ok is True, report
    assert report["config_ok"] is True


def test_build_config_enterprise_full_shape(tmp_path):
    answers = _enterprise_answers(tmp_path)
    cfg = df_init.build_config(answers)

    assert cfg["custody"]["threshold"] == 2
    assert len(cfg["custody"]["approvers"]) == 3
    assert cfg["credential_proxy"] == {
        "enabled": True,
        "token_env": "DF_TEST_ENTERPRISE_TOKEN",
        "allowlist": ["api.example.test"],
        "header": "authorization",
    }
    assert cfg["audit"]["signing"] is True
    assert cfg["audit"]["sink"]["required"] is True
    assert cfg["builder_confinement"] == {"enabled": True, "required": True}
    assert "enterprise_downgrade_note" not in cfg


# --- missing operator inputs: fail closed, list exactly what's missing -----


def test_build_config_enterprise_missing_everything_is_init_error_naming_keys(tmp_path):
    answers = _kv_answers(tmp_path, assurance="enterprise")
    with pytest.raises(df_init.InitError) as exc_info:
        df_init.build_config(answers)
    msg = str(exc_info.value)
    assert "approver_pubkeys" in msg
    assert "custody_threshold" in msg
    assert "credential_proxy" in msg
    assert "audit_sink" in msg


def test_build_config_enterprise_missing_only_audit_sink_is_init_error(tmp_path):
    answers = _enterprise_answers(tmp_path)
    del answers["audit_sink"]
    with pytest.raises(df_init.InitError, match="audit_sink"):
        df_init.build_config(answers)


def test_build_config_enterprise_missing_only_credential_proxy_is_init_error(tmp_path):
    answers = _enterprise_answers(tmp_path)
    del answers["credential_proxy"]
    with pytest.raises(df_init.InitError, match="credential_proxy"):
        df_init.build_config(answers)


def test_build_config_enterprise_missing_inputs_writes_nothing(tmp_path):
    """Validate-before-mutate: scaffold() calls build_config() before it
    writes a single file, so a missing-inputs InitError must leave the
    control root untouched (or nonexistent)."""
    answers = _kv_answers(tmp_path, assurance="enterprise")
    control_root = answers["control_root"]
    with pytest.raises(df_init.InitError):
        df_init.scaffold(control_root, answers)
    assert not os.path.exists(control_root)


# --- allow_dev_downgrade escape hatch ---------------------------------------


def test_build_config_enterprise_allow_dev_downgrade_emits_hardened(tmp_path):
    answers = _kv_answers(tmp_path, assurance="enterprise", allow_dev_downgrade=True)
    cfg = df_init.build_config(answers)

    assert cfg["assurance"] == "hardened"
    assert "enterprise_downgrade_note" in cfg
    note = cfg["enterprise_downgrade_note"]
    assert "hardened" in note and "NOT enterprise-qualified" in note
    assert "custody" not in cfg
    assert "credential_proxy" not in cfg


def test_scaffold_then_validate_scaffold_dev_downgrade_is_ok(tmp_path):
    answers = _kv_answers(
        tmp_path,
        assurance="enterprise",
        allow_dev_downgrade=True,
        builder_adapter=sys.executable,  # hardened requires an absolute existing adapter
    )
    control_root = answers["control_root"]

    df_init.scaffold(control_root, answers)
    ok, report = df_init.validate_scaffold(control_root)

    assert ok is True, report
    loaded = df_config.load_config(control_root)
    assert loaded["assurance"] == "hardened"


def test_build_config_enterprise_partial_inputs_without_downgrade_flag_still_fails_closed(tmp_path):
    # Only approver_pubkeys supplied, no downgrade flag -> still an error
    # naming the rest, never a half-generated enterprise config.
    answers = _enterprise_answers(tmp_path)
    del answers["credential_proxy"]
    del answers["audit_sink"]
    with pytest.raises(df_init.InitError) as exc_info:
        df_init.build_config(answers)
    msg = str(exc_info.value)
    assert "credential_proxy" in msg
    assert "audit_sink" in msg
    # approver_pubkeys WAS supplied -- must not be listed as a missing item
    # (the help text mentions the key name too, so check the specific
    # missing-item phrasing rather than a bare substring).
    assert "approver_pubkeys (non-empty list" not in msg


# --- preflight: malformed approver pubkey -----------------------------------


def test_build_config_enterprise_malformed_pubkey_wrong_length_fails_preflight(tmp_path):
    answers = _enterprise_answers(tmp_path)
    answers["approver_pubkeys"] = ["ab" * 31]  # 62 hex chars, not 64
    with pytest.raises(df_init.InitError, match="approver_pubkeys\\[0\\]"):
        df_init.build_config(answers)


def test_build_config_enterprise_malformed_pubkey_non_hex_fails_preflight(tmp_path):
    answers = _enterprise_answers(tmp_path)
    answers["approver_pubkeys"] = ["not-a-valid-hex-key" + "0" * 44]
    with pytest.raises(df_init.InitError, match="approver_pubkeys\\[0\\]"):
        df_init.build_config(answers)


def test_build_config_enterprise_duplicate_pubkeys_fails_preflight(tmp_path):
    pub = _approver_pubkey()
    answers = _enterprise_answers(tmp_path)
    answers["approver_pubkeys"] = [pub, pub.upper()]
    answers["custody_threshold"] = 1
    with pytest.raises(df_init.InitError, match="duplicate"):
        df_init.build_config(answers)


def test_build_config_enterprise_threshold_out_of_range_fails_preflight(tmp_path):
    answers = _enterprise_answers(tmp_path)
    answers["custody_threshold"] = 99
    with pytest.raises(df_init.InitError, match="custody_threshold"):
        df_init.build_config(answers)


# --- preflight: sink well-formedness + no inline secrets --------------------


def test_build_config_enterprise_malformed_http_sink_url_fails_preflight(tmp_path):
    answers = _enterprise_answers(
        tmp_path, audit_sink={"kind": "http-append", "url": "not-a-url"}
    )
    with pytest.raises(df_init.InitError, match="audit_sink.url"):
        df_init.build_config(answers)


def test_build_config_enterprise_s3_sink_missing_bucket_fails_preflight(tmp_path):
    answers = _enterprise_answers(
        tmp_path,
        audit_sink={
            "kind": "s3-objectlock",
            "endpoint": "https://s3.example.test",
            "region": "us-east-1",
        },
    )
    with pytest.raises(df_init.InitError, match="audit_sink"):
        df_init.build_config(answers)


def test_build_config_enterprise_inline_secret_key_in_sink_rejected(tmp_path):
    answers = _enterprise_answers(
        tmp_path,
        audit_sink={
            "kind": "s3-objectlock",
            "endpoint": "https://s3.example.test",
            "bucket": "df-audit",
            "region": "us-east-1",
            "secret_key": "literal-secret-value",
        },
    )
    with pytest.raises(df_init.InitError, match="secret_key"):
        df_init.build_config(answers)


def test_build_config_enterprise_inline_token_in_credential_proxy_rejected(tmp_path):
    answers = _enterprise_answers(tmp_path)
    answers["credential_proxy"] = {
        "token_env": "DF_TEST_ENTERPRISE_TOKEN",
        "allowlist": ["api.example.test"],
        "token": "literal-token-value",
    }
    with pytest.raises(df_init.InitError, match="token"):
        df_init.build_config(answers)


def test_build_config_enterprise_credential_proxy_env_name_wrong_shape_rejected(tmp_path):
    answers = _enterprise_answers(tmp_path)
    answers["credential_proxy"] = {
        "token_env": "not-a-valid-env-name",
        "allowlist": ["api.example.test"],
    }
    with pytest.raises(df_init.InitError, match="token_env"):
        df_init.build_config(answers)


# --- df_custody.validate_public_key (used by the preflight above) ----------


def test_validate_public_key_accepts_a_real_generated_key():
    pub = _approver_pubkey()
    df_custody.validate_public_key(pub)  # does not raise


def test_validate_public_key_rejects_wrong_length():
    with pytest.raises(df_custody.CustodyError):
        df_custody.validate_public_key("ab" * 10)


def test_validate_public_key_rejects_non_hex():
    with pytest.raises(df_custody.CustodyError):
        df_custody.validate_public_key("z" * 64)


# --- back-compat: non-enterprise tiers unaffected ---------------------------


def test_build_config_hardened_unaffected_by_enterprise_changes(tmp_path):
    answers = _kv_answers(tmp_path, assurance="hardened", builder_adapter=sys.executable)
    cfg = df_init.build_config(answers)
    assert cfg["assurance"] == "hardened"
    assert "custody" not in cfg
    assert "credential_proxy" not in cfg
    assert "enterprise_downgrade_note" not in cfg
