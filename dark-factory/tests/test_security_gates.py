"""Tests for security_gates config validation + the gate runner (M9 Task 2).

df_config.load_config injects cfg["_security"]; df_security.run_gates runs
the enabled built-ins + external gates over a workspace, fail-closed on
strict_unavailable.
"""
import os

import pytest

import df_config
import df_security
from test_config import write_config

AKIA_SECRET = "AKIAABCDEFGHIJKLMNOP"  # fake AWS access key id, AKIA + 16 caps


def _write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# --- df_config: cfg["_security"] --------------------------------------


def test_absent_security_gates_defaults_disabled(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    # M33a: cooperative (write_config default tier) leaves gates disabled, but
    # the tier-independent waiver policy is always present (fail-closed empty).
    assert cfg["_security"] == {
        "enabled": False,
        "waivers": {"signers": [], "threshold": 0},
    }


def test_enabled_applies_defaults(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"] == {
        "enabled": True,
        "secret_scan": True,
        "dangerous_scan": True,
        "sbom": True,
        "external": [],
        "fail_on": ["secret_scan", "dangerous_scan"],
        "strict_unavailable": True,
        "license": {"enabled": False, "allowlist": [], "require_license": False},
        "dependency_audit": {
            "enabled": False,
            "source": None,
            "snapshot_path": None,
            "ecosystems": [],
            "timeout_s": 20,
        },
        "waivers": {"signers": [], "threshold": 0},
    }


def test_explicit_valid_config_round_trips(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "secret_scan": True,
            "dangerous_scan": False,
            "sbom": False,
            "external": [{"name": "bandit", "cmd": ["bandit", "-r", "."]}],
            "fail_on": ["secret_scan", "bandit"],
            "strict_unavailable": False,
        },
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"] == {
        "enabled": True,
        "secret_scan": True,
        "dangerous_scan": False,
        "sbom": False,
        "external": [{"name": "bandit", "cmd": ["bandit", "-r", "."]}],
        "fail_on": ["secret_scan", "bandit"],
        "strict_unavailable": False,
        "license": {"enabled": False, "allowlist": [], "require_license": False},
        "dependency_audit": {
            "enabled": False,
            "source": None,
            "snapshot_path": None,
            "ecosystems": [],
            "timeout_s": 20,
        },
        "waivers": {"signers": [], "threshold": 0},
    }


@pytest.mark.parametrize("key", ["secret_scan", "dangerous_scan", "sbom", "strict_unavailable"])
def test_non_bool_flag_rejected(tmp_path, key):
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True, key: "yes"})
    with pytest.raises(df_config.ConfigError, match=key):
        df_config.load_config(str(cr))


def test_non_dict_security_gates_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates=["not", "a", "dict"])
    with pytest.raises(df_config.ConfigError, match="security_gates"):
        df_config.load_config(str(cr))


def test_external_missing_name_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True, "external": [{"cmd": ["true"]}]})
    with pytest.raises(df_config.ConfigError, match="name"):
        df_config.load_config(str(cr))


def test_external_empty_name_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "external": [{"name": "", "cmd": ["true"]}]}
    )
    with pytest.raises(df_config.ConfigError, match="name"):
        df_config.load_config(str(cr))


def test_external_cmd_not_list_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "external": [{"name": "x", "cmd": "true"}]}
    )
    with pytest.raises(df_config.ConfigError, match="cmd"):
        df_config.load_config(str(cr))


def test_external_cmd_empty_list_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "external": [{"name": "x", "cmd": []}]}
    )
    with pytest.raises(df_config.ConfigError, match="cmd"):
        df_config.load_config(str(cr))


def test_external_cmd_non_str_elements_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "external": [{"name": "x", "cmd": ["true", 1]}]}
    )
    with pytest.raises(df_config.ConfigError, match="cmd"):
        df_config.load_config(str(cr))


def test_fail_on_unknown_name_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True, "fail_on": ["not_a_gate"]})
    with pytest.raises(df_config.ConfigError, match="fail_on"):
        df_config.load_config(str(cr))


def test_fail_on_referencing_declared_external_name_ok(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "external": [{"name": "bandit", "cmd": ["bandit"]}],
            "fail_on": ["bandit"],
        },
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"]["fail_on"] == ["bandit"]


def test_fail_on_not_a_list_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True, "fail_on": "secret_scan"})
    with pytest.raises(df_config.ConfigError, match="fail_on"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("reserved", ["secret_scan", "dangerous_scan", "sbom"])
def test_external_name_collides_with_builtin_rejected(tmp_path, reserved):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "external": [{"name": reserved, "cmd": ["true"]}],
        },
    )
    with pytest.raises(df_config.ConfigError, match="reserved"):
        df_config.load_config(str(cr))


def test_external_duplicate_name_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "external": [
                {"name": "dup", "cmd": ["true"]},
                {"name": "dup", "cmd": ["false"]},
            ],
        },
    )
    with pytest.raises(df_config.ConfigError, match="duplicate"):
        df_config.load_config(str(cr))


# --- df_security.run_gates ---------------------------------------------


def test_run_gates_planted_secret_fails(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _write(str(ws), "config.py", f"aws_key = {AKIA_SECRET}\n")
    sec = {
        "enabled": True,
        "secret_scan": True,
        "dangerous_scan": True,
        "sbom": True,
        "external": [],
        "fail_on": ["secret_scan"],
        "strict_unavailable": True,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["checked"] is True
    assert report["failed"] == ["secret_scan"]
    assert report["gates"]["secret_scan"]["status"] == "fail"
    assert report["gates"]["secret_scan"]["findings"]


def test_run_gates_clean_workspace_passes(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _write(str(ws), "app.py", "def add(a, b):\n    return a + b\n")
    sec = {
        "enabled": True,
        "secret_scan": True,
        "dangerous_scan": True,
        "sbom": True,
        "external": [],
        "fail_on": ["secret_scan", "dangerous_scan"],
        "strict_unavailable": True,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["failed"] == []
    assert report["gates"]["secret_scan"]["status"] == "pass"
    assert report["gates"]["dangerous_scan"]["status"] == "pass"
    assert report["gates"]["sbom"]["status"] == "pass"
    assert "sbom" in report["gates"]["sbom"]


def test_run_gates_external_unavailable_strict_fails(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [{"name": "nope", "cmd": ["definitely-not-a-real-tool-xyz-999"]}],
        "fail_on": ["nope"],
        "strict_unavailable": True,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["nope"]["status"] == "unavailable"
    assert report["failed"] == ["nope"]


def test_run_gates_external_unavailable_not_strict_does_not_fail(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [{"name": "nope", "cmd": ["definitely-not-a-real-tool-xyz-999"]}],
        "fail_on": ["nope"],
        "strict_unavailable": False,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["nope"]["status"] == "unavailable"
    assert report["failed"] == []


def test_run_gates_external_present_command_passes(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [{"name": "ok", "cmd": ["true"]}],
        "fail_on": ["ok"],
        "strict_unavailable": True,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["ok"]["status"] == "pass"
    assert report["failed"] == []


def test_run_gates_external_failing_command_fails(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [{"name": "bad", "cmd": ["false"]}],
        "fail_on": ["bad"],
        "strict_unavailable": True,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["bad"]["status"] == "fail"
    assert report["failed"] == ["bad"]


def test_run_gates_fail_on_gate_not_run_is_unavailable_and_fails(tmp_path):
    # dangerous_scan is disabled but still listed in fail_on: it never runs,
    # so under strict_unavailable it must be treated as unavailable + failed
    # (regression: previously it silently vanished and failed==[]).
    ws = tmp_path / "ws"
    ws.mkdir()
    _write(str(ws), "app.py", "def add(a, b):\n    return a + b\n")
    sec = {
        "enabled": True,
        "secret_scan": True,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": ["secret_scan", "dangerous_scan"],
        "strict_unavailable": True,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["dangerous_scan"]["status"] == "unavailable"
    assert report["failed"] == ["dangerous_scan"]


def test_run_gates_fail_on_gate_not_run_not_strict_does_not_fail(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _write(str(ws), "app.py", "def add(a, b):\n    return a + b\n")
    sec = {
        "enabled": True,
        "secret_scan": True,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": ["secret_scan", "dangerous_scan"],
        "strict_unavailable": False,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["dangerous_scan"]["status"] == "unavailable"
    assert report["failed"] == []


def test_run_gates_gate_not_in_fail_on_does_not_fail_run(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _write(str(ws), "config.py", f"aws_key = {AKIA_SECRET}\n")
    sec = {
        "enabled": True,
        "secret_scan": True,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": [],
        "strict_unavailable": True,
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["secret_scan"]["status"] == "fail"
    assert report["failed"] == []


# --- M33a (DF-06): mandatory gates at standard+ + waiver policy ------------

# A syntactically valid ed25519 public key (64 hex chars). df_config validates
# waiver signers with the same stdlib _HEX64_RE shape check custody uses, so a
# fixed hex literal is sufficient (no `cryptography` needed at config load).
PUBKEY_A = "a" * 64
PUBKEY_B = "b" * 64


def _std(cr, **extra):
    write_config(cr, assurance="standard", **extra)


def test_standard_synthesizes_mandatory_gates_without_block(tmp_path):
    cr = tmp_path / "control"
    _std(cr)  # NO security_gates block at all
    sec = df_config.load_config(str(cr))["_security"]
    assert sec["enabled"] is True
    assert sec["secret_scan"] is True and sec["dangerous_scan"] is True
    assert sec["strict_unavailable"] is True
    assert set(sec["fail_on"]) >= {"secret_scan", "dangerous_scan"}
    assert sec["waivers"] == {"signers": [], "threshold": 0}


def test_mandatory_tiers_membership():
    # secret_scan/dangerous_scan are mandatory at exactly standard/hardened/
    # enterprise (cooperative excluded). The forcing code keys off this tuple,
    # so hardened/enterprise get the same treatment standard does (their full
    # configs also require custody/proxy/adapter blocks that other tests cover;
    # the security-gates logic itself is tier-generic).
    assert df_config.MANDATORY_TIERS == ("standard", "hardened", "enterprise")
    assert df_config.MANDATORY_GATES == ("secret_scan", "dangerous_scan")


def test_standard_disabling_secret_scan_rejected(tmp_path):
    cr = tmp_path / "control"
    _std(cr, security_gates={"enabled": True, "secret_scan": False})
    with pytest.raises(df_config.ConfigError, match="never disable secret_scan"):
        df_config.load_config(str(cr))


def test_standard_disabling_dangerous_scan_rejected(tmp_path):
    cr = tmp_path / "control"
    _std(cr, security_gates={"enabled": True, "dangerous_scan": False})
    with pytest.raises(df_config.ConfigError, match="never disable dangerous_scan"):
        df_config.load_config(str(cr))


def test_standard_may_strengthen_fail_on(tmp_path):
    cr = tmp_path / "control"
    _std(cr, security_gates={"enabled": True, "sbom": True, "fail_on": ["sbom"]})
    sec = df_config.load_config(str(cr))["_security"]
    # operator added sbom; mandatory gates are UNIONED in, never dropped.
    assert set(sec["fail_on"]) == {"sbom", "secret_scan", "dangerous_scan"}


def test_cooperative_unchanged_gates_optional(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)  # cooperative default, no gates
    sec = df_config.load_config(str(cr))["_security"]
    assert sec == {"enabled": False, "waivers": {"signers": [], "threshold": 0}}


def test_cooperative_may_disable_secret_scan(tmp_path):
    # The mandatory-gate rule is standard+ ONLY; cooperative can still turn a
    # gate off (it was never mandatory there).
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True, "secret_scan": False})
    sec = df_config.load_config(str(cr))["_security"]
    assert sec["secret_scan"] is False


def test_waivers_valid_policy(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={
        "enabled": True,
        "waivers": {"signers": [PUBKEY_A, PUBKEY_B], "threshold": 2},
    })
    sec = df_config.load_config(str(cr))["_security"]
    assert sec["waivers"] == {"signers": [PUBKEY_A, PUBKEY_B], "threshold": 2}


def test_waivers_tier_independent_on_cooperative(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={
        "enabled": True,
        "waivers": {"signers": [PUBKEY_A], "threshold": 1},
    })
    sec = df_config.load_config(str(cr))["_security"]
    assert sec["waivers"] == {"signers": [PUBKEY_A], "threshold": 1}


def test_waivers_bad_pubkey_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={
        "enabled": True, "waivers": {"signers": ["nothex"], "threshold": 1}})
    with pytest.raises(df_config.ConfigError, match="waivers.signers"):
        df_config.load_config(str(cr))


def test_waivers_threshold_over_len_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={
        "enabled": True, "waivers": {"signers": [PUBKEY_A], "threshold": 2}})
    with pytest.raises(df_config.ConfigError, match="waivers.threshold"):
        df_config.load_config(str(cr))


def test_waivers_threshold_zero_with_signers_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={
        "enabled": True, "waivers": {"signers": [PUBKEY_A], "threshold": 0}})
    with pytest.raises(df_config.ConfigError, match="waivers.threshold"):
        df_config.load_config(str(cr))


def test_waivers_threshold_without_signers_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={
        "enabled": True, "waivers": {"signers": [], "threshold": 1}})
    with pytest.raises(df_config.ConfigError, match="non-empty signers list"):
        df_config.load_config(str(cr))


def test_waivers_duplicate_signer_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={
        "enabled": True, "waivers": {"signers": [PUBKEY_A, PUBKEY_A], "threshold": 1}})
    with pytest.raises(df_config.ConfigError, match="duplicate"):
        df_config.load_config(str(cr))


# --- M33a Finding 1: a non-empty waiver policy requires signed manifests ----


def test_waivers_require_audit_signing_explicit_false_rejected(tmp_path):
    cr = tmp_path / "control"
    _std(
        cr,
        security_gates={"enabled": True, "waivers": {"signers": [PUBKEY_A], "threshold": 1}},
        audit={"signing": False},
    )
    with pytest.raises(df_config.ConfigError, match="requires audit.signing"):
        df_config.load_config(str(cr))


def test_waivers_with_audit_signing_true_ok(tmp_path):
    cr = tmp_path / "control"
    _std(
        cr,
        security_gates={"enabled": True, "waivers": {"signers": [PUBKEY_A], "threshold": 1}},
        audit={"signing": True, "key_path": str(tmp_path / "keys" / "audit.key")},
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["signing"] is True
    assert cfg["_security"]["waivers"] == {"signers": [PUBKEY_A], "threshold": 1}


def test_waivers_force_audit_signing_when_absent(tmp_path):
    # Absent/defaulted-false signing + a waiver policy => forced ON (mirrors
    # the hardened/enterprise audit.signing default), so the sealed allowlist
    # is HMAC-protected by construction.
    cr = tmp_path / "control"
    write_config(cr, security_gates={
        "enabled": True, "waivers": {"signers": [PUBKEY_A], "threshold": 1}})
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["signing"] is True
    assert cfg["_audit"]["key_path"]  # a concrete key path was defaulted in


def test_empty_waivers_policy_does_not_require_signing(tmp_path):
    # No signers => no waiver acceptance => no signing requirement; an explicit
    # audit.signing:false stays valid.
    cr = tmp_path / "control"
    _std(
        cr,
        security_gates={"enabled": True, "waivers": {"signers": [], "threshold": 0}},
        audit={"signing": False},
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["signing"] is False
