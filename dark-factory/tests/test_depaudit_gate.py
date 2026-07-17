"""Tests for the `dependency_audit` security gate + tier policy (M23 Task 2).

`df_depaudit` (Task 1) provides the OSV CVE-check backends. This module
wires it into `df_security.run_gates` as a new opt-in built-in gate, and
into `df_config.py` as `security_gates.dependency_audit` ->
`cfg["_security"]["dependency_audit"]`, with a TIER POLICY: `source:
"osv-api"` (a live network call to api.osv.dev) is forbidden by
ConfigError at hardened/enterprise (whose whole guarantee is no/
controlled egress); `source: "osv-snapshot"` (a pre-provisioned local
snapshot, zero run-time network egress) is allowed at every tier.

Every run_gates test here monkeypatches `df_depaudit.parse_installed` /
`df_depaudit.query_osv_api` / `df_depaudit.query_osv_snapshot` -- this
suite makes ZERO real network calls.
"""
import os

import pytest

import df_config
import df_depaudit
import df_security
from df_creds import Redactor
from test_config import write_config
from test_enterprise_config import VALID_ADAPTER, _base_enterprise

FIXTURE_SNAPSHOT_DIR = os.path.join(
    os.path.dirname(__file__), "fixtures", "osv_snapshot"
)


# ---------------------------------------------------------------------------
# df_config: security_gates.dependency_audit -- shape + tier policy
# ---------------------------------------------------------------------------


def test_absent_dependency_audit_block_defaults_disabled(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"]["dependency_audit"] == {
        "enabled": False,
        "source": None,
        "snapshot_path": None,
        "ecosystems": [],
        "timeout_s": 20,
    }


def test_absent_security_gates_no_dependency_audit_key(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    # M33a: the tier-independent waiver policy is always present (empty here).
    assert cfg["_security"] == {"enabled": False, "waivers": {"signers": [], "threshold": 0}}


def test_osv_api_at_standard_ok(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        assurance="standard",
        security_gates={
            "enabled": True,
            "dependency_audit": {"enabled": True, "source": "osv-api"},
        },
    )
    cfg = df_config.load_config(str(cr))
    da = cfg["_security"]["dependency_audit"]
    assert da["enabled"] is True
    assert da["source"] == "osv-api"
    assert da["snapshot_path"] is None
    assert da["timeout_s"] == 20


def test_osv_api_at_cooperative_ok(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        assurance="cooperative",
        security_gates={
            "enabled": True,
            "dependency_audit": {"enabled": True, "source": "osv-api"},
        },
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"]["dependency_audit"]["source"] == "osv-api"


def test_osv_api_at_hardened_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        assurance="hardened",
        roles={"builder": {"adapter": VALID_ADAPTER, "timeout_s": 60}},
        security_gates={
            "enabled": True,
            "dependency_audit": {"enabled": True, "source": "osv-api"},
        },
    )
    with pytest.raises(df_config.ConfigError, match="uncontrolled network egress"):
        df_config.load_config(str(cr))


def test_osv_api_at_enterprise_rejected(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise(
        security_gates={
            "enabled": True,
            "dependency_audit": {"enabled": True, "source": "osv-api"},
        },
    )
    write_config(cr, **overrides)
    with pytest.raises(df_config.ConfigError, match="uncontrolled network egress"):
        df_config.load_config(str(cr))


def test_osv_snapshot_at_hardened_with_valid_dir_ok(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        assurance="hardened",
        roles={"builder": {"adapter": VALID_ADAPTER, "timeout_s": 60}},
        security_gates={
            "enabled": True,
            "dependency_audit": {
                "enabled": True,
                "source": "osv-snapshot",
                "snapshot_path": FIXTURE_SNAPSHOT_DIR,
            },
        },
    )
    cfg = df_config.load_config(str(cr))
    da = cfg["_security"]["dependency_audit"]
    assert da["source"] == "osv-snapshot"
    assert da["snapshot_path"] == FIXTURE_SNAPSHOT_DIR


def test_osv_snapshot_at_enterprise_with_valid_dir_ok(tmp_path):
    cr = tmp_path / "control"
    overrides = _base_enterprise(
        security_gates={
            "enabled": True,
            "dependency_audit": {
                "enabled": True,
                "source": "osv-snapshot",
                "snapshot_path": FIXTURE_SNAPSHOT_DIR,
            },
        },
    )
    write_config(cr, **overrides)
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"]["dependency_audit"]["source"] == "osv-snapshot"


def test_osv_snapshot_missing_snapshot_path_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "dependency_audit": {"enabled": True, "source": "osv-snapshot"},
        },
    )
    with pytest.raises(df_config.ConfigError, match="snapshot_path"):
        df_config.load_config(str(cr))


def test_osv_snapshot_nonexistent_snapshot_path_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "dependency_audit": {
                "enabled": True,
                "source": "osv-snapshot",
                "snapshot_path": str(tmp_path / "does-not-exist"),
            },
        },
    )
    with pytest.raises(df_config.ConfigError, match="snapshot_path"):
        df_config.load_config(str(cr))


def test_source_omitted_when_enabled_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "dependency_audit": {"enabled": True}}
    )
    with pytest.raises(df_config.ConfigError, match="source"):
        df_config.load_config(str(cr))


def test_source_invalid_value_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "dependency_audit": {"enabled": True, "source": "nmap"},
        },
    )
    with pytest.raises(df_config.ConfigError, match="source"):
        df_config.load_config(str(cr))


def test_fail_on_dependency_audit_accepted(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        assurance="standard",
        security_gates={
            "enabled": True,
            "fail_on": ["dependency_audit"],
            "dependency_audit": {"enabled": True, "source": "osv-api"},
        },
    )
    cfg = df_config.load_config(str(cr))
    # M33a: standard forces the mandatory gates INTO fail_on (union), so the
    # operator-added dependency_audit is joined by secret_scan/dangerous_scan
    # rather than standing alone.
    assert set(cfg["_security"]["fail_on"]) == {
        "dependency_audit", "secret_scan", "dangerous_scan"}


def test_dependency_audit_block_non_dict_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "dependency_audit": ["not", "a", "dict"]}
    )
    with pytest.raises(df_config.ConfigError, match="dependency_audit"):
        df_config.load_config(str(cr))


def test_dependency_audit_enabled_non_bool_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={"enabled": True, "dependency_audit": {"enabled": "yes"}},
    )
    with pytest.raises(df_config.ConfigError, match="enabled"):
        df_config.load_config(str(cr))


def test_dependency_audit_ecosystems_non_list_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "dependency_audit": {"ecosystems": "PyPI"},
        },
    )
    with pytest.raises(df_config.ConfigError, match="ecosystems"):
        df_config.load_config(str(cr))


def test_dependency_audit_timeout_s_out_of_bounds_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={"enabled": True, "dependency_audit": {"timeout_s": 0}},
    )
    with pytest.raises(df_config.ConfigError, match="timeout_s"):
        df_config.load_config(str(cr))


def test_dependency_audit_custom_ecosystems_and_timeout_round_trip(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        assurance="standard",
        security_gates={
            "enabled": True,
            "dependency_audit": {
                "enabled": True,
                "source": "osv-api",
                "ecosystems": ["PyPI", "npm"],
                "timeout_s": 45,
            },
        },
    )
    cfg = df_config.load_config(str(cr))
    da = cfg["_security"]["dependency_audit"]
    assert da["ecosystems"] == ["PyPI", "npm"]
    assert da["timeout_s"] == 45


# ---------------------------------------------------------------------------
# run_gates wiring -- df_depaudit fully monkeypatched, ZERO network calls
# ---------------------------------------------------------------------------


def _sec(fail_on=None, strict_unavailable=True, **depaudit_overrides):
    depaudit = {
        "enabled": True,
        "source": "osv-api",
        "snapshot_path": None,
        "ecosystems": [],
        "timeout_s": 20,
    }
    depaudit.update(depaudit_overrides)
    return {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": fail_on if fail_on is not None else [],
        "strict_unavailable": strict_unavailable,
        "license": {"enabled": False, "allowlist": [], "require_license": False},
        "dependency_audit": depaudit,
    }


def test_run_gates_absent_block_never_calls_parse_installed(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()

    def _boom(*a, **kw):
        raise AssertionError("parse_installed must never be called when the "
                              "dependency_audit block is absent/disabled")

    monkeypatch.setattr(df_depaudit, "parse_installed", _boom)
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": [],
        "strict_unavailable": True,
    }  # no "dependency_audit" key at all -- back-compat sec dict
    report = df_security.run_gates(str(ws), sec)
    assert "dependency_audit" not in report["gates"]


def test_run_gates_disabled_dependency_audit_never_calls_parse_installed(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()

    def _boom(*a, **kw):
        raise AssertionError("parse_installed must never be called when disabled")

    monkeypatch.setattr(df_depaudit, "parse_installed", _boom)
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": [],
        "strict_unavailable": True,
        "dependency_audit": {
            "enabled": False,
            "source": None,
            "snapshot_path": None,
            "ecosystems": [],
            "timeout_s": 20,
        },
    }
    report = df_security.run_gates(str(ws), sec)
    assert "dependency_audit" not in report["gates"]


def test_run_gates_vulnerable_dep_fails_and_in_failed_when_fail_on(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(df_depaudit, "parse_installed",
                         lambda root: [{"ecosystem": "PyPI", "name": "bad-pkg", "version": "1.0.0"}])
    monkeypatch.setattr(
        df_depaudit,
        "query_osv_api",
        lambda pkgs, **kw: {
            "source": "osv-api",
            "checked": True,
            "unavailable": False,
            "reason": "",
            "results": [
                {
                    "name": "bad-pkg",
                    "version": "1.0.0",
                    "ecosystem": "PyPI",
                    "vulns": [{"id": "GHSA-xxxx", "summary": "bad"}],
                }
            ],
        },
    )
    sec = _sec(fail_on=["dependency_audit"])
    report = df_security.run_gates(str(ws), sec)
    gate = report["gates"]["dependency_audit"]
    assert gate["status"] == "fail"
    assert report["failed"] == ["dependency_audit"]
    assert gate["findings"] == [
        {
            "name": "bad-pkg",
            "version": "1.0.0",
            "ecosystem": "PyPI",
            "vuln_ids": ["GHSA-xxxx"],
            "source": "osv-api",
        }
    ]


def test_run_gates_clean_dep_passes(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(df_depaudit, "parse_installed",
                         lambda root: [{"ecosystem": "PyPI", "name": "good-pkg", "version": "2.0.0"}])
    monkeypatch.setattr(
        df_depaudit,
        "query_osv_api",
        lambda pkgs, **kw: {
            "source": "osv-api",
            "checked": True,
            "unavailable": False,
            "reason": "",
            "results": [
                {"name": "good-pkg", "version": "2.0.0", "ecosystem": "PyPI", "vulns": []}
            ],
        },
    )
    sec = _sec(fail_on=["dependency_audit"])
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["dependency_audit"]["status"] == "pass"
    assert report["gates"]["dependency_audit"]["findings"] == []
    assert report["failed"] == []


def test_run_gates_unavailable_fails_under_strict_unavailable(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(df_depaudit, "parse_installed", lambda root: [
        {"ecosystem": "PyPI", "name": "whatever", "version": "1.0.0"}
    ])
    monkeypatch.setattr(
        df_depaudit,
        "query_osv_api",
        lambda pkgs, **kw: {
            "source": "osv-api", "checked": True, "unavailable": True,
            "reason": "osv-api query failed: boom", "results": [],
        },
    )
    sec = _sec(fail_on=["dependency_audit"], strict_unavailable=True)
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["dependency_audit"]["status"] == "unavailable"
    assert report["failed"] == ["dependency_audit"]


def test_run_gates_unavailable_not_failed_when_strict_unavailable_false(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(df_depaudit, "parse_installed", lambda root: [
        {"ecosystem": "PyPI", "name": "whatever", "version": "1.0.0"}
    ])
    monkeypatch.setattr(
        df_depaudit,
        "query_osv_api",
        lambda pkgs, **kw: {
            "source": "osv-api", "checked": True, "unavailable": True,
            "reason": "osv-api query failed: boom", "results": [],
        },
    )
    sec = _sec(fail_on=["dependency_audit"], strict_unavailable=False)
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["dependency_audit"]["status"] == "unavailable"
    assert report["failed"] == []


def test_run_gates_not_in_fail_on_never_fails_run(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(df_depaudit, "parse_installed", lambda root: [
        {"ecosystem": "PyPI", "name": "bad-pkg", "version": "1.0.0"}
    ])
    monkeypatch.setattr(
        df_depaudit,
        "query_osv_api",
        lambda pkgs, **kw: {
            "source": "osv-api", "checked": True, "unavailable": False, "reason": "",
            "results": [{"name": "bad-pkg", "version": "1.0.0", "ecosystem": "PyPI",
                         "vulns": [{"id": "GHSA-xxxx", "summary": "bad"}]}],
        },
    )
    sec = _sec(fail_on=[])  # dependency_audit NOT mandatory
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["dependency_audit"]["status"] == "fail"
    assert report["failed"] == []


def test_finding_carries_no_secret_and_is_redacted(tmp_path, monkeypatch):
    # Simulate a secret-looking string leaking into a pinned dependency
    # name (e.g. a malicious/misconfigured manifest). The gate must still
    # report the finding (no special-casing), and the SAME redaction choke
    # point used for the rest of the security report (df_creds.Redactor)
    # must scrub it before it hits a written artifact -- this is
    # defense-in-depth, not something dependency_audit does itself.
    secret = "sk-supersecrettoken1234567890"
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(
        df_depaudit, "parse_installed",
        lambda root: [{"ecosystem": "PyPI", "name": f"{secret}-pkg", "version": "1.0.0"}],
    )
    monkeypatch.setattr(
        df_depaudit,
        "query_osv_api",
        lambda pkgs, **kw: {
            "source": "osv-api", "checked": True, "unavailable": False, "reason": "",
            "results": [{"name": f"{secret}-pkg", "version": "1.0.0", "ecosystem": "PyPI",
                         "vulns": [{"id": "GHSA-xxxx", "summary": "bad"}]}],
        },
    )
    sec = _sec(fail_on=["dependency_audit"])
    report = df_security.run_gates(str(ws), sec)
    finding = report["gates"]["dependency_audit"]["findings"][0]
    # No key beyond the documented shape -- nothing extra riding along.
    assert set(finding.keys()) == {"name", "version", "ecosystem", "vuln_ids", "source"}

    redactor = Redactor([secret])
    redacted_report = redactor.redact_obj(report)
    redacted_text = str(redacted_report)
    assert secret not in redacted_text
    assert Redactor.PLACEHOLDER in redacted_text


def test_osv_snapshot_path_makes_no_network_call(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()

    def _query_osv_api_raises(pkgs, **kw):
        raise AssertionError(
            "query_osv_api (the live network backend) must never be called "
            "when source is osv-snapshot"
        )

    monkeypatch.setattr(df_depaudit, "query_osv_api", _query_osv_api_raises)
    monkeypatch.setattr(
        df_depaudit, "parse_installed",
        lambda root: [{"ecosystem": "PyPI", "name": "demo-pkg", "version": "1.0.0"}],
    )
    sec = _sec(
        fail_on=["dependency_audit"],
        source="osv-snapshot",
        snapshot_path=FIXTURE_SNAPSHOT_DIR,
    )
    report = df_security.run_gates(str(ws), sec)
    # demo-pkg==1.0.0 is an enumerated vulnerable version in the fixture
    # snapshot (GHSA-enum-demo) -- proves the offline path actually ran
    # (not silently skipped) while never touching query_osv_api.
    assert report["gates"]["dependency_audit"]["status"] == "fail"
    assert report["failed"] == ["dependency_audit"]


def test_osv_snapshot_load_failure_is_unavailable(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(
        df_depaudit, "parse_installed",
        lambda root: [{"ecosystem": "PyPI", "name": "demo-pkg", "version": "1.0.0"}],
    )

    def _query_osv_api_raises(pkgs, **kw):
        raise AssertionError("must never be called for the snapshot source")

    monkeypatch.setattr(df_depaudit, "query_osv_api", _query_osv_api_raises)
    sec = _sec(
        fail_on=["dependency_audit"],
        source="osv-snapshot",
        snapshot_path=str(tmp_path / "no-such-snapshot-dir"),
    )
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["dependency_audit"]["status"] == "unavailable"
    assert report["failed"] == ["dependency_audit"]


def test_ecosystems_filter_restricts_packages_queried(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(
        df_depaudit, "parse_installed",
        lambda root: [
            {"ecosystem": "PyPI", "name": "pypkg", "version": "1.0.0"},
            {"ecosystem": "npm", "name": "npmpkg", "version": "1.0.0"},
        ],
    )
    seen = {}

    def _query_osv_api(pkgs, **kw):
        seen["pkgs"] = pkgs
        return {
            "source": "osv-api", "checked": True, "unavailable": False, "reason": "",
            "results": [
                {"name": p["name"], "version": p["version"], "ecosystem": p["ecosystem"], "vulns": []}
                for p in pkgs
            ],
        }

    monkeypatch.setattr(df_depaudit, "query_osv_api", _query_osv_api)
    sec = _sec(fail_on=["dependency_audit"], ecosystems=["PyPI"])
    report = df_security.run_gates(str(ws), sec)
    assert [p["name"] for p in seen["pkgs"]] == ["pypkg"]
    assert report["gates"]["dependency_audit"]["status"] == "pass"
