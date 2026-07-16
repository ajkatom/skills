"""Tests for the license-policy security gate (M18 Task 2).

df_security.license_scan scans an artifact tree for licenses DECLARED in
manifests (pyproject.toml, package.json) and VENDORED dependency metadata
(node_modules/*/package.json, *.dist-info/METADATA) physically present in
the tree -- offline, no network, no transitive resolution of un-vendored
deps. It is wired into run_gates as a new built-in gate `license`, and into
df_config.py as `security_gates.license` -> cfg["_security"]["license"].
"""
import json
import os

import pytest

import df_config
import df_security
from test_config import write_config


def _write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# --- license_scan --------------------------------------------------------


def test_pyproject_license_in_allowlist_no_finding(tmp_path):
    root = str(tmp_path)
    _write(root, "pyproject.toml", '[project]\nname = "demo"\nlicense = "MIT"\n')
    findings = df_security.license_scan(root, ["MIT"])
    assert findings == []


def test_pyproject_license_not_in_allowlist_finding_names_mit(tmp_path):
    root = str(tmp_path)
    _write(root, "pyproject.toml", '[project]\nname = "demo"\nlicense = "MIT"\n')
    findings = df_security.license_scan(root, ["Apache-2.0"])
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "disallowed-license"
    assert f["license"] == "MIT"
    assert f["file"] == "pyproject.toml"
    assert set(f.keys()) == {"file", "package", "license", "rule"}


def test_pyproject_license_table_text_form(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "pyproject.toml",
        '[project]\nname = "demo"\nlicense = { text = "GPL-3.0" }\n',
    )
    findings = df_security.license_scan(root, ["MIT"])
    assert len(findings) == 1
    assert findings[0]["license"] == "GPL-3.0"


def test_pyproject_trove_classifier(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "pyproject.toml",
        "\n".join(
            [
                "[project]",
                'name = "demo"',
                "classifiers = [",
                '    "License :: OSI Approved :: MIT License",',
                "]",
            ]
        ),
    )
    findings = df_security.license_scan(root, ["Apache-2.0"])
    assert len(findings) == 1
    assert findings[0]["rule"] == "disallowed-license"
    assert "MIT" in findings[0]["license"]


def test_package_json_license_not_in_allowlist(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", json.dumps({"name": "demo", "license": "GPL-3.0"}))
    findings = df_security.license_scan(root, ["MIT"])
    assert len(findings) == 1
    assert findings[0]["license"] == "GPL-3.0"
    assert findings[0]["rule"] == "disallowed-license"


def test_package_json_license_in_allowlist_no_finding(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", json.dumps({"name": "demo", "license": "MIT"}))
    findings = df_security.license_scan(root, ["MIT"])
    assert findings == []


def test_package_json_legacy_licenses_array(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "package.json",
        json.dumps({"name": "demo", "licenses": [{"type": "GPL-3.0"}]}),
    )
    findings = df_security.license_scan(root, ["MIT"])
    assert len(findings) == 1
    assert findings[0]["license"] == "GPL-3.0"


def test_vendored_node_modules_disallowed_license_names_package(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("node_modules", "foo", "package.json"),
        json.dumps({"name": "foo", "license": "GPL-3.0"}),
    )
    findings = df_security.license_scan(root, ["MIT"])
    assert len(findings) == 1
    assert findings[0]["package"] == "foo"
    assert findings[0]["license"] == "GPL-3.0"
    assert findings[0]["rule"] == "disallowed-license"


def test_vendored_node_modules_allowed_license_no_finding(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("node_modules", "foo", "package.json"),
        json.dumps({"name": "foo", "license": "MIT"}),
    )
    findings = df_security.license_scan(root, ["MIT"])
    assert findings == []


def test_vendored_dist_info_metadata_license_field(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("site-packages", "foo-1.2.3.dist-info", "METADATA"),
        "Metadata-Version: 2.1\nName: foo\nVersion: 1.2.3\nLicense: GPL-3.0\n\nSome long description.\n",
    )
    findings = df_security.license_scan(root, ["MIT"])
    assert len(findings) == 1
    assert findings[0]["package"] == "foo"
    assert findings[0]["license"] == "GPL-3.0"


def test_vendored_dist_info_metadata_classifier(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("site-packages", "bar-2.0.dist-info", "METADATA"),
        "Metadata-Version: 2.1\nName: bar\nClassifier: License :: OSI Approved :: Apache Software License\n\n",
    )
    findings = df_security.license_scan(root, ["MIT"])
    assert len(findings) == 1
    assert findings[0]["package"] == "bar"
    assert "Apache" in findings[0]["license"]


def test_require_license_missing_license_finding(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("node_modules", "nolicense", "package.json"),
        json.dumps({"name": "nolicense"}),
    )
    findings = df_security.license_scan(root, ["MIT"], require_license=True)
    assert len(findings) == 1
    assert findings[0]["rule"] == "missing-license"
    assert findings[0]["package"] == "nolicense"


def test_no_require_license_missing_license_not_flagged(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("node_modules", "nolicense", "package.json"),
        json.dumps({"name": "nolicense"}),
    )
    findings = df_security.license_scan(root, ["MIT"], require_license=False)
    assert findings == []


def test_case_insensitive_allowlist_match(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", json.dumps({"name": "demo", "license": "mit"}))
    findings = df_security.license_scan(root, ["MIT"])
    assert findings == []


def test_case_insensitive_allowlist_match_reverse_case(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", json.dumps({"name": "demo", "license": "MIT"}))
    findings = df_security.license_scan(root, ["mit"])
    assert findings == []


def test_empty_allowlist_disallows_everything(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", json.dumps({"name": "demo", "license": "MIT"}))
    findings = df_security.license_scan(root, [])
    assert len(findings) == 1
    assert findings[0]["rule"] == "disallowed-license"


def test_deterministic_sorted_output(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("node_modules", "zeta", "package.json"),
        json.dumps({"name": "zeta", "license": "GPL-3.0"}),
    )
    _write(
        root,
        os.path.join("node_modules", "alpha", "package.json"),
        json.dumps({"name": "alpha", "license": "GPL-3.0"}),
    )
    findings = df_security.license_scan(root, ["MIT"])
    files = [f["file"] for f in findings]
    assert files == sorted(files)


def test_findings_never_missing_required_keys(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", json.dumps({"name": "demo", "license": "GPL-3.0"}))
    findings = df_security.license_scan(root, ["MIT"])
    for f in findings:
        assert set(f.keys()) == {"file", "package", "license", "rule"}
        assert f["rule"] in {"disallowed-license", "missing-license"}


def test_skips_git_dir(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join(".git", "node_modules", "sneaky", "package.json"),
        json.dumps({"name": "sneaky", "license": "GPL-3.0"}),
    )
    findings = df_security.license_scan(root, ["MIT"])
    assert findings == []


def test_clean_tree_no_manifests_no_findings(tmp_path):
    root = str(tmp_path)
    _write(root, "app.py", "def add(a, b):\n    return a + b\n")
    findings = df_security.license_scan(root, ["MIT"])
    assert findings == []


def test_non_utf8_pyproject_does_not_crash(tmp_path):
    # tomllib.load does a strict utf-8 decode first, so an invalid byte
    # raises UnicodeDecodeError (not TOMLDecodeError). license_scan must
    # NOT let that escape -- it falls through to the tolerant regex
    # fallback (errors="ignore") and returns instead of crashing the run.
    root = str(tmp_path)
    path = os.path.join(root, "pyproject.toml")
    with open(path, "wb") as f:
        f.write(b'[project]\nname = "demo"\nlicense = "MIT"\n# bad byte -> \xff\n')
    # Should not raise; the regex fallback still recovers the "MIT" license.
    findings = df_security.license_scan(root, ["Apache-2.0"])
    assert len(findings) == 1
    assert findings[0]["license"] == "MIT"
    # And a garbage-byte manifest with no recoverable license is simply benign.
    assert df_security.license_scan(root, ["MIT"]) == []


def test_non_utf8_pyproject_run_gates_completes(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    path = os.path.join(str(ws), "pyproject.toml")
    with open(path, "wb") as f:
        f.write(b'[project]\nname = "demo"\n# garbage byte \xff\xfe\nlicense = "MIT"\n')
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": ["license"],
        "strict_unavailable": True,
        "license": {"enabled": True, "allowlist": ["Apache-2.0"], "require_license": False},
    }
    # run_gates must complete normally (no traceback escaping) -- the
    # regex fallback still recovers "MIT", which is disallowed here.
    report = df_security.run_gates(str(ws), sec)
    assert report["checked"] is True
    assert report["gates"]["license"]["status"] == "fail"
    assert report["failed"] == ["license"]


def test_malformed_package_json_does_not_crash(tmp_path):
    # A package.json with invalid JSON / garbage bytes must be tolerated
    # (json.load raises JSONDecodeError, caught) -- no crash, no finding.
    root = str(tmp_path)
    path = os.path.join(root, "package.json")
    with open(path, "wb") as f:
        f.write(b'{"name": "demo", "license": "MIT" \xff not json at all')
    assert df_security.license_scan(root, ["Apache-2.0"]) == []


def test_non_utf8_dist_info_metadata_does_not_crash(tmp_path):
    # METADATA is read with errors="ignore"; a stray non-utf-8 byte must
    # not crash the scan.
    root = str(tmp_path)
    path = os.path.join(root, "site-packages", "foo-1.0.dist-info", "METADATA")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"Name: foo\nLicense: MIT\xff\n\ndescription\n")
    # Must not raise; the license line is still recoverable (byte dropped).
    findings = df_security.license_scan(root, ["Apache-2.0"])
    assert len(findings) == 1
    assert findings[0]["package"] == "foo"


# --- run_gates wiring ----------------------------------------------------


def test_run_gates_license_fails_when_disallowed_and_in_fail_on(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _write(str(ws), "package.json", json.dumps({"name": "demo", "license": "GPL-3.0"}))
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": ["license"],
        "strict_unavailable": True,
        "license": {"enabled": True, "allowlist": ["MIT"], "require_license": False},
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["license"]["status"] == "fail"
    assert report["failed"] == ["license"]
    assert report["gates"]["license"]["findings"]


def test_run_gates_license_clean_tree_passes(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _write(str(ws), "package.json", json.dumps({"name": "demo", "license": "MIT"}))
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": ["license"],
        "strict_unavailable": True,
        "license": {"enabled": True, "allowlist": ["MIT"], "require_license": False},
    }
    report = df_security.run_gates(str(ws), sec)
    assert report["gates"]["license"]["status"] == "pass"
    assert report["failed"] == []


def test_run_gates_license_disabled_no_gate_produced(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    _write(str(ws), "package.json", json.dumps({"name": "demo", "license": "GPL-3.0"}))
    sec = {
        "enabled": True,
        "secret_scan": False,
        "dangerous_scan": False,
        "sbom": False,
        "external": [],
        "fail_on": [],
        "strict_unavailable": True,
        "license": {"enabled": False, "allowlist": [], "require_license": False},
    }
    report = df_security.run_gates(str(ws), sec)
    assert "license" not in report["gates"]


def test_run_gates_no_license_key_at_all_back_compat(tmp_path):
    # M9 sec dicts never carried a "license" key at all -- run_gates must
    # not KeyError or otherwise choke on its absence.
    ws = tmp_path / "ws"
    ws.mkdir()
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
    assert "license" not in report["gates"]


# --- df_config: security_gates.license ----------------------------------


def test_absent_license_block_defaults_disabled(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"]["license"] == {
        "enabled": False,
        "allowlist": [],
        "require_license": False,
    }


def test_explicit_license_block_round_trips(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "license": {
                "enabled": True,
                "allowlist": ["MIT", "Apache-2.0"],
                "require_license": True,
            },
        },
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"]["license"] == {
        "enabled": True,
        "allowlist": ["MIT", "Apache-2.0"],
        "require_license": True,
    }


def test_license_enabled_non_bool_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "license": {"enabled": "yes"}}
    )
    with pytest.raises(df_config.ConfigError, match="license"):
        df_config.load_config(str(cr))


def test_license_allowlist_non_list_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "license": {"allowlist": "MIT"}}
    )
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


def test_license_allowlist_empty_string_entry_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "license": {"allowlist": ["MIT", ""]}}
    )
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


def test_license_require_license_non_bool_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, security_gates={"enabled": True, "license": {"require_license": "yes"}}
    )
    with pytest.raises(df_config.ConfigError, match="require_license"):
        df_config.load_config(str(cr))


def test_license_block_non_dict_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, security_gates={"enabled": True, "license": ["not", "a", "dict"]})
    with pytest.raises(df_config.ConfigError, match="license"):
        df_config.load_config(str(cr))


def test_fail_on_license_accepted(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "fail_on": ["license"],
            "license": {"enabled": True, "allowlist": ["MIT"]},
        },
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"]["fail_on"] == ["license"]


def test_external_name_license_collides_with_builtin_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr,
        security_gates={
            "enabled": True,
            "external": [{"name": "license", "cmd": ["true"]}],
        },
    )
    with pytest.raises(df_config.ConfigError, match="reserved"):
        df_config.load_config(str(cr))


def test_absent_security_gates_no_license_key(tmp_path):
    # Absent security_gates entirely -> cfg["_security"] == {"enabled":
    # False}, no "license" key at all (byte-identical to pre-M18 M9
    # behavior).
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_security"] == {"enabled": False}
