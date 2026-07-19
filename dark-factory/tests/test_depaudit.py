"""Tests for df_depaudit (M23 Task 1) -- OSV CVE dependency audit.

Covers `parse_installed` (manifest/installed-tree parsing, PINNED only,
never raises), `query_osv_api` (injectable fetcher -- vuln/none/error paths,
fail-closed, request body carries ONLY name/version/ecosystem, NEVER
raises), `load_snapshot`/`query_osv_snapshot` (offline matching against a
tiny hand-written OSV fixture snapshot -- enumerated versions, simple
ranges, and an unparseable range that must be FLAGGED not silently
missed -- and a proof that the offline path makes ZERO network calls), and
two live probes against the real OSV backends (skipif no network).
"""
import json
import os
import socket

import pytest

from df_depaudit import (
    DepAuditError,
    fetch_snapshot,
    load_snapshot,
    parse_installed,
    query_osv_api,
    query_osv_snapshot,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "osv_snapshot")


def _write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if isinstance(content, bytes):
        with open(path, "wb") as f:
            f.write(content)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    return path


def _keys(pkgs):
    return {(p["ecosystem"], p["name"], p["version"]) for p in pkgs}


# --- parse_installed --------------------------------------------------------


def test_requirements_txt_pinned_only(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "requirements.txt",
        "flask==2.0.1\nrequests>=2.0\n# a comment\n\nnumpy==1.2.3\n-e ./local\n",
    )
    keys = _keys(parse_installed(root))
    assert ("PyPI", "flask", "2.0.1") in keys
    assert ("PyPI", "numpy", "1.2.3") in keys
    assert not any(k[1] == "requests" for k in keys)


def test_package_json_exact_version_only_deps_and_devdeps(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "package.json",
        json.dumps(
            {
                "dependencies": {"left-pad": "1.3.0", "lodash": "^4.17.0"},
                "devDependencies": {"jest": "29.0.0", "eslint": "~8.0.0"},
            }
        ),
    )
    keys = _keys(parse_installed(root))
    assert ("npm", "left-pad", "1.3.0") in keys
    assert ("npm", "jest", "29.0.0") in keys
    assert not any(k[1] == "lodash" for k in keys)
    assert not any(k[1] == "eslint" for k in keys)


def test_package_json_range_and_wildcard_versions_skipped(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "package.json",
        json.dumps(
            {
                "dependencies": {
                    "a": "*",
                    "b": ">=1.0.0",
                    "c": "1.x",
                    "d": "latest",
                    "e": "workspace:*",
                }
            }
        ),
    )
    pkgs = parse_installed(root)
    assert pkgs == []


def test_pyproject_deps_best_effort_pinned_only(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "pyproject.toml",
        "[project]\n"
        'name = "demo"\n'
        "dependencies = [\n"
        '    "click==8.1.3",\n'
        '    "rich>=13.0",\n'
        "]\n",
    )
    keys = _keys(parse_installed(root))
    assert ("PyPI", "click", "8.1.3") in keys
    assert not any(k[1] == "rich" for k in keys)


def test_dist_info_dirs_yield_pypi_name_version(tmp_path):
    root = str(tmp_path)
    os.makedirs(os.path.join(root, "site-packages", "foo-1.2.3.dist-info"))
    pkgs = parse_installed(root)
    assert {"ecosystem": "PyPI", "name": "foo", "version": "1.2.3"} in pkgs


def test_node_modules_installed_exact_version(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("node_modules", "bar", "package.json"),
        json.dumps({"name": "bar", "version": "2.0.0"}),
    )
    pkgs = parse_installed(root)
    assert {"ecosystem": "npm", "name": "bar", "version": "2.0.0"} in pkgs


def test_node_modules_installed_range_version_skipped(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("node_modules", "baz", "package.json"),
        json.dumps({"name": "baz", "version": "^3.0.0"}),
    )
    pkgs = parse_installed(root)
    assert not any(p["name"] == "baz" for p in pkgs)


def test_scoped_node_modules_package(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        os.path.join("node_modules", "@scope", "pkg", "package.json"),
        json.dumps({"name": "@scope/pkg", "version": "1.0.0"}),
    )
    pkgs = parse_installed(root)
    assert {"ecosystem": "npm", "name": "@scope/pkg", "version": "1.0.0"} in pkgs


def test_malformed_package_json_skipped_not_raised(tmp_path):
    root = str(tmp_path)
    _write(root, "package.json", "{not valid json")
    pkgs = parse_installed(root)  # must not raise
    assert isinstance(pkgs, list)


def test_malformed_requirements_txt_skipped_not_raised(tmp_path):
    root = str(tmp_path)
    _write(root, "requirements.txt", "!!! === not a real line\n")
    pkgs = parse_installed(root)
    assert pkgs == []


def test_non_utf8_requirements_txt_does_not_crash(tmp_path):
    root = str(tmp_path)
    path = os.path.join(root, "requirements.txt")
    with open(path, "wb") as f:
        f.write(b"flask==2.0.1\n\xff\xfe garbage line\n")
    keys = _keys(parse_installed(root))
    assert ("PyPI", "flask", "2.0.1") in keys


def test_non_utf8_package_json_does_not_crash(tmp_path):
    root = str(tmp_path)
    path = os.path.join(root, "package.json")
    with open(path, "wb") as f:
        f.write(b'{"dependencies": {"a": "1.0.0"}}\xff\xfe')
    pkgs = parse_installed(root)  # must not raise
    assert isinstance(pkgs, list)


def test_missing_manifests_empty_list(tmp_path):
    root = str(tmp_path)
    _write(root, "app.py", "print('hello')\n")
    assert parse_installed(root) == []


def test_deduped_and_sorted(tmp_path):
    root = str(tmp_path)
    _write(root, "requirements.txt", "flask==2.0.1\nflask==2.0.1\nalpha==1.0\n")
    pkgs = parse_installed(root)
    keys = [(p["ecosystem"], p["name"], p["version"]) for p in pkgs]
    assert len(keys) == len(set(keys))
    assert keys == sorted(keys)


def test_skips_git_dir(tmp_path):
    root = str(tmp_path)
    os.makedirs(os.path.join(root, ".git", "node_modules", "sneaky"))
    _write(
        root,
        os.path.join(".git", "node_modules", "sneaky", "package.json"),
        json.dumps({"name": "sneaky", "version": "1.0.0"}),
    )
    pkgs = parse_installed(root)
    assert not any(p["name"] == "sneaky" for p in pkgs)


def test_symlinked_top_level_manifest_skipped(tmp_path):
    """A symlinked requirements.txt must not be followed off-tree (matches
    df_security._walk_files discipline)."""
    root = tmp_path / "root"
    root.mkdir()
    target = tmp_path / "outside_requirements.txt"
    target.write_text("evil==6.6.6\n", encoding="utf-8")
    os.symlink(str(target), str(root / "requirements.txt"))
    pkgs = parse_installed(str(root))
    assert not any(p["name"] == "evil" for p in pkgs)


def test_symlinked_node_modules_manifest_skipped(tmp_path):
    """A symlinked node_modules/<pkg>/package.json must not be followed."""
    root = tmp_path / "root"
    pkg_dir = root / "node_modules" / "evilpkg"
    pkg_dir.mkdir(parents=True)
    target = tmp_path / "outside_package.json"
    target.write_text(json.dumps({"name": "evilpkg", "version": "6.6.6"}), encoding="utf-8")
    os.symlink(str(target), str(pkg_dir / "package.json"))
    pkgs = parse_installed(str(root))
    assert not any(p["name"] == "evilpkg" for p in pkgs)


# --- query_osv_api -----------------------------------------------------------


def test_query_osv_api_vuln_found_returns_id():
    calls = []

    def fake_fetcher(url, data, timeout_s):
        calls.append((url, data, timeout_s))
        body = json.dumps({"vulns": [{"id": "GHSA-xxxx", "summary": "bad"}]}).encode()
        return 200, body

    pkgs = [{"ecosystem": "PyPI", "name": "flask", "version": "0.1"}]
    result = query_osv_api(pkgs, fetcher=fake_fetcher)

    assert result["source"] == "osv-api"
    assert result["unavailable"] is False
    assert result["results"][0]["vulns"][0]["id"] == "GHSA-xxxx"

    # request body carries ONLY name/version/ecosystem
    assert len(calls) == 1
    url, data, timeout_s = calls[0]
    assert url.startswith("https://api.osv.dev/v1/query")
    sent = json.loads(data)
    assert set(sent.keys()) == {"version", "package"}
    assert sent["version"] == "0.1"
    assert set(sent["package"].keys()) == {"name", "ecosystem"}
    assert sent["package"] == {"name": "flask", "ecosystem": "PyPI"}


def test_query_osv_api_no_vuln_empty_list():
    def fake_fetcher(url, data, timeout_s):
        return 200, json.dumps({}).encode()

    pkgs = [{"ecosystem": "PyPI", "name": "flask", "version": "9.9.9"}]
    result = query_osv_api(pkgs, fetcher=fake_fetcher)
    assert result["unavailable"] is False
    assert result["results"][0]["vulns"] == []


def test_query_osv_api_fetcher_raises_is_unavailable_never_raises():
    def fake_fetcher(url, data, timeout_s):
        raise OSError("connection refused")

    pkgs = [{"ecosystem": "PyPI", "name": "flask", "version": "1.0"}]
    result = query_osv_api(pkgs, fetcher=fake_fetcher)  # must not raise
    assert result["unavailable"] is True
    assert result["source"] == "osv-api"
    assert result["reason"]


def test_query_osv_api_http_500_is_unavailable():
    def fake_fetcher(url, data, timeout_s):
        return 500, b"internal server error"

    pkgs = [{"ecosystem": "PyPI", "name": "flask", "version": "1.0"}]
    result = query_osv_api(pkgs, fetcher=fake_fetcher)
    assert result["unavailable"] is True


def test_query_osv_api_bad_json_is_unavailable():
    def fake_fetcher(url, data, timeout_s):
        return 200, b"not json at all"

    pkgs = [{"ecosystem": "PyPI", "name": "flask", "version": "1.0"}]
    result = query_osv_api(pkgs, fetcher=fake_fetcher)
    assert result["unavailable"] is True


def test_query_osv_api_one_bad_pkg_fails_whole_batch():
    calls = {"n": 0}

    def fake_fetcher(url, data, timeout_s):
        calls["n"] += 1
        if calls["n"] == 1:
            return 200, json.dumps({}).encode()
        raise OSError("boom on second package")

    pkgs = [
        {"ecosystem": "PyPI", "name": "ok-pkg", "version": "1.0"},
        {"ecosystem": "PyPI", "name": "bad-pkg", "version": "1.0"},
    ]
    result = query_osv_api(pkgs, fetcher=fake_fetcher)
    assert result["unavailable"] is True


def test_query_osv_api_never_raises_on_unexpected_exception():
    def fake_fetcher(url, data, timeout_s):
        raise ValueError("something weird")

    pkgs = [{"ecosystem": "PyPI", "name": "flask", "version": "1.0"}]
    result = query_osv_api(pkgs, fetcher=fake_fetcher)  # must not raise
    assert result["unavailable"] is True


# --- load_snapshot -----------------------------------------------------------


def test_load_snapshot_missing_dir_raises(tmp_path):
    with pytest.raises(DepAuditError):
        load_snapshot(str(tmp_path / "does-not-exist"))


def test_load_snapshot_empty_dir_raises(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(DepAuditError):
        load_snapshot(str(empty))


def test_load_snapshot_all_corrupt_records_raises(tmp_path):
    d = tmp_path / "corrupt"
    (d / "PyPI").mkdir(parents=True)
    (d / "PyPI" / "bad.json").write_text("{not valid json", encoding="utf-8")
    with pytest.raises(DepAuditError):
        load_snapshot(str(d))


def test_load_snapshot_skips_one_bad_record_not_crash(tmp_path):
    d = tmp_path / "mixed"
    (d / "PyPI").mkdir(parents=True)
    (d / "PyPI" / "bad.json").write_text("{not valid json", encoding="utf-8")
    (d / "PyPI" / "good.json").write_text(
        json.dumps(
            {
                "id": "GHSA-good",
                "affected": [{"package": {"ecosystem": "PyPI", "name": "goodpkg"}, "versions": ["1.0.0"]}],
            }
        ),
        encoding="utf-8",
    )
    snapshot = load_snapshot(str(d))  # must not raise
    result = query_osv_snapshot(
        [{"ecosystem": "PyPI", "name": "goodpkg", "version": "1.0.0"}], snapshot
    )
    assert any(v["id"] == "GHSA-good" for v in result["results"][0]["vulns"])


def test_load_snapshot_fixture_dir_loads():
    snapshot = load_snapshot(FIXTURE_DIR)
    assert isinstance(snapshot, dict)
    assert ("PyPI", "demo-pkg") in snapshot


# --- query_osv_snapshot -------------------------------------------------------


def test_query_osv_snapshot_enumerated_version_flagged():
    snapshot = load_snapshot(FIXTURE_DIR)
    pkgs = [{"ecosystem": "PyPI", "name": "demo-pkg", "version": "1.0.0"}]
    result = query_osv_snapshot(pkgs, snapshot)
    assert result["source"] == "osv-snapshot"
    assert result["unavailable"] is False
    vulns = result["results"][0]["vulns"]
    assert any(v["id"] == "GHSA-enum-demo" for v in vulns)


def test_query_osv_snapshot_safe_version_empty():
    snapshot = load_snapshot(FIXTURE_DIR)
    pkgs = [{"ecosystem": "PyPI", "name": "demo-pkg", "version": "9.9.9"}]
    result = query_osv_snapshot(pkgs, snapshot)
    assert result["results"][0]["vulns"] == []


def test_query_osv_snapshot_simple_range_definite_match_no_uncertain_note():
    snapshot = load_snapshot(FIXTURE_DIR)
    pkgs = [{"ecosystem": "PyPI", "name": "rangepkg", "version": "1.5.0"}]
    result = query_osv_snapshot(pkgs, snapshot)
    vulns = result["results"][0]["vulns"]
    match = [v for v in vulns if v["id"] == "GHSA-range-demo"]
    assert len(match) == 1
    assert "note" not in match[0]


def test_query_osv_snapshot_simple_range_fixed_version_safe():
    snapshot = load_snapshot(FIXTURE_DIR)
    pkgs = [{"ecosystem": "PyPI", "name": "rangepkg", "version": "2.0.0"}]
    result = query_osv_snapshot(pkgs, snapshot)
    assert result["results"][0]["vulns"] == []


def test_query_osv_snapshot_unparseable_range_flagged_uncertain():
    snapshot = load_snapshot(FIXTURE_DIR)
    pkgs = [{"ecosystem": "PyPI", "name": "fuzzypkg", "version": "1.0.0"}]
    result = query_osv_snapshot(pkgs, snapshot)
    vulns = result["results"][0]["vulns"]
    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-uncertain-demo"
    assert vulns[0].get("note") == "range-uncertain"


def test_query_osv_snapshot_empty_events_range_flagged_uncertain():
    """A name-matching record whose ONLY range has empty/malformed events
    (no enumerated versions either) must be FLAGGED range-uncertain, never
    silently dropped -- a missed vuln is the dangerous direction."""
    snapshot = load_snapshot(FIXTURE_DIR)
    pkgs = [{"ecosystem": "PyPI", "name": "weirdpkg", "version": "1.0.0"}]
    result = query_osv_snapshot(pkgs, snapshot)
    vulns = result["results"][0]["vulns"]
    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-emptyrange-demo"
    assert vulns[0].get("note") == "range-uncertain"


def test_query_osv_snapshot_malformed_non_dict_range_flagged_uncertain():
    """A name-matching record whose ranges[] entry isn't even a dict must be
    FLAGGED, not dropped."""
    snapshot = {
        ("PyPI", "brokenpkg"): [
            {
                "id": "GHSA-broken",
                "affected": [
                    {"package": {"ecosystem": "PyPI", "name": "brokenpkg"}, "ranges": ["not-a-dict"]}
                ],
            }
        ]
    }
    pkgs = [{"ecosystem": "PyPI", "name": "brokenpkg", "version": "1.0.0"}]
    result = query_osv_snapshot(pkgs, snapshot)
    vulns = result["results"][0]["vulns"]
    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-broken"
    assert vulns[0].get("note") == "range-uncertain"


def test_query_osv_snapshot_unknown_package_no_match():
    snapshot = load_snapshot(FIXTURE_DIR)
    pkgs = [{"ecosystem": "PyPI", "name": "totally-unknown-pkg", "version": "1.0.0"}]
    result = query_osv_snapshot(pkgs, snapshot)
    assert result["results"][0]["vulns"] == []


def test_query_osv_snapshot_makes_no_network_call(monkeypatch):
    """Belt-and-suspenders proof: even if something inside query_osv_snapshot
    tried to reach the network via the stdlib default transport, it would
    blow up here -- and it must not, since the function takes no fetcher and
    performs no I/O beyond the in-memory snapshot dict."""

    def _boom(*args, **kwargs):
        raise AssertionError("query_osv_snapshot must never touch the network")

    monkeypatch.setattr("urllib.request.urlopen", _boom)

    snapshot = load_snapshot(FIXTURE_DIR)
    pkgs = [
        {"ecosystem": "PyPI", "name": "demo-pkg", "version": "1.0.0"},
        {"ecosystem": "PyPI", "name": "rangepkg", "version": "1.5.0"},
        {"ecosystem": "PyPI", "name": "fuzzypkg", "version": "1.0.0"},
    ]
    result = query_osv_snapshot(pkgs, snapshot)  # must not raise
    assert result["unavailable"] is False


# --- live probes (skipif no network) ----------------------------------------


def _network_available() -> bool:
    try:
        with socket.create_connection(("api.osv.dev", 443), timeout=3):
            return True
    except OSError:
        return False


# M47 condition #10: only probe (and thus only reach api.osv.dev) when the
# opt-in DF_ALLOW_NETWORK_TESTS flag is set. A default `pytest` never makes this
# external connection -- not even at collection time -- so the suite is hermetic;
# the live OSV probes are still exercised in the opt-in/CI run.
NETWORK_LIVE = bool(os.environ.get("DF_ALLOW_NETWORK_TESTS")) and _network_available()


@pytest.mark.skipif(not NETWORK_LIVE,
                    reason="live external OSV probe; set DF_ALLOW_NETWORK_TESTS=1")
def test_live_query_osv_api_jinja2_2_4_1_has_vulns():
    pkgs = [{"ecosystem": "PyPI", "name": "jinja2", "version": "2.4.1"}]
    result = query_osv_api(pkgs)
    assert result["unavailable"] is False
    assert result["source"] == "osv-api"
    assert len(result["results"][0]["vulns"]) >= 1


@pytest.mark.skipif(not NETWORK_LIVE, reason="network unavailable")
def test_live_fetch_snapshot_then_offline_round_trip(tmp_path):
    dest = str(tmp_path / "snapshot")
    count = fetch_snapshot("PyPI", dest, timeout_s=300)
    assert count > 0

    snapshot = load_snapshot(dest)
    pkgs = [{"ecosystem": "PyPI", "name": "jinja2", "version": "2.4.1"}]
    result = query_osv_snapshot(pkgs, snapshot)
    assert result["unavailable"] is False
    assert len(result["results"][0]["vulns"]) >= 1
