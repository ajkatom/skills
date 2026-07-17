import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import df_depcache  # noqa: E402


def _fake_pypi_fetcher(responses):
    """responses: dict url_substring -> (status, body_bytes). Matches by
    substring so tests don't need to construct exact PyPI URLs."""
    def fetcher(url, data, timeout_s):
        for sub, (status, body) in responses.items():
            if sub in url:
                return status, body
        raise AssertionError(f"unexpected url: {url}")
    return fetcher


def test_fetch_pypi_writes_wheel(tmp_path):
    meta = json.dumps({
        "urls": [
            {"packagetype": "bdist_wheel", "filename": "foo-1.2.3-py3-none-any.whl",
             "url": "https://files.pythonhosted.org/foo-1.2.3-py3-none-any.whl"},
        ]
    }).encode()
    fetcher = _fake_pypi_fetcher({
        "pypi.org/pypi/foo/1.2.3/json": (200, meta),
        "foo-1.2.3-py3-none-any.whl": (200, b"WHEELBYTES"),
    })
    n = df_depcache.fetch_pypi(
        [{"ecosystem": "PyPI", "name": "foo", "version": "1.2.3"}],
        str(tmp_path), fetcher=fetcher,
    )
    assert n == 1
    out = tmp_path / "pypi" / "foo-1.2.3-py3-none-any.whl"
    assert out.read_bytes() == b"WHEELBYTES"


def test_fetch_pypi_falls_back_to_sdist_when_no_wheel(tmp_path):
    meta = json.dumps({
        "urls": [
            {"packagetype": "sdist", "filename": "bar-2.0.0.tar.gz",
             "url": "https://files.pythonhosted.org/bar-2.0.0.tar.gz"},
        ]
    }).encode()
    fetcher = _fake_pypi_fetcher({
        "pypi.org/pypi/bar/2.0.0/json": (200, meta),
        "bar-2.0.0.tar.gz": (200, b"SDISTBYTES"),
    })
    n = df_depcache.fetch_pypi(
        [{"ecosystem": "PyPI", "name": "bar", "version": "2.0.0"}],
        str(tmp_path), fetcher=fetcher,
    )
    assert n == 1
    assert (tmp_path / "pypi" / "bar-2.0.0.tar.gz").read_bytes() == b"SDISTBYTES"


def test_fetch_pypi_raises_depcache_error_on_missing_package(tmp_path):
    fetcher = _fake_pypi_fetcher({"pypi.org/pypi/gone/9.9.9/json": (404, b"not found")})
    try:
        df_depcache.fetch_pypi(
            [{"ecosystem": "PyPI", "name": "gone", "version": "9.9.9"}],
            str(tmp_path), fetcher=fetcher,
        )
        assert False, "expected DepCacheError"
    except df_depcache.DepCacheError as e:
        assert "gone" in str(e)


def test_fetch_pypi_raises_depcache_error_when_no_wheel_or_sdist():
    meta = json.dumps({"urls": []}).encode()
    fetcher = _fake_pypi_fetcher({"pypi.org/pypi/empty/1.0.0/json": (200, meta)})
    try:
        df_depcache.fetch_pypi(
            [{"ecosystem": "PyPI", "name": "empty", "version": "1.0.0"}],
            "/tmp/unused-depcache-test", fetcher=fetcher,
        )
        assert False, "expected DepCacheError"
    except df_depcache.DepCacheError as e:
        assert "empty" in str(e)


def test_fetch_npm_seeds_cache_via_npm_cache_add(tmp_path):
    meta = json.dumps({
        "versions": {
            "9.9.9": {"dist": {"tarball": "https://registry.npmjs.org/leftpad/-/leftpad-9.9.9.tgz"}},
        }
    }).encode()
    fetcher = _fake_pypi_fetcher({
        "registry.npmjs.org/leftpad": (200, meta),
        "leftpad-9.9.9.tgz": (200, b"TARBALLBYTES"),
    })
    calls = []

    def fake_runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    n = df_depcache.fetch_npm(
        [{"ecosystem": "npm", "name": "leftpad", "version": "9.9.9"}],
        str(tmp_path), fetcher=fetcher, runner=fake_runner,
    )
    assert n == 1
    assert len(calls) == 1
    assert calls[0][0] == "npm"
    assert "cache" in calls[0] and "add" in calls[0]
    assert str(tmp_path / "npm-cache") in " ".join(calls[0])


def test_fetch_npm_raises_depcache_error_when_npm_cache_add_fails(tmp_path):
    meta = json.dumps({
        "versions": {"1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}},
    }).encode()
    fetcher = _fake_pypi_fetcher({
        "registry.npmjs.org/x": (200, meta),
        "x-1.0.0.tgz": (200, b"X"),
    })

    def failing_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="npm cache add failed")

    try:
        df_depcache.fetch_npm(
            [{"ecosystem": "npm", "name": "x", "version": "1.0.0"}],
            str(tmp_path), fetcher=fetcher, runner=failing_runner,
        )
        assert False, "expected DepCacheError"
    except df_depcache.DepCacheError as e:
        assert "x" in str(e)


def test_fetch_npm_raises_depcache_error_on_version_not_found(tmp_path):
    meta = json.dumps({"versions": {}}).encode()
    fetcher = _fake_pypi_fetcher({"registry.npmjs.org/y": (200, meta)})
    try:
        df_depcache.fetch_npm(
            [{"ecosystem": "npm", "name": "y", "version": "3.3.3"}],
            str(tmp_path), fetcher=fetcher, runner=lambda *a, **k: None,
        )
        assert False, "expected DepCacheError"
    except df_depcache.DepCacheError as e:
        assert "y" in str(e)


# --- Finding 1: rollback-on-failure (no partial state survives a raised call) ---

def test_fetch_pypi_rolls_back_files_written_this_call_on_later_failure(tmp_path):
    """pkg 1 of 2 succeeds and is written to disk; pkg 2 fails. The whole call
    must raise, AND the file written for pkg 1 during this call must be
    removed -- no partial state survives a raised DepCacheError."""
    meta_ok = json.dumps({
        "urls": [
            {"packagetype": "bdist_wheel", "filename": "foo-1.2.3-py3-none-any.whl",
             "url": "https://files.pythonhosted.org/foo-1.2.3-py3-none-any.whl"},
        ]
    }).encode()
    fetcher = _fake_pypi_fetcher({
        "pypi.org/pypi/foo/1.2.3/json": (200, meta_ok),
        "foo-1.2.3-py3-none-any.whl": (200, b"WHEELBYTES"),
        "pypi.org/pypi/gone/9.9.9/json": (404, b"not found"),
    })
    try:
        df_depcache.fetch_pypi(
            [
                {"ecosystem": "PyPI", "name": "foo", "version": "1.2.3"},
                {"ecosystem": "PyPI", "name": "gone", "version": "9.9.9"},
            ],
            str(tmp_path), fetcher=fetcher,
        )
        assert False, "expected DepCacheError"
    except df_depcache.DepCacheError as e:
        assert "gone" in str(e)
    assert not (tmp_path / "pypi" / "foo-1.2.3-py3-none-any.whl").exists()
    assert list((tmp_path / "pypi").iterdir()) == []


def test_fetch_npm_rolls_back_whole_cache_when_created_fresh_this_call(tmp_path):
    """dest_dir/npm-cache did not exist before this call. pkg 1 of 2 succeeds
    (npm cache add), pkg 2 fails (unknown version). Since the cache was
    created fresh by this call, the whole npm-cache dir must be torn down on
    failure -- no partial cache survives. The tmp tarball dir must also be
    cleaned up even though the loop failed mid-way."""
    meta_a = json.dumps({
        "versions": {"1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}
    }).encode()
    fetcher = _fake_pypi_fetcher({
        "registry.npmjs.org/a": (200, meta_a),
        "a-1.0.0.tgz": (200, b"A"),
        "registry.npmjs.org/b": (200, json.dumps({"versions": {}}).encode()),
    })

    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    try:
        df_depcache.fetch_npm(
            [
                {"ecosystem": "npm", "name": "a", "version": "1.0.0"},
                {"ecosystem": "npm", "name": "b", "version": "3.3.3"},
            ],
            str(tmp_path), fetcher=fetcher, runner=fake_runner,
        )
        assert False, "expected DepCacheError"
    except df_depcache.DepCacheError as e:
        assert "b" in str(e)
    assert not (tmp_path / "npm-cache").exists()
    assert not (tmp_path / "_npm-tarballs").exists()


def test_fetch_npm_preserves_preexisting_cache_and_reports_honest_partial_state(tmp_path):
    """dest_dir/npm-cache already existed before this call (an operator
    re-running fetch to add more packages). pkg 1 of 2 succeeds, pkg 2 fails.
    Since the cache pre-existed, it must NOT be wholesale deleted -- instead
    the raised DepCacheError must clearly say the cache may hold a partial
    addition from this call, and the pre-existing content must survive."""
    cache_dir = tmp_path / "npm-cache"
    cache_dir.mkdir()
    marker = cache_dir / "preexisting-marker.txt"
    marker.write_text("keep me")

    meta_a = json.dumps({
        "versions": {"1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}
    }).encode()
    fetcher = _fake_pypi_fetcher({
        "registry.npmjs.org/a": (200, meta_a),
        "a-1.0.0.tgz": (200, b"A"),
        "registry.npmjs.org/b": (200, json.dumps({"versions": {}}).encode()),
    })

    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    try:
        df_depcache.fetch_npm(
            [
                {"ecosystem": "npm", "name": "a", "version": "1.0.0"},
                {"ecosystem": "npm", "name": "b", "version": "3.3.3"},
            ],
            str(tmp_path), fetcher=fetcher, runner=fake_runner,
        )
        assert False, "expected DepCacheError"
    except df_depcache.DepCacheError as e:
        msg = str(e)
        assert "already existed" in msg
        assert "1 of 2" in msg
        assert "inspect" in msg
    assert marker.exists()
    assert marker.read_text() == "keep me"
    assert not (tmp_path / "_npm-tarballs").exists()


# --- Finding 2: foreign-ecosystem entries must be silently skipped, never fetched ---

def test_fetch_pypi_ignores_non_pypi_ecosystem_entries(tmp_path):
    def exploding_fetcher(url, data, timeout_s):
        raise AssertionError(f"fetch_pypi must not fetch for a non-PyPI entry, called with {url}")

    n = df_depcache.fetch_pypi(
        [{"ecosystem": "cargo", "name": "foo", "version": "1.0.0"}],
        str(tmp_path), fetcher=exploding_fetcher,
    )
    assert n == 0


def test_fetch_npm_ignores_non_npm_ecosystem_entries(tmp_path):
    def exploding_fetcher(url, data, timeout_s):
        raise AssertionError(f"fetch_npm must not fetch for a non-npm entry, called with {url}")

    def exploding_runner(argv, **kwargs):
        raise AssertionError("fetch_npm must not run npm cache add for a non-npm entry")

    n = df_depcache.fetch_npm(
        [{"ecosystem": "cargo", "name": "foo", "version": "1.0.0"}],
        str(tmp_path), fetcher=exploding_fetcher, runner=exploding_runner,
    )
    assert n == 0
