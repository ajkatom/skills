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
