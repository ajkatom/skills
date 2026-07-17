# dark-factory M26 — Read-only pinned dependency cache (spec §7.3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close spec §7.3 — a "read-only pinned dependency proxy/cache, no direct registry/DNS" for hardened/enterprise builders. Today a hardened builder runs with `--network none` (or a wide-open `bridge`) and cannot `pip install`/`npm install` anything; it must have every dependency pre-vendored into the workspace by hand. This milestone gives the operator a one-time, host-side provisioning step (`df_depcache.py fetch`) that downloads the EXACT pinned versions a spec declares into a local directory, which the supervisor then bind-mounts **read-only** into the hardened/enterprise container (reusing the existing `ro_mounts` mechanism — no new network surface). Inside the container, `pip install --no-index --find-links=<cache>/pypi` and `npm install --offline` (pointed at a pre-seeded local npm cache dir) resolve entirely from the mount. "No direct registry/DNS" holds **by construction**: the cache is a filesystem mount, not a live process or proxy — nothing to reach, nothing to misconfigure into an open egress path.

**Architecture:** `df_depcache.py` (new, stdlib-only) reuses `df_depaudit.parse_installed()` to discover pinned `{ecosystem,name,version}` triples from a source directory, then `fetch_pypi` (PyPI JSON API → wheel/sdist download, mirrors `df_depaudit.fetch_snapshot`'s injectable-fetcher + fail-closed discipline) and `fetch_npm` (npm registry JSON API for the tarball URL, download, then `npm cache add <tarball>` via a subprocess to seed a real npm offline cache — npm has no flat-dir equivalent to pip's `--find-links`, so provisioning uses npm's own cache format). `df_config.py` gains an optional `hardened.dep_cache_dir` field (validated: absolute path, must exist as a directory at config-load time — fail-closed, never a silently-ignored bad pointer). `supervisor.py` mounts it into the SAME `ro_mounts` list the adapter directory already uses (both the `hardened` and `enterprise` branches), with the same `_disjoint`-vs-control-root TOCTOU re-check, and sets non-secret env vars (`PIP_NO_INDEX`, `PIP_FIND_LINKS`, `npm_config_cache`, `npm_config_offline`) via the existing `env=` argv channel.

**Tech Stack:** Python stdlib (`urllib`, `json`, `subprocess`). `npm` CLI required on the **operator's host** at provisioning time only (never inside the container, never at build time). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **No new network surface at build time.** The cache is consumed as a read-only bind mount, identical mechanism to the existing adapter-directory mount (`df_container.build_argv`'s `ro_mounts`). Nothing new listens on a port; nothing new is reachable from inside the container.
- **Fail-closed on a bad/missing cache pointer.** `hardened.dep_cache_dir` configured but not an existing directory → `ConfigError` at config load, never a silent skip or a build-time surprise.
- **`fetch` is the one deliberate, operator-run network op** — never called during a build, mirrors `df_depaudit.fetch_snapshot`'s docstring discipline exactly.
- **Never leak nothing secret here** — there is no credential in this milestone at all (PyPI/npm public registries, no auth), so no redaction concerns; still never print full URLs with query strings that could be sensitive (there are none) and never log package contents.
- **Reuse, don't reimplement:** discovering pinned packages reuses `df_depaudit.parse_installed`, not a new parser.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_depcache.py     # Task 1 — fetch_pypi, fetch_npm, CLI `main()`
    df_config.py        # Task 2 — hardened.dep_cache_dir validation
    supervisor.py        # Task 3 — ro_mounts + env wiring at hardened/enterprise
  references/
    hardened.md          # Task 3 — dep-cache section
    config-reference.md  # Task 3 — hardened.dep_cache_dir row
  tests/
    test_depcache.py     # Task 1
    test_config.py        # Task 2 (extend)
    test_supervisor_container.py  # Task 3 (extend, or new file if none exists — check first)
```

---

### Task 1: `df_depcache.py` — operator-run provisioning (fetch_pypi, fetch_npm)

**Files:**
- Create: `dark-factory/scripts/df_depcache.py`
- Test: `dark-factory/tests/test_depcache.py`

**Interfaces:**
- Consumes: `df_depaudit.parse_installed(root) -> [{ecosystem,name,version}]` (existing, unchanged).
- Produces: `fetch_pypi(pkgs, dest_dir, *, fetcher=_urlopen_fetch, timeout_s=60) -> int` (count written, writes `.whl`/`.tar.gz` files under `dest_dir/pypi/`), `fetch_npm(pkgs, dest_dir, *, fetcher=_urlopen_fetch, npm_cmd=("npm",), timeout_s=60, runner=subprocess.run) -> int` (count written, seeds an npm cache dir at `dest_dir/npm-cache/` via `npm cache add <tarball> --cache <dest_dir>/npm-cache`), `class DepCacheError(RuntimeError)`.

- [ ] **Step 1 (TDD):** Write `dark-factory/tests/test_depcache.py`:

```python
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
```

- [ ] **Step 2:** Run: `.venv/bin/python -m pytest dark-factory/tests/test_depcache.py -v`
  Expected: FAIL (`ModuleNotFoundError: No module named 'df_depcache'`)

- [ ] **Step 3:** Implement `dark-factory/scripts/df_depcache.py`:

```python
"""Read-only pinned dependency cache — operator-run provisioning (dark-factory
M26, spec §7.3). Stdlib only (urllib, json, subprocess).

`fetch_pypi(pkgs, dest_dir, ...)` and `fetch_npm(pkgs, dest_dir, ...)` are the
ONE deliberate, operator-run network op for this milestone (mirrors
df_depaudit.fetch_snapshot's docstring discipline) -- NEVER called during a
build. They download the EXACT pinned version of each package and write it
into dest_dir so the supervisor can bind-mount dest_dir READ-ONLY into the
hardened/enterprise builder container (see supervisor.py, df_container.py's
existing ro_mounts mechanism -- no new network surface is introduced; the
cache is consumed as a filesystem mount, not a live proxy).

PyPI: fetch_pypi writes wheels (preferred) or sdists to dest_dir/pypi/ as
flat files -- pip's `--no-index --find-links=<dir>` resolves directly against
a flat directory of package files, no index server needed.

npm: fetch_npm has no flat-dir equivalent (npm's installer expects its own
content-addressed cache format), so it downloads each pinned tarball and runs
`npm cache add <tarball> --cache <dest_dir>/npm-cache` (a LOCAL subprocess,
operator-host only) to seed a real npm offline cache at dest_dir/npm-cache/;
the builder container is then pointed at that cache dir with
`npm config set offline true` (see supervisor.py wiring). npm CLI is required
on the operator's host for this step only -- never inside the container,
never at build time.

ANY failure (fetcher raises, non-200, malformed JSON, no wheel/sdist found,
npm cache add fails) raises DepCacheError immediately -- fail-closed, no
partial/silent success. Each of fetch_pypi/fetch_npm accepts an injectable
`fetcher` (same shape as df_depaudit's: `fetcher(url, data, timeout_s) ->
(status, body_bytes)`) so tests make zero real network calls.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import df_depaudit  # noqa: E402


class DepCacheError(RuntimeError):
    """Raised by fetch_pypi/fetch_npm on any failure to provision a pinned
    package -- never a silent partial cache."""


def _urlopen_fetch(url: str, data, timeout_s: int):
    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def fetch_pypi(pkgs, dest_dir, *, fetcher=_urlopen_fetch, timeout_s: int = 60) -> int:
    """Download the exact pinned wheel (preferred) or sdist for each PyPI
    package in pkgs (`[{ecosystem,name,version}]`, ecosystem=="PyPI" entries
    only -- others are ignored) into dest_dir/pypi/. Raises DepCacheError on
    any failure for any package -- fail closed, no partial cache silently
    accepted. Returns the count written."""
    out_dir = os.path.join(dest_dir, "pypi")
    os.makedirs(out_dir, exist_ok=True)
    count = 0
    for pkg in pkgs:
        if pkg.get("ecosystem") != "PyPI":
            continue
        name, version = pkg["name"], pkg["version"]
        meta_url = f"https://pypi.org/pypi/{name}/{version}/json"
        try:
            status, body = fetcher(meta_url, None, timeout_s)
            if status != 200:
                raise DepCacheError(f"pypi metadata fetch failed for {name}=={version}: HTTP {status}")
            data = json.loads(body)
        except DepCacheError:
            raise
        except Exception as e:
            raise DepCacheError(f"pypi metadata fetch failed for {name}=={version}: {e}") from None

        urls = data.get("urls") if isinstance(data, dict) else None
        chosen = None
        if isinstance(urls, list):
            for u in urls:
                if isinstance(u, dict) and u.get("packagetype") == "bdist_wheel":
                    chosen = u
                    break
            if chosen is None:
                for u in urls:
                    if isinstance(u, dict) and u.get("packagetype") == "sdist":
                        chosen = u
                        break
        if chosen is None:
            raise DepCacheError(f"no wheel or sdist found for {name}=={version}")

        filename = chosen.get("filename")
        dl_url = chosen.get("url")
        if not filename or not dl_url:
            raise DepCacheError(f"malformed pypi release metadata for {name}=={version}")
        try:
            status, body = fetcher(dl_url, None, timeout_s)
            if status != 200:
                raise DepCacheError(f"pypi download failed for {name}=={version}: HTTP {status}")
        except DepCacheError:
            raise
        except Exception as e:
            raise DepCacheError(f"pypi download failed for {name}=={version}: {e}") from None

        # basename only -- never trust a path component from remote metadata
        safe_name = os.path.basename(filename)
        with open(os.path.join(out_dir, safe_name), "wb") as f:
            f.write(body)
        count += 1
    return count


def fetch_npm(pkgs, dest_dir, *, fetcher=_urlopen_fetch, npm_cmd=("npm",),
              timeout_s: int = 60, runner=subprocess.run) -> int:
    """Download the exact pinned tarball for each npm package in pkgs
    (ecosystem=="npm" entries only) and seed dest_dir/npm-cache/ via
    `npm cache add <tarball> --cache <dest_dir>/npm-cache` (operator-host
    subprocess; requires npm CLI on the operator's host, never inside the
    container). Raises DepCacheError on any failure. Returns the count
    seeded."""
    tmp_dir = os.path.join(dest_dir, "_npm-tarballs")
    cache_dir = os.path.join(dest_dir, "npm-cache")
    os.makedirs(tmp_dir, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)
    count = 0
    for pkg in pkgs:
        if pkg.get("ecosystem") != "npm":
            continue
        name, version = pkg["name"], pkg["version"]
        meta_url = f"https://registry.npmjs.org/{name}"
        try:
            status, body = fetcher(meta_url, None, timeout_s)
            if status != 200:
                raise DepCacheError(f"npm metadata fetch failed for {name}@{version}: HTTP {status}")
            data = json.loads(body)
        except DepCacheError:
            raise
        except Exception as e:
            raise DepCacheError(f"npm metadata fetch failed for {name}@{version}: {e}") from None

        versions = data.get("versions") if isinstance(data, dict) else None
        entry = versions.get(version) if isinstance(versions, dict) else None
        tarball = None
        if isinstance(entry, dict):
            dist = entry.get("dist")
            if isinstance(dist, dict):
                tarball = dist.get("tarball")
        if not tarball:
            raise DepCacheError(f"npm registry has no tarball for {name}@{version}")

        try:
            status, body = fetcher(tarball, None, timeout_s)
            if status != 200:
                raise DepCacheError(f"npm tarball download failed for {name}@{version}: HTTP {status}")
        except DepCacheError:
            raise
        except Exception as e:
            raise DepCacheError(f"npm tarball download failed for {name}@{version}: {e}") from None

        safe_name = os.path.basename(f"{name.replace('/', '-')}-{version}.tgz")
        tarball_path = os.path.join(tmp_dir, safe_name)
        with open(tarball_path, "wb") as f:
            f.write(body)

        argv = list(npm_cmd) + ["cache", "add", tarball_path, "--cache", cache_dir]
        try:
            proc = runner(argv, capture_output=True, text=True, timeout=timeout_s)
        except Exception as e:
            raise DepCacheError(f"npm cache add failed for {name}@{version}: {e}") from None
        if proc.returncode != 0:
            raise DepCacheError(
                f"npm cache add failed for {name}@{version}: "
                f"{(proc.stderr or proc.stdout or '')[:500]}"
            )
        count += 1
    shutil.rmtree(tmp_dir, ignore_errors=True)
    return count


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", required=True,
                     help="artifact/spec root to scan for pinned deps (df_depaudit.parse_installed)")
    ap.add_argument("--dest", required=True, help="cache directory to populate")
    args = ap.parse_args()

    pkgs = df_depaudit.parse_installed(args.source)
    n_pypi = fetch_pypi(pkgs, args.dest)
    n_npm = fetch_npm(pkgs, args.dest)
    print(f"df_depcache: fetched {n_pypi} PyPI package(s), seeded {n_npm} npm package(s) into {args.dest}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4:** Run: `.venv/bin/python -m pytest dark-factory/tests/test_depcache.py -v`
  Expected: PASS (7 passed)

- [ ] **Step 5:** Commit:

```bash
git add dark-factory/scripts/df_depcache.py dark-factory/tests/test_depcache.py
git commit -m "feat(dark-factory): df_depcache — operator-run pinned dependency cache provisioning (§7.3 Task 1)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: `df_config.py` — `hardened.dep_cache_dir` field

**Files:**
- Modify: `dark-factory/scripts/df_config.py` (near the existing `hardened` block validation, ~line 151-178; injection point ~line 980)
- Test: `dark-factory/tests/test_config.py` (extend — read the file first to match existing test style/fixtures for the `hardened` block before adding)

**Interfaces:**
- Consumes: nothing new (pure config validation).
- Produces: `cfg["_container"]["dep_cache_dir"]` — `None` when not configured, else the validated absolute directory path string. Read by supervisor.py Task 3.

- [ ] **Step 1:** Read `dark-factory/tests/test_config.py` and find the existing tests for the `hardened` block (search for `hardened.image` / `hardened.network` / `c_image` / `_container`) to copy their exact fixture/config-building helper pattern.

- [ ] **Step 2 (TDD):** Add to `dark-factory/tests/test_config.py`, using whatever helper the existing hardened-block tests use to build a minimal valid `assurance: hardened` config dict (do not invent a new one — reuse the existing helper found in Step 1):

```python
def test_dep_cache_dir_valid_directory_accepted(tmp_path):
    cache_dir = tmp_path / "depcache"
    cache_dir.mkdir()
    raw = _minimal_hardened_config()  # use the actual existing helper name from Step 1
    raw["hardened"]["dep_cache_dir"] = str(cache_dir)
    cfg = df_config.load_config(raw, control_root=str(tmp_path / "cr"))
    assert cfg["_container"]["dep_cache_dir"] == os.path.realpath(str(cache_dir))


def test_dep_cache_dir_absent_defaults_to_none(tmp_path):
    raw = _minimal_hardened_config()
    cfg = df_config.load_config(raw, control_root=str(tmp_path / "cr"))
    assert cfg["_container"]["dep_cache_dir"] is None


def test_dep_cache_dir_missing_directory_rejected(tmp_path):
    raw = _minimal_hardened_config()
    raw["hardened"]["dep_cache_dir"] = str(tmp_path / "does-not-exist")
    with pytest.raises(df_config.ConfigError, match="dep_cache_dir"):
        df_config.load_config(raw, control_root=str(tmp_path / "cr"))


def test_dep_cache_dir_not_a_directory_rejected(tmp_path):
    f = tmp_path / "notadir"
    f.write_text("x")
    raw = _minimal_hardened_config()
    raw["hardened"]["dep_cache_dir"] = str(f)
    with pytest.raises(df_config.ConfigError, match="dep_cache_dir"):
        df_config.load_config(raw, control_root=str(tmp_path / "cr"))


def test_dep_cache_dir_non_string_rejected(tmp_path):
    raw = _minimal_hardened_config()
    raw["hardened"]["dep_cache_dir"] = 123
    with pytest.raises(df_config.ConfigError, match="dep_cache_dir"):
        df_config.load_config(raw, control_root=str(tmp_path / "cr"))
```

  (Adjust the exact `load_config` call signature / helper names to match what Step 1's file actually uses — the existing hardened-block tests are the ground truth for call shape, not this snippet.)

- [ ] **Step 3:** Run the new tests, confirm they FAIL with `KeyError: 'dep_cache_dir'` or similar (the field doesn't exist yet).

- [ ] **Step 4:** In `df_config.py`, right after the existing `c_pids` validation (~line 177), add:

```python
    c_dep_cache_dir = hardened_raw.get("dep_cache_dir")
    if c_dep_cache_dir is not None:
        if not isinstance(c_dep_cache_dir, str) or not c_dep_cache_dir:
            raise ConfigError("hardened.dep_cache_dir must be a non-empty string")
        if not os.path.isdir(c_dep_cache_dir):
            raise ConfigError(
                f"hardened.dep_cache_dir does not exist or is not a directory: "
                f"{c_dep_cache_dir!r}"
            )
        c_dep_cache_dir = os.path.realpath(c_dep_cache_dir)
```

  Then in the `cfg["_container"] = {...}` construction (~line 980), add `"dep_cache_dir": c_dep_cache_dir,` alongside the existing `"image"`/`"network"`/`"memory"`/`"pids"` keys.

- [ ] **Step 5:** Run: `.venv/bin/python -m pytest dark-factory/tests/test_config.py -v`
  Expected: PASS (all, including the 5 new tests)

- [ ] **Step 6:** Run full suite: `.venv/bin/python -m pytest dark-factory/tests -q`
  Expected: all green, no regressions (existing `_container` dict construction/consumers must tolerate the new key — grep `cfg["_container"]` / `c["dep_cache_dir"]` usages if any test asserts an exact dict equality and needs updating for the new key).

- [ ] **Step 7:** Commit:

```bash
git add dark-factory/scripts/df_config.py dark-factory/tests/test_config.py
git commit -m "feat(dark-factory): hardened.dep_cache_dir config field (§7.3 Task 2)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: supervisor.py wiring (ro_mounts + env) + e2e proof + docs

**Files:**
- Modify: `dark-factory/scripts/supervisor.py` (both the `effective == "hardened"` branch ~line 1898-1925 and the `effective == "enterprise"` branch ~line 1926-1957)
- Modify: `dark-factory/references/hardened.md`, `dark-factory/references/config-reference.md`
- Test: extend whichever existing test file covers hardened container argv construction (search `test_*.py` for `build_argv` / `ro_mounts=\[adapter_ro_dir\]` to find it — read it first)

**Interfaces:**
- Consumes: `cfg["_container"]["dep_cache_dir"]` (Task 2, `None` or a realpath string).
- Produces: when set, `df_container.build_argv`/`build_enterprise_argv` is called with `ro_mounts=[adapter_ro_dir, dep_cache_dir]` and `env` merged with `{"PIP_NO_INDEX": "1", "PIP_FIND_LINKS": f"{dep_cache_dir}/pypi", "npm_config_cache": f"{dep_cache_dir}/npm-cache", "npm_config_offline": "true"}`.

- [ ] **Step 1:** Read `dark-factory/tests/test_supervisor.py` (or wherever `ro_mounts=[adapter_ro_dir]` is asserted — grep first) to find the exact test helper/fixture used to invoke the supervisor's hardened build-call path so the new test matches existing conventions instead of inventing a new harness.

- [ ] **Step 2 (TDD):** Add a test (in the file found in Step 1) asserting: with `cfg["_container"]["dep_cache_dir"]` set to a tmp dir containing `pypi/` and `npm-cache/` subdirs, the `docker run` argv the hardened path constructs (monkeypatch `df_container.build_argv` to capture its kwargs, same pattern the existing adapter_ro_dir test uses) includes `dep_cache_dir` in `ro_mounts` and the four env vars in `env`. Add a second test for the `enterprise` branch (`build_enterprise_argv`) asserting the same. Add a third test: `dep_cache_dir is None` (not configured) → `ro_mounts` is unchanged (`[adapter_ro_dir]` only) and none of the four env vars are injected — back-compat, no behavior change for runs that don't configure it.

- [ ] **Step 3:** Run the new tests, confirm FAIL (mount/env not yet wired).

- [ ] **Step 4:** In `supervisor.py`, in the `effective == "hardened"` branch (~line 1916-1920), change:

```python
                builder_prefix = df_container.build_argv(
                    c["image"], workspace,
                    ro_mounts=[adapter_ro_dir],
                    network=c["network"], memory=c["memory"], pids=c["pids"],
                    env=creds if creds else None)
```

  to:

```python
                ro_mounts = [adapter_ro_dir]
                dep_cache_env = None
                dep_cache_dir = c.get("dep_cache_dir")
                if dep_cache_dir:
                    # Same TOCTOU re-check discipline as the adapter mount above:
                    # config-load already validated the dir exists, but this is
                    # the moment it's about to be bind-mounted into the container.
                    if not _disjoint(dep_cache_dir, cfg["_control_root"]):
                        raise df_sandbox.SandboxError(
                            "hardened: refusing to mount dep_cache_dir — it "
                            f"overlaps the control root ({dep_cache_dir}); the "
                            "holdout barrier would be breached by construction")
                    ro_mounts.append(dep_cache_dir)
                    dep_cache_env = {
                        "PIP_NO_INDEX": "1",
                        "PIP_FIND_LINKS": os.path.join(dep_cache_dir, "pypi"),
                        "npm_config_cache": os.path.join(dep_cache_dir, "npm-cache"),
                        "npm_config_offline": "true",
                    }
                merged_env = dict(creds) if creds else {}
                if dep_cache_env:
                    merged_env.update(dep_cache_env)
                builder_prefix = df_container.build_argv(
                    c["image"], workspace,
                    ro_mounts=ro_mounts,
                    network=c["network"], memory=c["memory"], pids=c["pids"],
                    env=merged_env if merged_env else None)
```

  And in the `effective == "enterprise"` branch (~line 1945-1952), apply the identical `ro_mounts`/`dep_cache_env` construction (reusing the same local variables computed just above if the two branches are adjacent — otherwise duplicate the same block, since enterprise passes `env=None` today for credentials but MUST still be able to carry the non-secret dep-cache env vars):

```python
                ro_mounts_ent = [adapter_ro_dir]
                dep_cache_env_ent = None
                dep_cache_dir = c.get("dep_cache_dir")
                if dep_cache_dir:
                    if not _disjoint(dep_cache_dir, cfg["_control_root"]):
                        raise df_sandbox.SandboxError(
                            "enterprise: refusing to mount dep_cache_dir — it "
                            f"overlaps the control root ({dep_cache_dir}); the "
                            "holdout barrier would be breached by construction")
                    ro_mounts_ent.append(dep_cache_dir)
                    dep_cache_env_ent = {
                        "PIP_NO_INDEX": "1",
                        "PIP_FIND_LINKS": os.path.join(dep_cache_dir, "pypi"),
                        "npm_config_cache": os.path.join(dep_cache_dir, "npm-cache"),
                        "npm_config_offline": "true",
                    }
                builder_prefix = df_container.build_enterprise_argv(
                    c["image"], workspace,
                    ro_mounts=ro_mounts_ent,
                    proxy_endpoint=proxy_endpoint,
                    seccomp_profile_path=cfg["_enterprise"]["seccomp"],
                    entrypoint_path=entrypoint_path,
                    memory=c["memory"], pids=c["pids"],
                    env=dep_cache_env_ent)
```

  (`env=None` today at enterprise stays `env=None` when `dep_cache_env_ent` is `None` — no behavior change when the field isn't configured.)

- [ ] **Step 5:** Run the Step 2 tests, confirm PASS. Run full suite: `.venv/bin/python -m pytest dark-factory/tests -q` — all green, no regressions.

- [ ] **Step 6 (live proof, if Docker is available):** Provision a real tiny cache and prove a hardened builder container can install from it with zero network:

```bash
mkdir -p /tmp/df-depcache-smoke/pypi
cd /Users/alonadelson/Projects/ai_projects/skills
.venv/bin/pip download --no-deps -d /tmp/df-depcache-smoke/pypi six==1.16.0
docker run --rm --network none \
  -v /tmp/df-depcache-smoke:/tmp/df-depcache-smoke:ro \
  -e PIP_NO_INDEX=1 -e PIP_FIND_LINKS=/tmp/df-depcache-smoke/pypi \
  python:3.12-alpine \
  pip install six==1.16.0
```
Expected: pip installs `six` successfully with `--network none` (proves the mount + env vars genuinely satisfy pip with zero container-side network reachability). If Docker isn't available in this environment, skip this step and note it as not-yet-live-verified in the commit/PR description rather than skipping silently.

- [ ] **Step 7:** Update `dark-factory/references/hardened.md` — add a "Pinned dependency cache (§7.3)" section: what problem it solves (a hardened/enterprise builder previously couldn't `pip install`/`npm install` anything — every dependency had to be pre-vendored by hand into the workspace), the operator provisioning command (`python3 dark-factory/scripts/df_depcache.py --source <spec-or-scaffold-dir> --dest <cache-dir>`), the config (`hardened.dep_cache_dir`), and the honest scope: this is a **read-only filesystem mount**, not a live proxy — "no direct registry/DNS" holds by construction (there is nothing running to reach), and pip/npm resolve entirely from the local files; anything not in the cache fails to install (pip/npm's own fail-closed behavior, not reimplemented here). Note the npm CLI is required on the **operator's** host at provisioning time only.

- [ ] **Step 8:** Update `dark-factory/references/config-reference.md` — add a `hardened.dep_cache_dir` row (optional, string, absolute path to a pre-provisioned cache dir; default `null`/unset).

- [ ] **Step 9:** Update `dark-factory/SKILL.md` — find the reference to the once-over audit's §7.3 gap (or the References list) and either remove the "not built" framing or add `hardened.md`'s new section to the References list if not already listed there.

- [ ] **Step 10:** Commit:

```bash
git add dark-factory/scripts/supervisor.py dark-factory/references/hardened.md dark-factory/references/config-reference.md dark-factory/SKILL.md dark-factory/tests/
git commit -m "feat(dark-factory): mount read-only pinned dependency cache into hardened/enterprise builders (§7.3 Task 3)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review Notes (plan ↔ spec)

**Covered:** spec §7.3's "read-only pinned dependency proxy/cache, no direct registry/DNS" — implemented as a read-only bind mount (not a live proxy), which is a STRONGER guarantee than a network proxy would be (nothing to reach, nothing to misconfigure into an open egress path) and reuses the exact `ro_mounts` + TOCTOU-recheck + fail-closed-config-validation patterns already proven for the adapter-directory mount and the M23 OSV snapshot pattern. Closes the audit-identified gap "(a) a hardened builder can't pip-install; must vendor deps."

**Deliberately deferred (state in hardened.md):** the cache only covers PyPI (wheel/sdist) and npm (via npm's own offline-cache format) — no other ecosystems (cargo, gem, etc.) since `df_depaudit.parse_installed` doesn't discover those either (same scope boundary as the M23 CVE gate). Transitive dependency resolution is NOT performed by `df_depcache.py fetch` — it fetches exactly the pinned packages `parse_installed` finds in the artifact tree's manifests; if a spec's builder ends up needing an un-pinned transitive dependency pip/npm would normally resolve from the live registry, that install fails closed (not silently allowed out to the network) — the operator re-runs `fetch` with a fuller pinned manifest. This mirrors the already-documented "full transitive dep solver" deferral for the M23 CVE gate.

**Honesty note:** the "no direct registry/DNS" property is TRUE BY CONSTRUCTION at both hardened (`--network none` unaffected — the mount needs no network) and enterprise (nothing new is added to the egress allowlist; the cache doesn't need one). This is not a proxy-based enforcement claim like the M17 credential proxy — it's simpler and stronger: there is no running listener to reach in the first place.
