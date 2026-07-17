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
