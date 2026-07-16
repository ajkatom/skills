"""OSV CVE dependency audit (M23 Task 1). Stdlib only (urllib, zipfile, json)
-- no new dependency.

`parse_installed(root)` walks an artifact tree for PINNED dependencies only
(requirements.txt `name==version`, package.json deps/devDeps with an EXACT
version, pyproject.toml `[project]` deps `name==version` best-effort,
`*.dist-info` dirs, and `node_modules/<pkg>/package.json`'s own installed
version) and returns a deduped, sorted `[{ecosystem,name,version}]`. Mirrors
df_security.py's manifest-parsing style: sorted directory walk, skip
`.git`/symlinks/binaries where relevant, `errors="ignore"` reads, and NEVER
raises on a bad or non-UTF8 manifest -- a malformed manifest is simply
skipped, exactly like `sbom()`/`license_scan()`.

`query_osv_api(pkgs, fetcher=...)` POSTs each package to the live
`api.osv.dev` backend (the ONE gate, in api mode, that leaves the box) via
an INJECTABLE fetcher -- same discipline as df_audit_sink.py/df_notify.py's
`fetcher`/sink pattern -- so every non-live test makes ZERO network calls.
ANY error (fetcher raises, non-200, bad JSON) on ANY package fails the
WHOLE batch closed (`unavailable: True`) -- never a silent partial pass,
never a raised exception.

`load_snapshot(dir)` + `query_osv_snapshot(pkgs, snapshot)` match pinned
versions against a local, pre-provisioned OSV snapshot OFFLINE -- no
fetcher parameter exists on this path at all, so it cannot reach the
network by construction. The matcher is intentionally best-effort (a
packaging-style release-tuple compare for PyPI, a semver-ish tuple compare
for npm) and ERRS TOWARD FLAGGING: a package name that matches a snapshot
record but whose range is ambiguous/unparseable is reported as a finding
with a `"range-uncertain"` note rather than silently passed over -- a
false negative here is the dangerous direction.

`fetch_snapshot(ecosystem, dest_dir, fetcher=...)` is the one deliberate,
operator-run provisioning network op (downloads OSV's published
per-ecosystem export and unzips it); it is never called during a run.
"""
import io
import json
import os
import re
import urllib.error
import urllib.request
import zipfile


class DepAuditError(RuntimeError):
    """Raised by `load_snapshot`/`fetch_snapshot` on a missing/empty/corrupt
    snapshot dir or a fetch failure. Callers (the M23 Task 2 gate) map this
    to an `unavailable` gate status -- never a silent pass."""


# --- parse_installed ---------------------------------------------------

_PINNED_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)$")
_DIST_INFO_NAME_VERSION_RE = re.compile(r"^(.+)-([^-]+)$")
_PYPROJECT_DEPS_ARRAY_RE = re.compile(r"^\s*dependencies\s*=\s*\[\s*$")
_PYPROJECT_DEP_LINE_RE = re.compile(r"""^\s*["']([^"']+)["']\s*,?\s*$""")
# Exact npm version only: plain dotted numeric (optionally with a
# pre-release/build suffix). No ^ ~ * range operators, no "x" wildcards, no
# comparator strings ("latest", ">=1.0.0", "workspace:*", "file:...", etc).
_NPM_EXACT_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){0,2}(?:[-+][0-9A-Za-z.\-]+)?$")


def _is_exact_npm_version(v) -> bool:
    if not isinstance(v, str):
        return False
    v = v.strip()
    return bool(v) and bool(_NPM_EXACT_VERSION_RE.match(v))


def _parse_requirements_txt(path) -> list:
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = _PINNED_RE.match(line)
                if m:
                    out.append({"ecosystem": "PyPI", "name": m.group(1), "version": m.group(2)})
    except OSError:
        pass
    return out


def _parse_package_json_deps(path) -> list:
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return out
    if not isinstance(data, dict):
        return out
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, version in section.items():
            if not isinstance(name, str) or not name.strip():
                continue
            if _is_exact_npm_version(version):
                out.append({"ecosystem": "npm", "name": name.strip(), "version": version.strip()})
    return out


def _parse_pyproject_toml_deps(path) -> list:
    """Best-effort, tolerant line scan for `[project] dependencies = [...]`,
    mirroring df_security.sbom()'s `_parse_pyproject_toml` fallback style --
    stdlib has no guaranteed tomllib pre-3.11, so this is intentionally a
    simple regex/line parse, not a real TOML parser."""
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return out

    in_array = False
    for line in lines:
        if not in_array:
            if _PYPROJECT_DEPS_ARRAY_RE.match(line):
                in_array = True
            continue
        stripped = line.strip()
        if stripped.startswith("]"):
            in_array = False
            continue
        m = _PYPROJECT_DEP_LINE_RE.match(line)
        if m:
            pm = _PINNED_RE.match(m.group(1).strip())
            if pm:
                out.append({"ecosystem": "PyPI", "name": pm.group(1), "version": pm.group(2)})
    return out


def _dist_info_name_version(dirname: str):
    base = dirname[: -len(".dist-info")] if dirname.endswith(".dist-info") else dirname
    m = _DIST_INFO_NAME_VERSION_RE.match(base)
    if not m:
        return None
    return m.group(1), m.group(2)


def _npm_installed_from_package_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    name = data.get("name")
    version = data.get("version")
    if not isinstance(name, str) or not name.strip():
        return None
    if not _is_exact_npm_version(version):
        return None
    return {"ecosystem": "npm", "name": name.strip(), "version": version.strip()}


def _is_npm_package_dir(dirpath: str) -> bool:
    """True when `dirpath` is a direct (possibly scoped) child of a
    `node_modules` directory, i.e. `node_modules/<pkg>` or
    `node_modules/@scope/<pkg>` -- the package's OWN install directory, not
    an arbitrary directory somewhere inside it."""
    parent_dir = os.path.dirname(dirpath)
    parent = os.path.basename(parent_dir)
    if parent == "node_modules":
        return True
    grandparent = os.path.basename(os.path.dirname(parent_dir))
    return parent.startswith("@") and grandparent == "node_modules"


def _walk_installed_dirs(root: str):
    """Yield (dirpath, dirnames, filenames) like os.walk, skipping `.git`
    and symlinked directories, sorted for determinism -- mirrors
    df_security._walk_files's discipline."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d != ".git" and not os.path.islink(os.path.join(dirpath, d))
        )
        yield dirpath, dirnames, sorted(filenames)


def parse_installed(root) -> list:
    """Extract PINNED-only `[{ecosystem,name,version}]` from the artifact
    tree at `root`. Deduped and sorted by (ecosystem, name, version). Never
    raises on a bad/non-UTF8 manifest -- such a manifest simply contributes
    nothing."""
    pkgs = []

    req_path = os.path.join(root, "requirements.txt")
    if os.path.isfile(req_path) and not os.path.islink(req_path):
        pkgs.extend(_parse_requirements_txt(req_path))

    pkg_json_path = os.path.join(root, "package.json")
    if os.path.isfile(pkg_json_path) and not os.path.islink(pkg_json_path):
        pkgs.extend(_parse_package_json_deps(pkg_json_path))

    pyproject_path = os.path.join(root, "pyproject.toml")
    if os.path.isfile(pyproject_path) and not os.path.islink(pyproject_path):
        pkgs.extend(_parse_pyproject_toml_deps(pyproject_path))

    for dirpath, dirnames, filenames in _walk_installed_dirs(root):
        for d in dirnames:
            if d.endswith(".dist-info"):
                nv = _dist_info_name_version(d)
                if nv:
                    pkgs.append({"ecosystem": "PyPI", "name": nv[0], "version": nv[1]})

        if "package.json" in filenames and _is_npm_package_dir(dirpath):
            pkg_json = os.path.join(dirpath, "package.json")
            # Skip a symlinked manifest, matching df_security._walk_files's
            # discipline (never follow a symlinked file into an off-tree read).
            if not os.path.islink(pkg_json):
                rec = _npm_installed_from_package_json(pkg_json)
                if rec:
                    pkgs.append(rec)

    seen = set()
    out = []
    for p in pkgs:
        key = (p["ecosystem"], p["name"], p["version"])
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    out.sort(key=lambda p: (p["ecosystem"], p["name"], p["version"]))
    return out


# --- query_osv_api -------------------------------------------------------

_OSV_API_URL = "https://api.osv.dev/v1/query"
_OSV_SNAPSHOT_URL_TMPL = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"


def _urlopen_fetch(url: str, data, timeout_s: int):
    """Default injectable fetcher: `fetcher(url, data_bytes_or_None,
    timeout_s) -> (status, body_bytes)`. POST when `data` is given (the
    query_osv_api case), GET otherwise (the fetch_snapshot case). An HTTP
    error status is returned as a normal (status, body) tuple -- NOT
    raised -- so every caller's status check is uniform; a network-level
    failure (unreachable host, timeout, DNS) still propagates as an
    exception, which callers catch."""
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def query_osv_api(pkgs, *, fetcher=_urlopen_fetch, timeout_s: int = 20) -> dict:
    """POST each `{ecosystem,name,version}` in `pkgs` to the live OSV API.
    The request body carries ONLY `version` and `package: {name,
    ecosystem}` -- never anything else about the artifact. ANY error
    (fetcher raises, non-200 status, unparseable JSON) on ANY package fails
    the WHOLE batch closed (`unavailable: True`) -- fail-closed, never a
    silent partial pass. NEVER raises."""
    results = []
    for pkg in pkgs:
        try:
            body = json.dumps(
                {
                    "version": pkg["version"],
                    "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
                }
            ).encode("utf-8")
            status, resp_body = fetcher(_OSV_API_URL, body, timeout_s)
            if status != 200:
                return {
                    "source": "osv-api",
                    "checked": True,
                    "results": [],
                    "unavailable": True,
                    "reason": f"osv-api returned HTTP {status} for {pkg.get('name')!r}",
                }
            data = json.loads(resp_body)
            if not isinstance(data, dict):
                raise ValueError("osv-api response body was not a JSON object")
        except Exception as e:  # never raise out of query_osv_api
            return {
                "source": "osv-api",
                "checked": True,
                "results": [],
                "unavailable": True,
                "reason": f"osv-api query failed: {e}",
            }

        vulns = []
        for v in data.get("vulns") or []:
            if isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]:
                vulns.append({"id": v["id"], "summary": v.get("summary") or ""})
        results.append(
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "ecosystem": pkg["ecosystem"],
                "vulns": vulns,
            }
        )

    return {"source": "osv-api", "checked": True, "results": results, "unavailable": False, "reason": ""}


# --- load_snapshot / query_osv_snapshot -----------------------------------


def _record_ecosystem_names(record: dict):
    """All distinct (ecosystem, lower(name)) pairs an OSV record's
    `affected[]` list declares (usually exactly one)."""
    keys = set()
    affected = record.get("affected")
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            pkg = entry.get("package")
            if not isinstance(pkg, dict):
                continue
            eco = pkg.get("ecosystem")
            name = pkg.get("name")
            if isinstance(eco, str) and eco and isinstance(name, str) and name:
                keys.add((eco, name.lower()))
    return keys


def load_snapshot(snapshot_dir) -> dict:
    """Load OSV records from a local snapshot directory tree (per-ecosystem
    subdirs of `*.json`, i.e. the flat layout `fetch_snapshot` writes).
    Indexed by `(ecosystem, lower(name)) -> [record, ...]`. A missing,
    empty, or entirely-corrupt snapshot dir raises `DepAuditError` (the
    caller maps this to an `unavailable` gate). An individual corrupt
    record is skipped, not fatal -- `errors="ignore"` per-record, same
    discipline as `df_security.py`'s scanners."""
    if not snapshot_dir or not os.path.isdir(snapshot_dir):
        raise DepAuditError(f"osv snapshot directory not found: {snapshot_dir!r}")

    index: dict = {}
    found_any = False
    for dirpath, dirnames, filenames in os.walk(snapshot_dir):
        dirnames[:] = sorted(
            d for d in dirnames if d != ".git" and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            if not name.endswith(".json"):
                continue
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    record = json.load(f)
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue  # skip a bad record, don't crash
            if not isinstance(record, dict) or not record.get("id"):
                continue
            keys = _record_ecosystem_names(record)
            if not keys:
                continue
            found_any = True
            for key in keys:
                index.setdefault(key, []).append(record)

    if not found_any:
        raise DepAuditError(f"osv snapshot directory has no valid OSV records: {snapshot_dir!r}")

    return index


def _pypi_version_tuple(v):
    """packaging-style tuple compare on release segments only (best-effort,
    stdlib -- ignores pre/post/dev qualifiers). Returns None when the
    string doesn't start with a dotted-numeric release (unparseable)."""
    if not isinstance(v, str):
        return None
    v = v.strip()
    m = re.match(r"^[vV]?(\d+(?:\.\d+)*)", v)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _npm_version_tuple(v):
    """semver-ish tuple compare (major.minor.patch), best-effort, stdlib.
    Returns None when the string doesn't start with a dotted-numeric
    version (unparseable)."""
    if not isinstance(v, str):
        return None
    v = v.strip()
    m = re.match(r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m:
        return None
    return tuple(int(g) if g is not None else 0 for g in m.groups())


def _version_tuple_fn(ecosystem: str):
    return _npm_version_tuple if ecosystem == "npm" else _pypi_version_tuple


def _match_affected_entry(pkg_version_tuple, pkg_version: str, entry: dict, ecosystem: str):
    """Return (matched, uncertain) for one `affected[]` entry of a record
    already confirmed to name this package. `matched` is a definite hit
    (enumerated version list, or a cleanly parsed simple range). `uncertain`
    means the package NAME matched but the range data couldn't be reliably
    evaluated -- callers must treat this as a finding too (err toward
    flagging, never a silent miss)."""
    versions = entry.get("versions")
    if isinstance(versions, list) and pkg_version in versions:
        return True, False

    ranges = entry.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        # No enumerated versions, no ranges: nothing actionable on this
        # entry (not a match, not uncertain either -- there's simply no
        # version data to evaluate against).
        return False, False

    matched = False
    uncertain = False
    version_tuple_fn = _version_tuple_fn(ecosystem)

    for rng in ranges:
        if not isinstance(rng, dict):
            # A malformed range entry on a name-matching package is NOT
            # something we can positively clear -- flag it rather than drop
            # it (err toward a finding, never a silent miss).
            uncertain = True
            continue
        events = rng.get("events")
        if not isinstance(events, list) or not events:
            # Missing/empty events: no version data to evaluate, but the
            # package NAME matched -- flag as uncertain, don't drop.
            uncertain = True
            continue

        introduced = None
        fixed = None
        extra_event = False
        for ev in events:
            if not isinstance(ev, dict):
                continue
            if "introduced" in ev and introduced is None:
                introduced = ev["introduced"]
            elif "fixed" in ev and fixed is None:
                fixed = ev["fixed"]
            elif any(k in ev for k in ("introduced", "fixed", "limit", "last_affected")):
                # More than one simple introduced/fixed pair, or a "limit"/
                # "last_affected" event -- our comparator only handles the
                # simple single-introduced/single-fixed case reliably.
                extra_event = True

        if pkg_version_tuple is None or extra_event:
            uncertain = True
            continue

        introduced_tuple = None
        if introduced is not None and introduced != "0":
            introduced_tuple = version_tuple_fn(str(introduced))
            if introduced_tuple is None:
                uncertain = True
                continue

        fixed_tuple = None
        if fixed is not None:
            fixed_tuple = version_tuple_fn(str(fixed))
            if fixed_tuple is None:
                uncertain = True
                continue

        in_range = True
        if introduced_tuple is not None and pkg_version_tuple < introduced_tuple:
            in_range = False
        if fixed_tuple is not None and pkg_version_tuple >= fixed_tuple:
            in_range = False
        if in_range:
            matched = True

    return matched, uncertain


def query_osv_snapshot(pkgs, snapshot) -> dict:
    """Match each `{ecosystem,name,version}` in `pkgs` against the indexed
    OSV `snapshot` (from `load_snapshot`) OFFLINE. Same return shape as
    `query_osv_api` (`source: "osv-snapshot"`). Takes no fetcher parameter
    at all -- it cannot make a network call by construction.

    A matching record is a finding when the version is enumerated in
    `affected[].versions`, or falls inside a cleanly-parsed simple
    `introduced`/`fixed` range. An AMBIGUOUS or unparseable range on an
    otherwise-matching package name is FLAGGED too (with a
    `"range-uncertain"` note) rather than silently skipped -- a false
    negative here is the dangerous direction."""
    results = []
    for pkg in pkgs:
        ecosystem = pkg["ecosystem"]
        name = pkg["name"]
        version = pkg["version"]
        key = (ecosystem, name.lower())
        records = snapshot.get(key, []) if isinstance(snapshot, dict) else []

        version_tuple = _version_tuple_fn(ecosystem)(version)
        vulns = []
        for record in records:
            vid = record.get("id")
            if not isinstance(vid, str) or not vid:
                continue
            affected_list = record.get("affected")
            if not isinstance(affected_list, list):
                continue

            record_matched = False
            record_uncertain = False
            for entry in affected_list:
                if not isinstance(entry, dict):
                    continue
                pkg_field = entry.get("package")
                if not isinstance(pkg_field, dict):
                    continue
                if pkg_field.get("ecosystem") != ecosystem:
                    continue
                entry_name = pkg_field.get("name")
                if not isinstance(entry_name, str) or entry_name.lower() != name.lower():
                    continue
                m, u = _match_affected_entry(version_tuple, version, entry, ecosystem)
                record_matched = record_matched or m
                record_uncertain = record_uncertain or u

            if record_matched:
                vulns.append({"id": vid, "summary": record.get("summary") or ""})
            elif record_uncertain:
                vulns.append(
                    {"id": vid, "summary": record.get("summary") or "", "note": "range-uncertain"}
                )

        results.append({"name": name, "version": version, "ecosystem": ecosystem, "vulns": vulns})

    return {
        "source": "osv-snapshot",
        "checked": True,
        "results": results,
        "unavailable": False,
        "reason": "",
    }


# --- fetch_snapshot (operator provisioning) -------------------------------


def fetch_snapshot(ecosystem, dest_dir, *, fetcher=_urlopen_fetch, timeout_s: int = 120) -> int:
    """Operator provisioning step (the ONE deliberate network op; NOT
    called during a run): download OSV's published export for `ecosystem`
    and unzip its `*.json` records into `dest_dir/<ecosystem>/`. Returns
    the number of records written."""
    url = _OSV_SNAPSHOT_URL_TMPL.format(ecosystem)
    try:
        status, body = fetcher(url, None, timeout_s)
    except Exception as e:
        raise DepAuditError(f"fetch_snapshot: request failed for {ecosystem!r}: {e}") from None
    if status != 200:
        raise DepAuditError(f"fetch_snapshot: HTTP {status} for {ecosystem!r}")

    out_dir = os.path.join(dest_dir, ecosystem)
    os.makedirs(out_dir, exist_ok=True)

    count = 0
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".json"):
                    continue
                # zip-slip guard: write under the bare filename only, never
                # honor a path from inside the archive.
                name = os.path.basename(info.filename)
                if not name:
                    continue
                data = zf.read(info)
                with open(os.path.join(out_dir, name), "wb") as f:
                    f.write(data)
                count += 1
    except zipfile.BadZipFile as e:
        raise DepAuditError(f"fetch_snapshot: bad zip for {ecosystem!r}: {e}") from None

    return count
