"""Stdlib security scanners over a directory (M9 Task 1, M18 Task 2).

Pure functions: `secret_scan`, `dangerous_scan`, `sbom`, `license_scan`.
All walk a directory deterministically (sorted, skip `.git`, skip
symlinks, skip binary files detected by a NUL byte in the first read
chunk), use only stdlib (`re`, `os`, `json`, `tomllib` when available),
do no network I/O, and return sorted, deterministic output.

Honest scope: these are heuristic, pattern-based scanners — a floor,
not a full SAST/secret-detection engine. `secret_scan` findings record
the RULE NAME ONLY, never the matched secret value. `license_scan`
(M18) covers licenses DECLARED in manifests and metadata that are
PHYSICALLY PRESENT in the artifact tree (pyproject.toml, package.json,
vendored node_modules/*/package.json, vendored *.dist-info/METADATA);
it does NOT resolve the license of an un-vendored transitive
dependency — that would require a network lookup or a bundled license
database, both out of scope for an offline, stdlib-only tool. An
un-vendored dependency is simply invisible to this scanner (not
silently reported as compliant) — this is documented in
references/security-gates.md, not faked.
"""
import json
import os
import re
import shutil
import subprocess

import df_depaudit

try:
    import tomllib
except ImportError:  # pragma: no cover - < 3.11 fallback path
    tomllib = None

# --- secret_scan -----------------------------------------------------------

_SECRET_RULES = {
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    ),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "generic_secret_assignment": re.compile(
        r"(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"][^'\"\n]{16,}['\"]"
    ),
}

# --- dangerous_scan ----------------------------------------------------

_DANGEROUS_RULES = {
    "eval_exec": re.compile(r"\b(?:eval|exec)\s*\("),
    "os_system": re.compile(r"\bos\.system\s*\("),
    "shell_true": re.compile(r"shell\s*=\s*True"),
    "pickle_loads": re.compile(r"\bpickle\.loads\s*\("),
    "yaml_unsafe": re.compile(r"\byaml\.load\s*\("),
}

_BINARY_SNIFF_BYTES = 8192


def _is_binary(path: str) -> bool:
    """Detect binary files by a NUL byte in the first read chunk."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def _walk_files(root: str, suffix: str | None = None):
    """Yield (abspath, relpath) for files under root, sorted, skipping
    `.git`, symlinks (files and dirs), and binary files.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d != ".git" and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            abspath = os.path.join(dirpath, name)
            if os.path.islink(abspath):
                continue
            if suffix is not None and not name.endswith(suffix):
                continue
            if _is_binary(abspath):
                continue
            relpath = os.path.relpath(abspath, root)
            yield abspath, relpath.replace(os.sep, "/")


def secret_scan(root: str) -> list[dict]:
    """Scan all text files under `root` for secret patterns.

    Returns findings `{"file": relpath, "line": int, "rule": str}` —
    rule name only, never the matched secret value. Sorted by
    (file, line, rule).
    """
    findings = []
    for abspath, relpath in _walk_files(root):
        try:
            with open(abspath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            for rule, pattern in _SECRET_RULES.items():
                if pattern.search(line):
                    findings.append({"file": relpath, "line": lineno, "rule": rule})
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return findings


def dangerous_scan(root: str) -> list[dict]:
    """Scan `*.py` files under `root` for dangerous-pattern rules.

    Returns findings `{"file","line","rule"}`, sorted by
    (file, line, rule).
    """
    findings = []
    for abspath, relpath in _walk_files(root, suffix=".py"):
        try:
            with open(abspath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            for rule, pattern in _DANGEROUS_RULES.items():
                if pattern.search(line):
                    findings.append({"file": relpath, "line": lineno, "rule": rule})
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return findings


# --- sbom --------------------------------------------------------------

_PYPROJECT_DEPS_ARRAY_RE = re.compile(r"^\s*dependencies\s*=\s*\[\s*$")
_PYPROJECT_DEP_LINE_RE = re.compile(r"""^\s*["']([^"']+)["']\s*,?\s*$""")


def _parse_requirements_txt(path: str) -> list[str]:
    deps = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            deps.append(line)
    return deps


def _parse_package_json(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []
    if not isinstance(data, dict):
        return []
    deps = []
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            for name, version in section.items():
                if version:
                    deps.append(f"{name}=={version}")
                else:
                    deps.append(name)
    return deps


def _parse_pyproject_toml(path: str) -> list[str]:
    """Best-effort, tolerant line scan for `[project] dependencies = [...]`.

    stdlib has no tomllib pre-3.11, so this is intentionally a simple
    regex/line parse, not a real TOML parser.
    """
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

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
            deps.append(m.group(1))
    return deps


def _name_of(dep: str) -> str:
    """Extract the bare package name from a declared dependency string."""
    return re.split(r"[=<>!~\[; ]", dep, maxsplit=1)[0].strip()


def sbom(root: str) -> dict:
    """Declared-dependency inventory from manifest files under `root`.

    Parses `requirements.txt`, `package.json`, and (best-effort)
    `pyproject.toml`. Missing manifests are simply omitted from
    `declared` (not an error). Returns
    `{"declared": {...}, "count": N, "unpinned": [names]}`.
    """
    declared = {}

    req_path = os.path.join(root, "requirements.txt")
    if os.path.isfile(req_path):
        declared["pip"] = _parse_requirements_txt(req_path)

    pkg_path = os.path.join(root, "package.json")
    if os.path.isfile(pkg_path):
        declared["npm"] = _parse_package_json(pkg_path)

    pyproject_path = os.path.join(root, "pyproject.toml")
    if os.path.isfile(pyproject_path):
        declared["pyproject"] = _parse_pyproject_toml(pyproject_path)

    unpinned = []
    count = 0
    for deps in declared.values():
        count += len(deps)
        for dep in deps:
            if "==" not in dep:
                unpinned.append(_name_of(dep))

    result = {
        "declared": declared,
        "count": count,
        "unpinned": sorted(unpinned),
    }
    if "pyproject" in declared:
        result["parser"] = "best-effort"
    return result


# --- license_scan (M18 Task 2) ------------------------------------------

_PYPROJECT_LICENSE_STR_RE = re.compile(r'''^\s*license\s*=\s*["']([^"']+)["']\s*$''')
_PYPROJECT_LICENSE_TABLE_TEXT_RE = re.compile(
    r'''^\s*license\s*=\s*\{[^}]*\btext\s*=\s*["']([^"']+)["']'''
)
_PYPROJECT_NAME_RE = re.compile(r'''^\s*name\s*=\s*["']([^"']+)["']\s*$''')
_PYPROJECT_CLASSIFIERS_ARRAY_RE = re.compile(r"^\s*classifiers\s*=\s*\[\s*$")
_PYPROJECT_CLASSIFIER_LINE_RE = re.compile(r'''^\s*["'](License ::[^"']*)["']\s*,?\s*$''')

_METADATA_NAME_RE = re.compile(r"^Name:\s*(.+)$", re.IGNORECASE)
_METADATA_LICENSE_RE = re.compile(r"^License:\s*(.+)$", re.IGNORECASE)
_METADATA_CLASSIFIER_RE = re.compile(r"^Classifier:\s*(License ::.*)$", re.IGNORECASE)


def _classifier_license_name(classifier: str) -> str:
    """`License :: OSI Approved :: MIT License` -> `MIT License`."""
    return classifier.split("::")[-1].strip()


def _pyproject_license_fallback(path: str):
    """Best-effort, tolerant line scan of `[project]` for `license` +
    `License ::` classifiers, mirroring sbom()'s `_parse_pyproject_toml`
    fallback style — used only when tomllib is unavailable or fails to
    parse the file.
    """
    name = None
    declared = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return name, declared

    in_project = False
    in_classifiers = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_project = stripped == "[project]"
            in_classifiers = False
            continue
        if not in_project:
            continue
        if in_classifiers:
            if stripped.startswith("]"):
                in_classifiers = False
                continue
            m = _PYPROJECT_CLASSIFIER_LINE_RE.match(line)
            if m:
                seg = _classifier_license_name(m.group(1))
                if seg:
                    declared.append(seg)
            continue
        if _PYPROJECT_CLASSIFIERS_ARRAY_RE.match(line):
            in_classifiers = True
            continue
        m = _PYPROJECT_NAME_RE.match(line)
        if m and name is None:
            name = m.group(1).strip()
            continue
        m = _PYPROJECT_LICENSE_STR_RE.match(line)
        if m:
            declared.append(m.group(1).strip())
            continue
        m = _PYPROJECT_LICENSE_TABLE_TEXT_RE.match(line)
        if m:
            declared.append(m.group(1).strip())
            continue
    return name, declared


def _pyproject_name_and_licenses(path: str):
    """Returns (project_name_or_None, [declared_license_strings]).

    Prefers stdlib `tomllib` (available 3.11+) for a real parse; falls
    back to a tolerant line/regex scan (mirroring sbom()'s pyproject
    parser) when tomllib is unavailable or the file fails to parse.
    `license = {file = ...}` alone contributes no textual license value
    (there is nothing to check against the allowlist without reading
    an arbitrary referenced file) — it is not treated as "declared".
    """
    if tomllib is not None:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
            # tomllib.load does a STRICT utf-8 decode before parsing, so a
            # manifest with invalid encoding raises UnicodeDecodeError (NOT
            # TOMLDecodeError) — catch it too and fall through to the
            # tolerant regex fallback (which reads errors="ignore"), so a
            # malformed manifest is benign here rather than an uncaught
            # exception escaping license_scan -> run_gates -> the run.
            data = None
        if isinstance(data, dict):
            project = data.get("project")
            name = None
            declared = []
            if isinstance(project, dict):
                name_val = project.get("name")
                if isinstance(name_val, str) and name_val.strip():
                    name = name_val.strip()
                lic = project.get("license")
                if isinstance(lic, str) and lic.strip():
                    declared.append(lic.strip())
                elif isinstance(lic, dict):
                    text = lic.get("text")
                    if isinstance(text, str) and text.strip():
                        declared.append(text.strip())
                classifiers = project.get("classifiers")
                if isinstance(classifiers, list):
                    for c in classifiers:
                        if isinstance(c, str) and c.startswith("License ::"):
                            seg = _classifier_license_name(c)
                            if seg:
                                declared.append(seg)
            return name, declared
    return _pyproject_license_fallback(path)


def _package_json_licenses(data: dict) -> list:
    declared = []
    lic = data.get("license")
    if isinstance(lic, str) and lic.strip():
        declared.append(lic.strip())
    elif isinstance(lic, dict):
        t = lic.get("type")
        if isinstance(t, str) and t.strip():
            declared.append(t.strip())
    legacy = data.get("licenses")
    if isinstance(legacy, list):
        for entry in legacy:
            if isinstance(entry, dict):
                t = entry.get("type")
                if isinstance(t, str) and t.strip():
                    declared.append(t.strip())
            elif isinstance(entry, str) and entry.strip():
                declared.append(entry.strip())
    return declared


def _dist_info_package_name(relpath: str) -> str:
    """`.../foo-1.2.3.dist-info/METADATA` -> `foo` (used only when the
    METADATA file itself has no `Name:` header)."""
    dist_dir = relpath.split("/")[-2]
    base = dist_dir[: -len(".dist-info")] if dist_dir.endswith(".dist-info") else dist_dir
    m = re.match(r"^(.+)-[^-]+$", base)
    return m.group(1) if m else base


def _parse_dist_info_metadata(path: str):
    """Scan the RFC822-style header block of a `*.dist-info/METADATA`
    file for `Name:`, `License:`, and `Classifier: License :: ...`.
    Stops at the first blank line (end of headers, start of the free-
    text description) so description text can never spuriously match.
    """
    name = None
    declared = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return name, declared
    for line in lines:
        if not line.strip():
            break
        m = _METADATA_NAME_RE.match(line)
        if m:
            name = m.group(1).strip()
            continue
        m = _METADATA_LICENSE_RE.match(line)
        if m:
            val = m.group(1).strip()
            if val:
                declared.append(val)
            continue
        m = _METADATA_CLASSIFIER_RE.match(line)
        if m:
            seg = _classifier_license_name(m.group(1))
            if seg:
                declared.append(seg)
    return name, declared


def _record_license_findings(findings, relpath, package, declared, allowed, require_license):
    if not declared:
        if require_license:
            findings.append(
                {"file": relpath, "package": package, "license": None, "rule": "missing-license"}
            )
        return
    seen = set()
    for lic in declared:
        key = lic.lower()
        if key in seen:
            continue
        seen.add(key)
        if key not in allowed:
            findings.append(
                {"file": relpath, "package": package, "license": lic, "rule": "disallowed-license"}
            )


def license_scan(root: str, allowlist: list, *, require_license: bool = False) -> list:
    """Scan `root` for licenses declared in manifests / vendored metadata
    physically present in the tree.

    Sources: pyproject.toml `[project].license` (string or {text=}) + a
    `License ::` trove classifier; package.json `"license"` (SPDX str) /
    legacy `"licenses"` array; vendored `node_modules/*/package.json`
    `"license"`; vendored `*.dist-info/METADATA` `License:` /
    `Classifier: License :: ...`.

    A declared license NOT in `allowlist` (matched case-insensitively)
    -> `"disallowed-license"`. A discovered package with NO declared
    license AND `require_license` -> `"missing-license"`. An empty
    allowlist disallows every declared license (the operator must list
    them explicitly). Returns findings `{"file","package","license",
    "rule"}`, deterministic (sorted). Skips `.git`, binary files, and
    symlinks like the other scanners (via `_walk_files`).

    Honest scope: this does NOT resolve the license of a dependency
    declared in a manifest but not physically vendored anywhere in
    `root` — such a dependency is invisible to this function (no
    finding either way), not silently treated as compliant.
    """
    allowed = {a.strip().lower() for a in allowlist}
    findings = []

    for abspath, relpath in _walk_files(root):
        parts = relpath.split("/")
        name = parts[-1]

        if name == "pyproject.toml":
            pkg_name, declared = _pyproject_name_and_licenses(abspath)
            package = pkg_name or (
                parts[-2] if len(parts) > 1 else os.path.basename(os.path.normpath(root)) or "."
            )
            _record_license_findings(findings, relpath, package, declared, allowed, require_license)

        elif name == "package.json":
            try:
                with open(abspath, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                data = None
            if isinstance(data, dict):
                declared = _package_json_licenses(data)
                if "node_modules" in parts:
                    idx = len(parts) - 1 - parts[::-1].index("node_modules")
                    package = "/".join(parts[idx + 1 : -1]) or "?"
                else:
                    pkg_name = data.get("name")
                    package = (
                        pkg_name
                        if isinstance(pkg_name, str) and pkg_name
                        else (parts[-2] if len(parts) > 1 else "<project>")
                    )
                _record_license_findings(findings, relpath, package, declared, allowed, require_license)

        elif name == "METADATA" and len(parts) >= 2 and parts[-2].endswith(".dist-info"):
            meta_name, declared = _parse_dist_info_metadata(abspath)
            package = meta_name or _dist_info_package_name(relpath)
            _record_license_findings(findings, relpath, package, declared, allowed, require_license)

    findings.sort(key=lambda f: (f["file"], f["package"], f["license"] or "", f["rule"]))
    return findings


# --- run_gates -----------------------------------------------------------

_EXTERNAL_TIMEOUT_S = 300
_DETAIL_TAIL_CHARS = 2000


def _run_external_gate(workspace: str, cmd: list) -> dict:
    """Run one external gate command; never raises.

    `unavailable` when the command isn't on PATH or fails to spawn/times
    out (a gate that errored to run is unavailable, not a silent pass).
    """
    if shutil.which(cmd[0]) is None:
        return {"status": "unavailable", "detail": f"{cmd[0]} not found on PATH"}
    try:
        proc = subprocess.run(
            cmd,
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=_EXTERNAL_TIMEOUT_S,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return {"status": "unavailable", "detail": str(e)}
    if proc.returncode == 0:
        return {"status": "pass"}
    output = (proc.stderr or proc.stdout or "")[-_DETAIL_TAIL_CHARS:]
    return {"status": "fail", "detail": output}


def _run_dependency_audit_gate(workspace: str, depaudit_cfg: dict) -> dict:
    """Run the `dependency_audit` gate (M23 Task 2): OSV CVE check over the
    artifact's PINNED dependencies, via whichever backend
    `depaudit_cfg["source"]` selects.

    `osv-api` calls `df_depaudit.query_osv_api` (the ONE backend that
    leaves the box -- live network to api.osv.dev); `osv-snapshot` loads
    the pre-provisioned local snapshot at `depaudit_cfg["snapshot_path"]`
    and calls `df_depaudit.query_osv_snapshot`, which makes NO network
    call by construction. Either way: any backend error/timeout, or a
    missing/corrupt snapshot, is `status: "unavailable"` -- fail-closed,
    never a silent pass. A clean tree is `"pass"`; any package with one or
    more vulns is `"fail"`, with findings `{name, version, ecosystem,
    vuln_ids, source}` -- names/versions/vuln-ids only, nothing about
    artifact content. Never raises.
    """
    try:
        pkgs = df_depaudit.parse_installed(workspace)
    except Exception as e:  # never let a bad manifest crash the run
        return {"status": "unavailable", "detail": f"parse_installed failed: {e}"}

    ecosystems = depaudit_cfg.get("ecosystems") or []
    if ecosystems:
        pkgs = [p for p in pkgs if p.get("ecosystem") in ecosystems]

    source = depaudit_cfg.get("source")
    if source == "osv-snapshot":
        try:
            snapshot = df_depaudit.load_snapshot(depaudit_cfg.get("snapshot_path"))
        except df_depaudit.DepAuditError as e:
            return {"status": "unavailable", "detail": str(e)}
        result = df_depaudit.query_osv_snapshot(pkgs, snapshot)
    else:  # "osv-api"
        result = df_depaudit.query_osv_api(pkgs, timeout_s=depaudit_cfg.get("timeout_s", 20))

    if result.get("unavailable"):
        return {"status": "unavailable", "detail": result.get("reason", "")}

    findings = []
    for r in result.get("results", []):
        vulns = r.get("vulns") or []
        if not vulns:
            continue
        findings.append(
            {
                "name": r["name"],
                "version": r["version"],
                "ecosystem": r["ecosystem"],
                "vuln_ids": [v["id"] for v in vulns if isinstance(v, dict) and v.get("id")],
                "source": result.get("source"),
            }
        )

    return {"status": "fail" if findings else "pass", "findings": findings}


def run_gates(workspace: str, sec: dict) -> dict:
    """Run the enabled built-in + external gates over `workspace`.

    `sec` is the validated `cfg["_security"]` block. Returns
    `{"checked": True, "gates": {name: {...}}, "failed": [names]}`.
    A `fail_on` gate that is `fail` (or `unavailable` under
    `strict_unavailable`) counts as a run failure.
    """
    gates = {}

    if sec.get("secret_scan"):
        findings = secret_scan(workspace)
        gates["secret_scan"] = {
            "status": "fail" if findings else "pass",
            "findings": findings,
        }

    if sec.get("dangerous_scan"):
        findings = dangerous_scan(workspace)
        gates["dangerous_scan"] = {
            "status": "fail" if findings else "pass",
            "findings": findings,
        }

    if sec.get("sbom"):
        gates["sbom"] = {"status": "pass", "sbom": sbom(workspace)}

    license_cfg = sec.get("license") or {}
    if license_cfg.get("enabled"):
        findings = license_scan(
            workspace,
            license_cfg.get("allowlist", []),
            require_license=license_cfg.get("require_license", False),
        )
        gates["license"] = {
            "status": "fail" if findings else "pass",
            "findings": findings,
        }

    depaudit_cfg = sec.get("dependency_audit") or {}
    if depaudit_cfg.get("enabled"):
        gates["dependency_audit"] = _run_dependency_audit_gate(workspace, depaudit_cfg)

    for entry in sec.get("external", []):
        gates[entry["name"]] = _run_external_gate(workspace, entry["cmd"])

    strict_unavailable = sec.get("strict_unavailable", True)
    failed = set()
    for name in sec.get("fail_on", []):
        gate = gates.get(name)
        if gate is None:
            # A mandatory gate that never ran (its built-in flag is off, or
            # it otherwise produced no result) is unavailable, not a silent
            # pass. Surface it in the report so fail-closed is auditable.
            gate = {"status": "unavailable", "detail": "gate not run"}
            gates[name] = gate
        status = gate["status"]
        if status == "fail":
            failed.add(name)
        elif status == "unavailable" and strict_unavailable:
            failed.add(name)

    return {"checked": True, "gates": gates, "failed": sorted(failed)}
