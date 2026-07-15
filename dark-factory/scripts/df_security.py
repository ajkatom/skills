"""Stdlib security scanners over a directory (M9 Task 1).

Pure functions: `secret_scan`, `dangerous_scan`, `sbom`. All walk a
directory deterministically (sorted, skip `.git`, skip symlinks, skip
binary files detected by a NUL byte in the first read chunk), use only
stdlib (`re`, `os`, `json`), do no network I/O, and return sorted,
deterministic output.

Honest scope: these are heuristic, pattern-based scanners — a floor,
not a full SAST/secret-detection engine. `secret_scan` findings record
the RULE NAME ONLY, never the matched secret value.
"""
import json
import os
import re
import shutil
import subprocess

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
