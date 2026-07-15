"""Credential broker for dark-factory: allowlisted sources (env-file, macOS
keychain, launcher env), gitignore/permission verification, and artifact
redaction. Stdlib only.

Fail-closed discipline: any uncertainty about resolving a credential raises
CredsError. There is exactly one deliberate exception, documented in
check_gitignored: when git itself is genuinely absent (OSError launching it)
or git cleanly reports the env-file's directory is not inside any work tree,
there is no repository to leak the file into, so verification passes. Every
other git failure (timeout, dubious ownership, permissions, corruption) is
uncertainty and fails closed.
"""
import os
import subprocess
import sys


class CredsError(RuntimeError):
    """Raised whenever a credential cannot be resolved safely."""


def parse_env_file(path: str) -> dict:
    """Parse a KEY=VALUE env-file.

    Blank lines and #-comments are ignored. A leading `export ` is stripped.
    Values may be optionally wrapped in matching single or double quotes,
    which are stripped. Refuses (CredsError) if the file is missing or is
    group/world-readable (mode & 0o077 != 0). A malformed line (no '=', or
    an empty key) raises CredsError naming the line number.
    """
    if not os.path.isfile(path):
        raise CredsError(f"env-file not found: {path}")

    mode = os.stat(path).st_mode
    if mode & 0o077 != 0:
        raise CredsError(
            f"env-file {path} has overly permissive permissions "
            f"(mode {oct(mode & 0o777)}); fix with: chmod 600 {path}"
        )

    result = {}
    with open(path, "r") as f:
        lines = f.readlines()

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip("\n").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        # NOTE: malformed-line errors must NEVER include the line content —
        # a malformed line is often a pasted bare token, and this message
        # flows to stderr via the supervisor's credential-refusal path.
        if "=" not in line:
            raise CredsError(
                f"{path}:{lineno}: malformed line (expected KEY=VALUE)"
            )
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            raise CredsError(
                f"{path}:{lineno}: malformed line (expected KEY=VALUE)"
            )
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[key] = value
    return result


def check_gitignored(path: str, runner=subprocess.run) -> None:
    """Verify an env-file is safe to use from inside a git work tree.

    If the file's directory is inside a git work tree: `git ls-files
    --error-unmatch` must FAIL (the file is not already tracked — tracking
    predates any gitignore rule and would still leak history), AND `git
    check-ignore -q` must pass (the file is ignored).

    The ONLY fail-open cases are the ones where no repository exists to
    leak through: git binary genuinely absent (OSError launching it), or
    git cleanly reporting "not a git repository". Anything else that stops
    us from answering — a hung git (timeout), dubious-ownership refusals,
    permission errors, repo corruption — is uncertainty, and uncertainty
    fails closed (CredsError).
    """
    abspath = os.path.abspath(path)
    directory = os.path.dirname(abspath)

    def _git(argv):
        # Once we know a work tree exists, every failure to answer is
        # uncertainty and fails closed. A hung git (timeout) is uncertainty
        # even before that — only a genuinely ABSENT git binary is safe.
        try:
            return runner(argv, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            raise CredsError(
                f"git timed out while verifying env-file {abspath} is "
                f"git-ignored; fix git in {directory} before running"
            )
        except OSError as e:
            raise CredsError(
                f"git failed while verifying env-file {abspath} is "
                f"git-ignored ({e.__class__.__name__}); fix git in "
                f"{directory} before running"
            )

    try:
        worktree = runner(
            ["git", "-C", directory, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
    except OSError:
        return  # git binary absent — no repo to leak through (documented)
    except subprocess.TimeoutExpired:
        raise CredsError(
            f"git timed out while verifying env-file {abspath} is "
            f"git-ignored; fix git in {directory} before running"
        )

    if worktree.returncode != 0:
        stderr = worktree.stderr or ""
        if "not a git repository" in stderr.lower():
            return  # cleanly outside any work tree — the documented fail-open
        raise CredsError(
            f"git could not determine whether env-file {abspath} is inside a "
            f"work tree (exit {worktree.returncode}); fix git in {directory} "
            f"(ownership/permissions/repository state) before running"
        )
    if worktree.stdout.strip() != "true":
        return  # inside a .git dir, not a work tree — nothing checked out to leak

    # Tracked status must be checked BEFORE trusting check-ignore: git
    # deliberately reports an already-tracked path as "not ignored" (rc 1)
    # regardless of matching .gitignore patterns, since ignore rules never
    # apply to paths already in the index. Checking tracked status first
    # gives the more specific, more urgent diagnostic in that case.
    tracked_result = _git(["git", "-C", directory, "ls-files", "--error-unmatch", abspath])
    if tracked_result.returncode == 0:
        raise CredsError(
            f"env-file {abspath} is git-TRACKED; remove it from the index "
            f"(git rm --cached) and gitignore it"
        )

    ignore_result = _git(["git", "-C", directory, "check-ignore", "-q", abspath])
    if ignore_result.returncode != 0:
        raise CredsError(
            f"env-file {abspath} is inside a git repository but not git-ignored; "
            f"add it to .gitignore before running"
        )


def keychain_lookup(service: str, runner=subprocess.run) -> str:
    """Look up a secret from the macOS keychain via the `security` CLI."""
    if sys.platform != "darwin":
        raise CredsError("keychain source requires macOS in M11")

    try:
        result = runner(
            ["security", "find-generic-password", "-s", service, "-w"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CredsError(f"keychain lookup for {service!r} failed: {e}")

    if result.returncode != 0:
        raise CredsError(
            f"keychain lookup for {service!r} failed (exit {result.returncode})"
        )

    value = result.stdout.strip()
    if not value:
        raise CredsError(f"keychain lookup for {service!r} returned an empty value")
    return value


def load_credentials(spec: dict, runner=subprocess.run) -> dict:
    """Resolve every name in spec['allowlist'] from spec['source'].

    Returns exactly {name: value} for the allowlisted names — never more,
    never a missing or empty value (all such cases raise CredsError).
    """
    source = spec["source"]
    allowlist = spec["allowlist"]
    result = {}

    if source == "env-file":
        env_file = spec["env_file"]
        check_gitignored(env_file, runner=runner)
        values = parse_env_file(env_file)
        for name in allowlist:
            if name not in values:
                raise CredsError(
                    f"credential {name!r} not found in env-file {env_file}"
                )
            result[name] = values[name]

    elif source == "keychain":
        prefix = spec.get("service_prefix", "dark-factory/")
        for name in allowlist:
            result[name] = keychain_lookup(f"{prefix}{name}", runner=runner)

    elif source == "env":
        for name in allowlist:
            try:
                result[name] = os.environ[name]
            except KeyError:
                raise CredsError(
                    f"credential {name!r} not set in launcher environment"
                )

    else:
        raise CredsError(f"unknown credential source: {source!r}")

    for name, value in result.items():
        if not value:
            raise CredsError(f"credential {name!r} resolved to an empty value")

    return result


class Redactor:
    """Redacts credential values out of text and nested data structures.

    Values shorter than 6 characters are dropped — redacting them would
    also strike common substrings unrelated to any credential. Remaining
    values are matched longest-first so that when one value is itself a
    substring of another, the longer value is fully consumed first and no
    partial fragment of it can leak out from underneath.
    """

    MIN_LEN = 6
    PLACEHOLDER = "***REDACTED***"

    def __init__(self, values):
        seen = set()
        kept = []
        for v in values:
            if isinstance(v, str) and len(v) >= self.MIN_LEN and v not in seen:
                seen.add(v)
                kept.append(v)
        kept.sort(key=len, reverse=True)
        self._values = kept

    def redact(self, text):
        if not isinstance(text, str):
            return text
        for value in self._values:
            if value in text:
                text = text.replace(value, self.PLACEHOLDER)
        return text

    def redact_obj(self, obj):
        if isinstance(obj, dict):
            # Keys are a leak surface too (e.g. {token: "seen at ..."}).
            return {
                (self.redact(k) if isinstance(k, str) else k): self.redact_obj(v)
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [self.redact_obj(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.redact_obj(v) for v in obj)
        if isinstance(obj, str):
            return self.redact(obj)
        return obj
