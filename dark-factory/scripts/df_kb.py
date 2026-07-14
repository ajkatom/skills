"""Barrier-safe knowledge-base write-back (spec 3A). Stdlib only.

Appends a run summary to a wiki file. The summary is built from an ALLOWLIST
of manifest fields plus failing behavior IDs — it structurally cannot carry
scenario text, observed output, or prompts, because it never reads them.
open-brain (MCP) write-back is performed by the Claude session, not here.
"""
import os
import re

BEHAVIOR_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")
_SUMMARY_FILE = "dark-factory-runs.md"


class KBLeakError(ValueError):
    pass


def build_summary(manifest: dict, failing_behaviors: list) -> str:
    for b in failing_behaviors:
        if not BEHAVIOR_RE.fullmatch(b):
            raise KBLeakError(f"failing_behaviors must be BHV ids only (offending value withheld)")
    failing = ", ".join(sorted(failing_behaviors)) if failing_behaviors else "none"
    return (
        f"## dark-factory run {manifest.get('finished_ts') or manifest.get('invocation', '')}\n"
        f"- invocation: `{manifest.get('invocation', '')}`\n"
        f"- outcome: **{manifest.get('outcome', '')}**\n"
        f"- tier: {manifest.get('tier', '')}  qualified: {manifest.get('qualified', '')}\n"
        f"- iterations: {manifest.get('iterations', '')}\n"
        f"- failing behaviors: {failing}\n"
    )


def write_run_summary(kb: dict, manifest: dict, failing_behaviors: list):
    if kb.get("kind") != "wiki" or not kb.get("write_back"):
        return None
    path = os.path.join(kb["path"], _SUMMARY_FILE)
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n" + build_summary(manifest, failing_behaviors))
    return path
