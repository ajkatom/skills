"""Hash-chained audit log (spec 7.5, M13). Stdlib only.

Each finalized manifest gets one linked entry appended to a per-control-root
ndjson chain at ``<control_root>/audit-chain.jsonl``:

    entry_core = {"invocation", "manifest_sha256", "ts"}
    chain_hash = sha256(canonical_json(entry_core) + prev_chain_hash)

Linking each entry's hash to the previous entry's hash means silently
deleting or editing any entry breaks every link computed from that point
forward — detectable by ``verify_chain``. Chaining alone is only
tamper-EVIDENT: a local process that can rewrite the chain file can also
recompute a fresh, internally-consistent chain over its own tampered
content. Passing ``audit_key`` additionally HMAC-signs (df_audit.sign) each
``chain_hash``, so forging a replacement link requires the M5a audit key —
see references/audit.md for the full trust-domain discussion (the true
tamper-resistance anchor is the off-box sink in df_audit_sink.py, not the
local chain file).
"""
import json
import os
import tempfile

import df_audit
import df_common

GENESIS = "0" * 64

# Fields hashed into chain_hash. Order doesn't matter (canonical_json sorts
# keys) but this tuple is also used to reconstruct entry_core from a stored
# entry and to validate that a parsed line carries everything required.
CORE_KEYS = ("invocation", "manifest_sha256", "ts")


class ChainError(RuntimeError):
    pass


def compute_chain_hash(entry_core: dict, prev_chain_hash: str) -> str:
    return df_common.sha256_str(df_common.canonical_json(entry_core) + prev_chain_hash)


def read_chain(chain_path: str) -> list:
    """Parse the ndjson chain file. Missing file -> []. A malformed line (bad
    JSON, not an object, or missing a required key) raises ChainError naming
    the 1-indexed line number."""
    if not os.path.exists(chain_path):
        return []
    entries = []
    with open(chain_path, encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                raise ChainError(
                    f"malformed audit chain at {chain_path} line {lineno}: {e}"
                )
            if not isinstance(entry, dict):
                raise ChainError(
                    f"malformed audit chain at {chain_path} line {lineno}: "
                    "entry is not a JSON object"
                )
            missing = [k for k in (*CORE_KEYS, "chain_hash") if k not in entry]
            if missing:
                raise ChainError(
                    f"malformed audit chain at {chain_path} line {lineno}: "
                    f"missing required key(s) {missing}"
                )
            entries.append(entry)
    return entries


def _write_chain_atomic(chain_path: str, entries: list) -> None:
    """Rewrite the whole chain file atomically (temp file + os.replace).
    df_common.atomic_write can't append a single line, and there is no
    partial-append primitive here — every append rewrites the full,
    already-validated entry list, so a crash mid-write leaves either the old
    file (temp never replaced it) or the new one (os.replace is atomic on
    POSIX), never a half-written line."""
    d = os.path.dirname(os.path.abspath(chain_path))
    os.makedirs(d, exist_ok=True)
    text = "".join(df_common.canonical_json(e) + "\n" for e in entries)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, chain_path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def append_entry(
    chain_path: str,
    invocation: str,
    manifest_sha256: str,
    ts: str,
    audit_key: bytes | None = None,
) -> dict:
    entries = read_chain(chain_path)
    prev_chain_hash = entries[-1]["chain_hash"] if entries else GENESIS
    entry_core = {
        "invocation": invocation,
        "manifest_sha256": manifest_sha256,
        "ts": ts,
    }
    chain_hash = compute_chain_hash(entry_core, prev_chain_hash)
    entry = dict(entry_core)
    entry["prev_chain_hash"] = prev_chain_hash
    entry["chain_hash"] = chain_hash
    if audit_key is not None:
        entry["sig"] = df_audit.sign(audit_key, chain_hash.encode("utf-8"))

    entries.append(entry)
    _write_chain_atomic(chain_path, entries)
    return entry


def verify_chain(chain_path: str, audit_key: bytes | None = None) -> tuple:
    try:
        entries = read_chain(chain_path)
    except ChainError as e:
        return False, str(e)

    if not entries:
        return True, "OK: 0 entries"

    prev_chain_hash = GENESIS
    for i, entry in enumerate(entries):
        label = entry.get("invocation", f"<entry {i}>")

        if entry.get("prev_chain_hash") != prev_chain_hash:
            return (
                False,
                f"entry {i} ({label}): broken link — prev_chain_hash does not "
                "match the preceding entry's chain_hash (edited or deleted entry)",
            )

        entry_core = {k: entry.get(k) for k in CORE_KEYS}
        expected_hash = compute_chain_hash(entry_core, prev_chain_hash)
        if entry.get("chain_hash") != expected_hash:
            return (
                False,
                f"entry {i} ({label}): chain_hash does not match its content "
                "(tampered entry)",
            )

        if audit_key is not None:
            sig = entry.get("sig")
            if not sig or not df_audit.verify(
                audit_key, entry["chain_hash"].encode("utf-8"), sig
            ):
                return (
                    False,
                    f"entry {i} ({label}): missing or invalid signature",
                )

        prev_chain_hash = entry["chain_hash"]

    return True, f"OK: {len(entries)} entries"
