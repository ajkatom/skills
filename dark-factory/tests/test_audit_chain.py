import json
import os

import pytest

import df_audit_chain as chain


def _append_three(path, audit_key=None):
    e1 = chain.append_entry(path, "inv-1", "a" * 64, "2026-07-15T00:00:00Z", audit_key)
    e2 = chain.append_entry(path, "inv-2", "b" * 64, "2026-07-15T00:01:00Z", audit_key)
    e3 = chain.append_entry(path, "inv-3", "c" * 64, "2026-07-15T00:02:00Z", audit_key)
    return e1, e2, e3


def test_compute_chain_hash_matches_manual_sha256():
    import df_common

    core = {"invocation": "inv-1", "manifest_sha256": "a" * 64, "ts": "2026-07-15T00:00:00Z"}
    expected = df_common.sha256_str(df_common.canonical_json(core) + chain.GENESIS)
    assert chain.compute_chain_hash(core, chain.GENESIS) == expected


def test_read_chain_missing_file_returns_empty(tmp_path):
    assert chain.read_chain(str(tmp_path / "nope.jsonl")) == []


def test_append_three_and_read_chain_links(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    e1, e2, e3 = _append_three(path)

    entries = chain.read_chain(path)
    assert len(entries) == 3
    assert entries[0]["prev_chain_hash"] == chain.GENESIS
    assert entries[1]["prev_chain_hash"] == entries[0]["chain_hash"]
    assert entries[2]["prev_chain_hash"] == entries[1]["chain_hash"]
    assert entries[0]["invocation"] == "inv-1"
    assert entries[-1] == e3


def test_verify_chain_ok_on_untampered_chain(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    _append_three(path)
    ok, msg = chain.verify_chain(path)
    assert ok is True
    assert msg == "OK: 3 entries"


def test_verify_chain_empty_or_missing_is_ok(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    ok, msg = chain.verify_chain(path)
    assert ok is True


def test_verify_chain_detects_tampered_manifest_sha256(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    _append_three(path)

    entries = chain.read_chain(path)
    entries[1]["manifest_sha256"] = "f" * 64  # tamper middle entry's payload only
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    ok, msg = chain.verify_chain(path)
    assert ok is False
    assert "inv-2" in msg


def test_verify_chain_detects_deleted_middle_entry(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    _append_three(path)

    entries = chain.read_chain(path)
    del entries[1]  # silently delete the middle entry
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    ok, msg = chain.verify_chain(path)
    assert ok is False


def test_signed_chain_has_sig_and_verifies(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    key = b"\x01" * 32
    _append_three(path, audit_key=key)

    entries = chain.read_chain(path)
    assert all("sig" in e for e in entries)

    ok, msg = chain.verify_chain(path, audit_key=key)
    assert ok is True
    assert msg == "OK: 3 entries"


def test_signed_chain_stripped_sig_fails_verify(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    key = b"\x01" * 32
    _append_three(path, audit_key=key)

    entries = chain.read_chain(path)
    del entries[1]["sig"]
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    ok, msg = chain.verify_chain(path, audit_key=key)
    assert ok is False


def test_signed_chain_wrong_key_fails_verify(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    key = b"\x01" * 32
    wrong_key = b"\x02" * 32
    _append_three(path, audit_key=key)

    ok, msg = chain.verify_chain(path, audit_key=wrong_key)
    assert ok is False


def test_malformed_ndjson_line_raises_chain_error(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    _append_three(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write("{not valid json\n")

    with pytest.raises(chain.ChainError) as excinfo:
        chain.read_chain(path)
    assert "4" in str(excinfo.value)  # line number of the malformed line


def test_entry_missing_required_keys_raises_chain_error(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"invocation": "inv-1"}) + "\n")

    with pytest.raises(chain.ChainError):
        chain.read_chain(path)


def test_crash_safety_double_append_always_parseable(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    chain.append_entry(path, "inv-1", "a" * 64, "2026-07-15T00:00:00Z")
    # File must be fully parseable after each atomic rewrite - no leftover
    # temp files, no partial/truncated lines.
    entries_after_first = chain.read_chain(path)
    assert len(entries_after_first) == 1

    tmp_files_after_first = [p for p in os.listdir(str(tmp_path)) if p.startswith(".tmp-")]
    assert tmp_files_after_first == []

    chain.append_entry(path, "inv-2", "b" * 64, "2026-07-15T00:01:00Z")
    entries_after_second = chain.read_chain(path)
    assert len(entries_after_second) == 2

    tmp_files_after_second = [p for p in os.listdir(str(tmp_path)) if p.startswith(".tmp-")]
    assert tmp_files_after_second == []

    with open(path, encoding="utf-8") as f:
        text = f.read()
    assert text.endswith("\n")
    for line in text.strip("\n").split("\n"):
        json.loads(line)  # every line is valid, standalone JSON


def test_append_entry_returns_full_entry_dict(tmp_path):
    path = str(tmp_path / "audit-chain.jsonl")
    entry = chain.append_entry(path, "inv-1", "a" * 64, "2026-07-15T00:00:00Z")
    assert entry["invocation"] == "inv-1"
    assert entry["manifest_sha256"] == "a" * 64
    assert entry["ts"] == "2026-07-15T00:00:00Z"
    assert entry["prev_chain_hash"] == chain.GENESIS
    assert "chain_hash" in entry
    assert "sig" not in entry  # unsigned when no audit_key given
