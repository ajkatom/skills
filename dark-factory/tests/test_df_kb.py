import os

import pytest

import df_kb

MARKER = "HOLDOUT-MARKER-93e1"


def manifest(**over):
    m = {"invocation": "20260714T000000Z-abcd1234", "finished_ts": "2026-07-14T00:00:01Z",
         "outcome": "CAP_REACHED", "tier": "standard", "qualified": False, "iterations": 3}
    m.update(over)
    return m


def test_build_summary_contains_only_safe_fields():
    s = df_kb.build_summary(manifest(), ["BHV-002", "BHV-001"])
    assert "CAP_REACHED" in s and "standard" in s and "BHV-001" in s and "BHV-002" in s
    assert "20260714T000000Z-abcd1234" in s


def test_build_summary_rejects_non_behavior_id():
    with pytest.raises(df_kb.KBLeakError):
        df_kb.build_summary(manifest(), [f"expected {MARKER}"])


def test_write_run_summary_wiki_appends(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    kb = {"kind": "wiki", "path": str(wiki), "write_back": True}
    p1 = df_kb.write_run_summary(kb, manifest(), ["BHV-001"])
    p2 = df_kb.write_run_summary(kb, manifest(outcome="COMPLETE_QUALIFIED", qualified=True), [])
    assert p1 == p2 == os.path.join(str(wiki), "dark-factory-runs.md")
    body = open(p1, encoding="utf-8").read()
    assert body.count("## dark-factory run") == 2  # appended, not overwritten
    assert "COMPLETE_QUALIFIED" in body


def test_write_run_summary_noop_when_disabled(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    assert df_kb.write_run_summary({"kind": "wiki", "path": str(wiki), "write_back": False}, manifest(), []) is None
    assert df_kb.write_run_summary({"kind": "none", "path": "", "write_back": True}, manifest(), []) is None
    assert df_kb.write_run_summary({"kind": "open-brain", "path": "", "write_back": True}, manifest(), []) is None
    assert not (wiki / "dark-factory-runs.md").exists()


def test_write_run_summary_never_leaks_marker(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    kb = {"kind": "wiki", "path": str(wiki), "write_back": True}
    # a manifest polluted with marker-bearing fields must not leak them into the wiki
    m = manifest(spec_sha256=MARKER, extra_note=f"secret {MARKER}")
    df_kb.write_run_summary(kb, m, ["BHV-001"])
    assert MARKER not in open(wiki / "dark-factory-runs.md", encoding="utf-8").read()
