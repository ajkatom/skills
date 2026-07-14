import json

import pytest

import df_config
from test_config import write_config  # reuse the existing helper


def test_absent_kb_defaults_to_none(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_kb"] == {"kind": "none", "path": "", "write_back": False}


def test_wiki_kb_requires_existing_dir(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "wiki", "path": str(tmp_path / "nope")})
    with pytest.raises(df_config.ConfigError, match="wiki"):
        df_config.load_config(str(cr))


def test_wiki_kb_valid(tmp_path):
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "wiki", "path": str(wiki), "write_back": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_kb"] == {"kind": "wiki", "path": str(wiki), "write_back": True}


def test_open_brain_kb_needs_no_path(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "open-brain"})
    cfg = df_config.load_config(str(cr))
    assert cfg["_kb"]["kind"] == "open-brain" and cfg["_kb"]["write_back"] is False


def test_bad_kb_kind_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "notion"})
    with pytest.raises(df_config.ConfigError, match="knowledge_base"):
        df_config.load_config(str(cr))


def test_kb_write_back_must_be_bool(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "open-brain", "write_back": "yes"})
    with pytest.raises(df_config.ConfigError, match="write_back"):
        df_config.load_config(str(cr))
