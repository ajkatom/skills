import json
import os

import supervisor
from test_supervisor import FAKE, STUBBORN, setup_control  # existing helpers


def _wiki_cfg(tmp_path, adapter, wiki, **over):
    cr = setup_control(tmp_path, adapter, checkpoint="auto", **over)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["knowledge_base"] = {"kind": "wiki", "path": str(wiki), "write_back": True}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def test_converged_run_appends_wiki_summary(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = _wiki_cfg(tmp_path, FAKE, wiki)
    assert supervisor.run(str(cr), None) == 0
    body = (wiki / "dark-factory-runs.md").read_text(encoding="utf-8")
    assert "## dark-factory run" in body and "failing behaviors: none" in body


def test_cap_run_appends_failing_behaviors(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = _wiki_cfg(tmp_path, STUBBORN, wiki, max_iterations=2)
    assert supervisor.run(str(cr), None) == 3
    body = (wiki / "dark-factory-runs.md").read_text(encoding="utf-8")
    assert "CAP_REACHED" in body and "BHV-001" in body


def test_no_writeback_when_disabled(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # no knowledge_base block
    assert supervisor.run(str(cr), None) == 0
    assert not (wiki / "dark-factory-runs.md").exists()


def test_writeback_failure_does_not_crash_run(tmp_path):
    # point the wiki at a dir, then make the summary file unwritable by removing the dir mid-config:
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = _wiki_cfg(tmp_path, FAKE, wiki)
    os.chmod(wiki, 0o500)  # read+exec only → append fails
    try:
        rc = supervisor.run(str(cr), None)
    finally:
        os.chmod(wiki, 0o700)
    assert rc == 0  # KB failure never changes the exit code
    run_id = os.listdir(cr / "runs")[0]
    journal = (cr / "runs" / run_id / "journal.jsonl").read_text()
    assert "KB_WRITEBACK_ERROR" in journal


def test_kb_writeback_tolerates_any_exception(tmp_path, monkeypatch):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = _wiki_cfg(tmp_path, FAKE, wiki)
    import df_kb
    monkeypatch.setattr(df_kb, "write_run_summary", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    assert "KB_WRITEBACK_ERROR" in (cr / "runs" / run_id / "journal.jsonl").read_text()
