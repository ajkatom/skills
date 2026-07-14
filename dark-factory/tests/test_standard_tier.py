import json
import os
import sys

import pytest

import df_sandbox
import supervisor
from test_supervisor import FAKE, setup_control


def _std(tmp_path, **kw):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto", **kw)
    # rewrite assurance to standard
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"; p.write_text(json.dumps(cfg))
    return cr


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_run_converges_qualified_when_probe_passes(tmp_path):
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    cr = _std(tmp_path)
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_QUALIFIED"
    assert m["qualified"] is True
    assert m["denial_probe_passed"] is True
    assert m["sandbox_backend"] in ("macos-sandbox-exec", "linux-bwrap")


def test_standard_fails_closed_when_probe_fails(tmp_path, monkeypatch):
    cr = _std(tmp_path)
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: False)
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend",
                        lambda: df_sandbox.BACKENDS["linux"])  # a real backend object
    assert supervisor.run(str(cr), None) == 2  # fail closed, no downgrade flag
    run_id = os.listdir(cr / "runs")[0]
    states = [json.loads(l)["state"] for l in (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    assert "PROBE_FAILED" in states


def test_standard_downgrades_with_flag(tmp_path, monkeypatch):
    cr = _std(tmp_path)
    monkeypatch.setattr(supervisor.df_sandbox, "probe_denial", lambda *a, **k: False)
    monkeypatch.setattr(supervisor.df_sandbox, "current_backend",
                        lambda: df_sandbox.BACKENDS["linux"])
    assert supervisor.run(str(cr), None, allow_downgrade=True) == 0
    run_id = os.listdir(cr / "runs")[0]
    entries = [json.loads(l) for l in (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    states = [e["state"] for e in entries]
    assert "DOWNGRADE" in states
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["qualified"] is False and m["outcome"] == "COMPLETE_UNQUALIFIED"


def test_cooperative_unaffected(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # cooperative default
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["qualified"] is False and m["outcome"] == "COMPLETE_UNQUALIFIED"
    assert m["sandbox_backend"] is None


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_resume_stays_qualified_and_reprobes(tmp_path):
    # DEFAULT standard flow: autonomy 4 → pause → resume finalizes. resume MUST
    # re-probe + re-wrap, else the resumed build/verify runs UNSANDBOXED and the
    # qualified claim is a lie. This pins that path.
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    cr = _std(tmp_path)                      # _std sets checkpoint="auto"...
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["checkpoint"] = "pause"; p.write_text(json.dumps(cfg))
    assert supervisor.run(str(cr), None) == 10          # paused at iteration 1
    assert supervisor.resume(str(cr), "continue") == 0  # resume re-probes, converges
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_QUALIFIED" and m["qualified"] is True
    assert m["denial_probe_passed"] is True
