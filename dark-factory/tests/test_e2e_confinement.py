"""M14-3 e2e: the airtight builder confinement proof.

  (a) DETERMINISTIC (always runs, no live CLI, no network): a control with
      `builder_confinement:{enabled:true,required:true}` and
      `roles.builder.adapter` pointed at the REAL gemini adapter script
      (`df_confine.PROFILES["gemini"]["supported"] is False`) drives the
      actual `supervisor.py` CLI as a subprocess (matching
      test_e2e_final_exam.py / test_e2e_hardened.py's pattern). The gemini
      adapter fails closed BEFORE it ever spawns (or even checks for) the
      gemini CLI, so this is deterministic on any machine regardless of
      whether gemini is installed. Asserts: exit 2, journal
      CONFINEMENT_UNSUPPORTED, manifest outcome CONFINEMENT_REFUSED, and
      that the builder workspace never received an artifact (proof the
      builder CLI was never spawned at all, not merely that it "failed").

  (b) LIVE (opt-in `DF_LIVE_CONFINE=1`, skipif unset OR the CLI is absent
      from PATH): `df_confine.probe_confinement("claude", tmp)` and
      `df_confine.probe_confinement("codex", tmp)` each call the REAL
      installed CLI under its confinement profile and assert (True,
      "verified") — the airtight, observable-side-effect evidence that a
      denied tool (Bash for claude; MCP for codex) is actually blocked, not
      merely that a flag was passed. These are slow (real model calls) and
      cost tokens, so they are excluded from the default suite and run
      during milestone acceptance (see the task report for the real
      observed result of each run).
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

import df_confine
from test_supervisor import setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
GEMINI_ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "gemini")

LIVE = os.environ.get("DF_LIVE_CONFINE") == "1"


def _run_cli(cr, *args, timeout=60):
    return subprocess.run(
        [sys.executable, SUP, *args, "--control-root", str(cr)],
        capture_output=True, text=True, timeout=timeout,
    )


def _set_confine_required(cr):
    cfg = json.loads((cr / "config.json").read_text())
    cfg["builder_confinement"] = {"enabled": True, "required": True}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")


def _journal(cr, run_id):
    lines = (cr / "runs" / run_id / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in lines.strip().splitlines()]


def test_fail_closed_refusal_e2e_gemini_never_spawned(tmp_path):
    """The gemini adapter has no probe-verified confinement profile
    (df_confine.PROFILES["gemini"]["supported"] is False). At a
    confinement-required tier, the real supervisor CLI must refuse the run
    fail-closed WITHOUT ever spawning the gemini CLI — proven here by the
    workspace never receiving a build artifact."""
    assert df_confine.is_supported("gemini") is False  # sanity: this test is non-vacuous

    cr = setup_control(tmp_path, GEMINI_ADAPTER, checkpoint="auto")
    _set_confine_required(cr)

    proc = _run_cli(cr, "run")
    assert proc.returncode == 2, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"

    run_ids = os.listdir(cr / "runs")
    assert len(run_ids) == 1
    run_id = run_ids[0]

    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["outcome"] == "CONFINEMENT_REFUSED"
    assert manifest["qualified"] is False
    assert manifest["builder_confinement"]["enabled"] is True

    entries = _journal(cr, run_id)
    states = [e["state"] for e in entries]
    assert "CONFINEMENT_UNSUPPORTED" in states
    assert "BUILD" not in states  # the builder call never reached a build step

    # The builder CLI was never spawned at all: no workspace, no artifact.
    ws_dir = os.path.join(str(tmp_path / "ws"), run_id)
    assert not os.path.exists(os.path.join(ws_dir, "greet.py"))


# ---------------------------------------------------------------------------
# Live probe — THE airtight evidence. Opt-in only; never part of the default
# suite (`DF_LIVE_CONFINE=1` gates it; the CLI must also be on PATH).
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not LIVE, reason="set DF_LIVE_CONFINE=1 to run the live confinement probe")
@pytest.mark.skipif(shutil.which("claude") is None, reason="claude CLI not on PATH")
def test_live_probe_claude_blocks_bash(tmp_path):
    ok, reason = df_confine.probe_confinement("claude", str(tmp_path), timeout_s=300)
    assert (ok, reason) == (True, "verified"), (
        f"claude confinement probe did not verify: ok={ok} reason={reason!r} "
        f"workdir={tmp_path} allowed={os.path.exists(os.path.join(str(tmp_path), 'ALLOWED_PROOF'))} "
        f"denied={os.path.exists(os.path.join(str(tmp_path), 'DENIED_PROOF'))}"
    )


@pytest.mark.skipif(not LIVE, reason="set DF_LIVE_CONFINE=1 to run the live confinement probe")
@pytest.mark.skipif(shutil.which("codex") is None, reason="codex CLI not on PATH")
def test_live_probe_codex_blocks_mcp(tmp_path):
    # codex's xhigh reasoning effort occasionally runs well past 180s on the
    # denied-tool call (observed live during acceptance); 300s gives headroom
    # without weakening the fail-closed contract -- a genuine hang still times
    # out and reports (False, "probe spawn failed: ...timed out...").
    ok, reason = df_confine.probe_confinement("codex", str(tmp_path), timeout_s=300)
    assert (ok, reason) == (True, "verified"), (
        f"codex confinement probe did not verify: ok={ok} reason={reason!r} "
        f"workdir={tmp_path} allowed={os.path.exists(os.path.join(str(tmp_path), 'ALLOWED_PROOF'))} "
        f"denied={os.path.exists(os.path.join(str(tmp_path), 'DENIED_PROOF'))}"
    )
