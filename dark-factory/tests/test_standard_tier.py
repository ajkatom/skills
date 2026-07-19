import json
import os
import sys

import pytest

import df_sandbox
import supervisor
from test_supervisor import FAKE, STUBBORN, setup_control, stub_network_probe

HERE = os.path.dirname(os.path.abspath(__file__))
READS_PROMPT = os.path.join(HERE, "fixtures", "fake_builder_reads_prompt")


def _std(tmp_path, candidate_network=None, **kw):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto", **kw)
    # rewrite assurance to standard
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"
    # M47 RA-08(a): a qualifying run needs a CONFINED candidate network.
    if candidate_network is not None:
        cfg["candidate_network"] = candidate_network
    p.write_text(json.dumps(cfg))
    return cr


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_run_converges_qualified_when_probe_passes(tmp_path, monkeypatch):
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    # M47 RA-08(a): confine candidate egress so the run can QUALIFY; stub the
    # egress-denial probe so this stays hermetic (no external connection).
    cr = _std(tmp_path, candidate_network="deny")
    stub_network_probe(monkeypatch)
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
def test_standard_resume_stays_qualified_and_reprobes(tmp_path, monkeypatch):
    # DEFAULT standard flow: autonomy 4 → pause → resume finalizes. resume MUST
    # re-probe + re-wrap, else the resumed build/verify runs UNSANDBOXED and the
    # qualified claim is a lie. This pins that path.
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    # M47 RA-08(a): confine candidate egress to QUALIFY; stub the probe (hermetic).
    cr = _std(tmp_path, candidate_network="deny")   # _std sets checkpoint="auto"...
    stub_network_probe(monkeypatch)
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["checkpoint"] = "pause"; p.write_text(json.dumps(cfg))
    assert supervisor.run(str(cr), None) == 10          # paused at iteration 1
    # M36b: H2 converges into a before-ship pause; the seal-reentry re-probes
    # isolation + re-runs gates over the frozen object, then seals qualified.
    assert supervisor.resume(str(cr), "continue") == 10  # converged -> AWAIT_SHIP
    assert supervisor.resume(str(cr), "continue") == 0   # seal-reentry
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "COMPLETE_QUALIFIED" and m["qualified"] is True
    assert m["denial_probe_passed"] is True


# --- M2b-7 regression: qualified:true must never leak onto a non-converged
# standard-tier terminal. Standard registers qualified:true in the tier
# registry, so every finalize_manifest call that inherits manifest_base
# without an explicit override is a false-qualification bug. These pin the
# three non-converged terminals reachable without disabling the sandbox.

def test_standard_snapshot_failure_is_not_qualified(tmp_path):
    # SnapshotError abort happens BEFORE isolation is resolved (resolve_isolation
    # runs after the snapshot block), so manifest_base still carries the raw
    # registry qualified:true for standard. The finalize site must force False.
    cr = _std(tmp_path)
    src = tmp_path / "badsrc"
    src.mkdir()
    real = src / "real.txt"
    real.write_text("x", encoding="utf-8")
    os.symlink(real, src / "link.txt")  # snapshot_source rejects symlinks
    rc = supervisor.run(str(cr), str(src))
    assert rc == 2
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "ABORTED_BUILD_ERROR"
    assert m["qualified"] is False


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_resume_abort_is_not_qualified(tmp_path):
    # decision=="abort" finalizes BEFORE the continue-only resolve_isolation
    # re-probe, so it too inherits raw registry qualified:true unless forced.
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    cr = setup_control(tmp_path, FAKE)  # default autonomy 4 -> checkpoint pause
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"; p.write_text(json.dumps(cfg))
    assert supervisor.run(str(cr), None) == 10  # paused at iteration 1
    assert supervisor.resume(str(cr), "abort") == 2
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "ABORTED_BY_HUMAN"
    assert m["qualified"] is False


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_cap_is_not_qualified(tmp_path):
    # CAP_REACHED means the loop never converged, even though isolation WAS
    # resolved+probed successfully — qualified must still be forced False.
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    cr = setup_control(tmp_path, STUBBORN, max_iterations=2, checkpoint="auto")
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"; p.write_text(json.dumps(cfg))
    rc = supervisor.run(str(cr), None)
    assert rc == 3
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["outcome"] == "CAP_REACHED"
    assert m["qualified"] is False


# --- C1 regression: under standard, the wrapped builder must be able to read
# ITS OWN PROMPT FILE. The real scripts/adapters/claude adapter does
# open(req["prompt_file"]); if prompt_file lives under control_root (denied
# root), that open() hits PermissionError under the sandbox and every standard
# build aborts (exit 2) — the QUALIFIED outcome is unreachable in production.
# fake_builder_reads_prompt models that real adapter behavior (it actually
# opens and reads prompt_file) so this test is RED against the bug and GREEN
# once the supervisor writes the working prompt copy into the workspace.

@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_prompt_reading_adapter_converges_qualified(tmp_path, monkeypatch):
    if not (df_sandbox.current_backend() and df_sandbox.current_backend().available()):
        pytest.skip("no OS sandbox primitive")
    cr = setup_control(tmp_path, READS_PROMPT, checkpoint="auto")
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"
    # M47 RA-08(a): confine candidate egress to QUALIFY; stub the probe (hermetic).
    cfg["candidate_network"] = "deny"; p.write_text(json.dumps(cfg))
    stub_network_probe(monkeypatch)
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    run_id = os.listdir(cr / "runs")[0]
    m = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert m["qualified"] is True
    assert m["outcome"] == "COMPLETE_QUALIFIED"
