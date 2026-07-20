"""M63 (Codex R6): startup correctness.

  * DF-R6-06 — the supervisor enforces a Python 3.10 floor with an ACTIONABLE
    error before the df_* imports that would otherwise crash with an opaque
    `TypeError: unsupported operand type(s) for |` on 3.9.
  * DF-R6-05 — a real standard-tier supervisor run launched from a denied
    $HOME-resident CWD passes the default-deny probe (the probe child runs
    with cwd=workspace), instead of failing closed before the build.
"""
import json
import os
import subprocess
import sys

import pytest

import df_sandbox
import supervisor
from test_supervisor import FAKE, setup_control, stub_network_probe

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")

_macos = df_sandbox.BACKENDS["darwin"]
needs_live = pytest.mark.skipif(
    sys.platform != "darwin" or not _macos.available(),
    reason="live macOS sandbox-exec required")


def _find_python39():
    for cand in ("/usr/bin/python3", "python3.9"):
        try:
            out = subprocess.run([cand, "-c",
                                  "import sys;print('%d.%d'%sys.version_info[:2])"],
                                 capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                maj, min = (int(x) for x in out.stdout.strip().split("."))
                if (maj, min) < (3, 10):
                    return cand
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
    return None


def test_python_floor_gives_an_actionable_error_not_a_type_error():
    py39 = _find_python39()
    if py39 is None:
        pytest.skip("no Python < 3.10 available to prove the floor message")
    out = subprocess.run([py39, SUP, "--help"], capture_output=True, text=True, timeout=30)
    assert out.returncode == 2, out
    assert "requires Python 3.10 or newer" in out.stderr
    # the OLD failure mode (opaque TypeError at import) must be gone:
    assert "unsupported operand type" not in out.stderr


def test_supported_interpreter_runs_help():
    out = subprocess.run([sys.executable, SUP, "--help"],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0
    assert "usage:" in out.stdout.lower()


@needs_live
def test_standard_run_from_a_denied_home_cwd_converges(tmp_path, monkeypatch):
    # DF-R6-05 end-to-end: the supported invocation from a $HOME-resident CWD
    # (which the default-deny profile denies) must reach the build/verify loop,
    # not fail closed on a probe that inherited the denied directory.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "standard"
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    stub_network_probe(monkeypatch)
    monkeypatch.chdir(os.path.expanduser("~"))
    rc = supervisor.run(str(cr), None)
    # converges (0) — the point is it did NOT fail-closed at the probe (2).
    assert rc == 0, "a standard run from a denied CWD must reach + pass the loop"
    run_id = os.listdir(cr / "runs")[0]
    mf = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert mf["denial_probe_passed"] is True
