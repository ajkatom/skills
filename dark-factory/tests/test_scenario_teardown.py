"""DF-02 / M29a Task 2: CLI scenarios (run_scenario's `when.run` path) must
reap their FULL process tree on completion/timeout, exactly like
`_run_http_scenario` already does for `when.http` scenarios. Before this
fix, `run_scenario` used bare `subprocess.run(...)` with no new session and
no process-group reap -- a candidate that backgrounds a child (even without
setsid/double-forking) leaves it running forever after the scenario
"completes". See run_scenarios.run_scenario / _reap_process_group /
_run_http_scenario.
"""
import os
import subprocess
import time

import run_scenarios


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just not ours -- still alive
    return True


def _no_orphans(marker: str) -> bool:
    out = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    return out.stdout.strip() == ""


def _scenario(run, timeout_s=10, then=None):
    return {
        "id": "BHV-900-S1",
        "behavior_id": "BHV-900",
        "when": {"run": run, "timeout_s": timeout_s},
        "then": then or {},
    }


# Parent prints the background child's pid then exits immediately -- the
# child (a plain `sleep 300`, NOT setsid'd/double-forked) stays in the SAME
# process group as the parent under start_new_session=True, so a
# process-group reap must catch it even though it outlives its parent. The
# child's own stdio is redirected away from the parent's captured pipes --
# exactly what a real "leave this running in the background" child does --
# so the parent's stdout pipe closes (and `communicate()` returns) the
# instant the parent exits, instead of blocking on the still-open pipe the
# child would otherwise inherit.
DETACHED_CHILD_SCRIPT = (
    "import subprocess, sys\n"
    "p = subprocess.Popen(['sleep', '300'], stdin=subprocess.DEVNULL, "
    "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
    "sys.stdout.write('CHILD=%d\\n' % p.pid)\n"
    "sys.stdout.flush()\n"
)


def test_run_scenario_reaps_detached_background_child(tmp_path):
    sc = _scenario(
        ["python3", "-c", DETACHED_CHILD_SCRIPT],
        then={"stdout_contains": "CHILD="},
    )
    r = run_scenarios.run_scenario(sc, str(tmp_path))

    assert r["pass"] is True and r["taxonomy"] is None
    stdout = r["observed"]["stdout"]
    assert "CHILD=" in stdout
    child_pid = int(stdout.strip().split("CHILD=", 1)[1])

    # give teardown a moment to land, then require the background child to
    # be gone -- reaped by the process-group kill, not merely orphaned.
    for _ in range(30):
        if not _alive(child_pid):
            break
        time.sleep(0.1)
    assert not _alive(child_pid), (
        f"detached child pid {child_pid} survived run_scenario -- "
        "process-group reap did not reach it (pre-fix behavior: bare "
        "subprocess.run() with no start_new_session/reap leaks this child)"
    )


def test_run_scenario_normal_output_unaffected(tmp_path):
    sc = _scenario(
        ["python3", "-c", "print('ok')"],
        then={"exit_code": 0, "stdout_contains": "ok"},
    )
    r = run_scenarios.run_scenario(sc, str(tmp_path))
    assert r["pass"] is True and r["taxonomy"] is None
    assert r["observed"]["exit_code"] == 0
    assert r["observed"]["stdout"] == "ok\n"
    assert r["observed"]["stderr"] == ""


def test_run_scenario_crash_taxonomy_still_works_under_popen(tmp_path):
    sc = _scenario(["./does-not-exist-xyz"], timeout_s=5)
    r = run_scenarios.run_scenario(sc, str(tmp_path))
    assert r["pass"] is False and r["taxonomy"] == "crash"


TIMEOUT_CHILD_MARKER = "df-cli-timeout-teardown-fixture-7f3d21"

# Parent backgrounds a marked long-sleeping child (same process group, not
# setsid'd) and then itself hangs well past the scenario timeout.
TIMEOUT_PARENT_SCRIPT = (
    "import subprocess, time\n"
    "subprocess.Popen(['python3', '-c', "
    "'import time; time.sleep(300)  # " + TIMEOUT_CHILD_MARKER + "'], "
    "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
    "time.sleep(30)\n"
)


def test_run_scenario_times_out_and_reaps_full_tree(tmp_path):
    sc = _scenario(["python3", "-c", TIMEOUT_PARENT_SCRIPT], timeout_s=1)

    r = run_scenarios.run_scenario(sc, str(tmp_path))

    assert r["pass"] is False and r["taxonomy"] == "timeout"

    for _ in range(30):
        if _no_orphans(TIMEOUT_CHILD_MARKER):
            break
        time.sleep(0.1)
    assert _no_orphans(TIMEOUT_CHILD_MARKER), (
        "background child of a timed-out CLI scenario survived -- "
        "process-group reap did not fire on the timeout path"
    )
