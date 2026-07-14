import json
import os
import time

import df_twins

HERE = os.path.dirname(os.path.abspath(__file__))
WRAP = os.path.join(HERE, "fixtures", "twin_shell_wrapper")


def _alive(pid):
    try:
        os.kill(pid, 0); return True
    except (ProcessLookupError, OSError):
        return False


def test_stop_reaps_grandchild_process(tmp_path):
    gc_pidfile = tmp_path / "gc.pid"
    td = tmp_path / "twins"; td.mkdir()
    (td / "w.json").write_text(json.dumps({
        "twin_version": "0.1", "name": "w",
        "launch": ["bash", WRAP]}), encoding="utf-8")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    os.environ["DF_GRANDCHILD_PIDFILE"] = str(gc_pidfile)
    ts = df_twins.TwinSet()
    try:
        ts.start(df_twins.load_defs(str(td)), str(run_dir), 20)
        # wait for the grandchild pid to be recorded
        for _ in range(100):
            if gc_pidfile.exists() and gc_pidfile.read_text().strip():
                break
            time.sleep(0.05)
        gc_pid = int(gc_pidfile.read_text().strip())
        assert _alive(gc_pid)
        ts.stop()
        time.sleep(0.3)
        assert not _alive(gc_pid)  # grandchild reaped via process group
    finally:
        ts.stop()
        os.environ.pop("DF_GRANDCHILD_PIDFILE", None)
