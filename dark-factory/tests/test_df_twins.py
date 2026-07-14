import json
import os
import socket
import urllib.request

import pytest

import df_twins

HERE = os.path.dirname(os.path.abspath(__file__))
GREETER = os.path.join(HERE, "fixtures", "twin_greeter")


def write_def(twins_dir, name="greeter", **over):
    twins_dir.mkdir(parents=True, exist_ok=True)
    d = {"twin_version": "0.1", "name": name,
         "launch": ["python3", GREETER], "fidelity": "dev mock"}
    d.update(over)
    (twins_dir / f"{name}.json").write_text(json.dumps(d), encoding="utf-8")
    return d


def test_load_defs_validates_and_defaults_env_var(tmp_path):
    write_def(tmp_path / "twins")
    defs = df_twins.load_defs(str(tmp_path / "twins"))
    assert defs[0]["name"] == "greeter" and defs[0]["env_var"] == "DF_TWIN_GREETER"


def test_load_defs_rejects_bad_name(tmp_path):
    write_def(tmp_path / "twins", name="Bad-Name")
    with pytest.raises(df_twins.TwinError, match="name"):
        df_twins.load_defs(str(tmp_path / "twins"))


def test_start_returns_reachable_endpoint(tmp_path):
    defs = [write_def(tmp_path / "twins")]
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        env = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
        assert set(env) == {"DF_TWIN_GREETER"}
        host, port = env["DF_TWIN_GREETER"].split(":")
        body = urllib.request.urlopen(f"http://{host}:{port}/greet/World", timeout=5).read().decode()
        assert body == "Hello, World!"
    finally:
        ts.stop()


def test_reset_gives_a_fresh_running_endpoint(tmp_path):
    write_def(tmp_path / "twins")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        env1 = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
        env2 = ts.reset(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
        # reachable after reset
        h, p = env2["DF_TWIN_GREETER"].split(":")
        assert urllib.request.urlopen(f"http://{h}:{p}/greet/X", timeout=5).status == 200
    finally:
        ts.stop()


def test_stop_reaps_processes(tmp_path):
    write_def(tmp_path / "twins")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    env = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
    host, port = env["DF_TWIN_GREETER"].split(":")
    ts.stop()
    # port no longer accepts connections
    s = socket.socket(); s.settimeout(1)
    with pytest.raises((ConnectionRefusedError, OSError)):
        s.connect((host, int(port)))
    s.close()


def test_start_times_out_when_endpoint_never_written(tmp_path):
    # a launch that never writes the endpoint file
    write_def(tmp_path / "twins", launch=["python3", "-c", "import time; time.sleep(30)"])
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        with pytest.raises(df_twins.TwinError, match="timeout|ready"):
            ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 1)
    finally:
        ts.stop()


def test_launch_failure_mid_batch_reaps_and_raises(tmp_path):
    td = tmp_path / "twins"; td.mkdir()
    # twin 'a' launches fine (the greeter); twin 'z' has a bogus command
    (td / "a.json").write_text(json.dumps({"twin_version":"0.1","name":"a","launch":["python3", GREETER]}), encoding="utf-8")
    (td / "z.json").write_text(json.dumps({"twin_version":"0.1","name":"z","launch":["this-command-does-not-exist-xyz"]}), encoding="utf-8")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    with pytest.raises(df_twins.TwinError):
        ts.start(df_twins.load_defs(str(td)), str(run_dir), 20)
    # engine self-cleaned: no tracked procs remain alive
    assert all(p.poll() is not None for p, _ in ts._procs) or ts._procs == []
    ts.stop()  # idempotent, safe
