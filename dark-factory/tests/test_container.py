import os
import socket
import subprocess
import sys
import uuid

import pytest

import df_container


# ---------------------------------------------------------------------------
# build_argv — pure tests (no docker)
# ---------------------------------------------------------------------------

def test_build_argv_exact_flag_set_and_order(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    argv = df_container.build_argv("img:tag", str(ws), [])
    assert argv[0:3] == ["docker", "run", "--rm"]
    assert "-i" in argv
    assert "--cap-drop" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in argv and argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert "--read-only" in argv
    assert "--tmpfs" in argv and argv[argv.index("--tmpfs") + 1] == "/tmp"
    assert "--pids-limit" in argv and argv[argv.index("--pids-limit") + 1] == "256"
    assert "--memory" in argv and argv[argv.index("--memory") + 1] == "2g"
    idx = argv.index("-e")
    assert argv[idx + 1] == "HOME=/tmp"


def test_build_argv_workspace_mounted_rw_at_realpath(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    real_ws = os.path.realpath(str(ws))
    argv = df_container.build_argv("img", str(ws), [])
    assert "-v" in argv
    v_idx = argv.index("-v")
    assert argv[v_idx + 1] == f"{real_ws}:{real_ws}"
    assert "-w" in argv and argv[argv.index("-w") + 1] == real_ws


def test_build_argv_ro_mounts_mounted_ro_sorted_deduped(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    real_a = os.path.realpath(str(a))
    real_b = os.path.realpath(str(b))
    # pass duplicates and out-of-order to verify sort+dedup
    argv = df_container.build_argv("img", str(ws), [str(b), str(a), str(b)])
    v_specs = [argv[i + 1] for i, x in enumerate(argv) if x == "-v"]
    expected_ro = sorted({f"{real_a}:{real_a}:ro", f"{real_b}:{real_b}:ro"})
    assert v_specs[1:] == expected_ro


def test_build_argv_exactly_one_plus_len_ro_mounts_v_flags(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    mounts = []
    for name in ("m1", "m2", "m3"):
        d = tmp_path / name
        d.mkdir()
        mounts.append(str(d))
    argv = df_container.build_argv("img", str(ws), mounts)
    v_count = sum(1 for x in argv if x == "-v")
    assert v_count == 1 + len(mounts)


def test_build_argv_env_dict_sorted_e_flags(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    argv = df_container.build_argv("img", str(ws), [], env={"ZEBRA": "1", "ALPHA": "2"})
    e_indices = [i for i, x in enumerate(argv) if x == "-e"]
    e_pairs = [argv[i + 1] for i in e_indices]
    # first -e is always HOME=/tmp, then sorted env pairs
    assert e_pairs[0] == "HOME=/tmp"
    assert e_pairs[1:] == ["ALPHA=2", "ZEBRA=1"]


def test_build_argv_image_is_last_element(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    argv = df_container.build_argv("my-image:latest", str(ws), [])
    assert argv[-1] == "my-image:latest"


def test_build_argv_network_value_honored(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    argv = df_container.build_argv("img", str(ws), [], network="bridge")
    n_idx = argv.index("--network")
    assert argv[n_idx + 1] == "bridge"


def test_build_argv_missing_workspace_raises(tmp_path):
    with pytest.raises(df_container.ContainerError):
        df_container.build_argv("img", str(tmp_path / "does-not-exist"), [])


def test_build_argv_missing_ro_mount_raises(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    with pytest.raises(df_container.ContainerError):
        df_container.build_argv("img", str(ws), [str(tmp_path / "nope")])


def test_build_argv_path_containing_colon_raises(tmp_path):
    ws = tmp_path / "ws:bad"
    ws.mkdir()
    with pytest.raises(df_container.ContainerError):
        df_container.build_argv("img", str(ws), [])


def test_build_argv_relative_workspace_raises(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.chdir(tmp_path)
    with pytest.raises(df_container.ContainerError):
        df_container.build_argv("img", "ws", [])


def test_build_argv_flag_like_or_empty_image_raises(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    for bad in ("--privileged", "-x", ""):
        with pytest.raises(df_container.ContainerError):
            df_container.build_argv(bad, str(ws), [])


# ---------------------------------------------------------------------------
# docker_available — injected fake runners
# ---------------------------------------------------------------------------

class _FakeCompletedProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode


def test_docker_available_true_when_which_and_rc0(monkeypatch):
    monkeypatch.setattr(df_container.shutil, "which", lambda name: "/usr/bin/docker")
    runner = lambda *a, **k: _FakeCompletedProcess(0)
    assert df_container.docker_available(runner=runner) is True


def test_docker_available_false_when_rc_nonzero(monkeypatch):
    monkeypatch.setattr(df_container.shutil, "which", lambda name: "/usr/bin/docker")
    runner = lambda *a, **k: _FakeCompletedProcess(1)
    assert df_container.docker_available(runner=runner) is False


def test_docker_available_false_when_runner_raises_oserror(monkeypatch):
    monkeypatch.setattr(df_container.shutil, "which", lambda name: "/usr/bin/docker")
    def runner(*a, **k):
        raise OSError("boom")
    assert df_container.docker_available(runner=runner) is False


def test_docker_available_false_when_runner_raises_timeout(monkeypatch):
    monkeypatch.setattr(df_container.shutil, "which", lambda name: "/usr/bin/docker")
    def runner(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker info", timeout=10)
    assert df_container.docker_available(runner=runner) is False


def test_docker_available_false_when_which_is_none(monkeypatch):
    monkeypatch.setattr(df_container.shutil, "which", lambda name: None)
    runner = lambda *a, **k: _FakeCompletedProcess(0)
    assert df_container.docker_available(runner=runner) is False


# ---------------------------------------------------------------------------
# probe_container — fail-closed matrix, injected fake runner
# ---------------------------------------------------------------------------

class _FakeProbeProcess:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout


def test_probe_container_true_on_denial_marker(tmp_path):
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()
    runner = lambda *a, **k: _FakeProbeProcess(0, "DF-READ-DENIED\n")
    assert df_container.probe_container("img", str(deny_root), str(ws), runner=runner) is True


def test_probe_container_false_when_token_leaks(tmp_path):
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()
    captured = {}

    def runner(*a, **k):
        # simulate the container "reading" the canary content: real content is the
        # planted token, which the caller controls via the file on disk.
        content = deny_root.iterdir()
        for f in deny_root.iterdir():
            captured["content"] = f.read_text()
        return _FakeProbeProcess(0, captured.get("content", "LEAKED-TOKEN"))

    assert df_container.probe_container("img", str(deny_root), str(ws), runner=runner) is False


def test_probe_container_false_on_nonzero_rc_even_with_marker(tmp_path):
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()
    # launch failure: rc != 0 must not be mistaken for a proven denial even if the
    # marker text happens to appear (vacuous stdout).
    runner = lambda *a, **k: _FakeProbeProcess(1, "DF-READ-DENIED")
    assert df_container.probe_container("img", str(deny_root), str(ws), runner=runner) is False


def test_probe_container_false_when_runner_raises_timeout(tmp_path):
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()

    def runner(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker run", timeout=180)

    assert df_container.probe_container("img", str(deny_root), str(ws), runner=runner) is False


def test_probe_container_false_when_runner_raises_oserror(tmp_path):
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()

    def runner(*a, **k):
        raise OSError("docker not found")

    assert df_container.probe_container("img", str(deny_root), str(ws), runner=runner) is False


def test_probe_container_canary_always_removed(tmp_path):
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()
    runner = lambda *a, **k: _FakeProbeProcess(0, "DF-READ-DENIED")
    df_container.probe_container("img", str(deny_root), str(ws), runner=runner)
    leftovers = [n for n in os.listdir(deny_root) if n.startswith(".probe-canary-") or "canary" in n.lower()]
    assert leftovers == []


def test_probe_container_canary_removed_even_on_exception(tmp_path):
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()

    def runner(*a, **k):
        raise OSError("boom")

    df_container.probe_container("img", str(deny_root), str(ws), runner=runner)
    leftovers = list(os.listdir(deny_root))
    assert leftovers == []


# ---------------------------------------------------------------------------
# Live tests — require a real docker daemon
# ---------------------------------------------------------------------------

DOCKER_LIVE = df_container.docker_available()


@pytest.fixture(scope="session", autouse=True)
def _prepull_image():
    """Idempotent pre-pull so the first live test never absorbs a cold image
    download inside its own (tighter) timeout. No-op when docker is absent."""
    if DOCKER_LIVE:
        subprocess.run(
            ["docker", "pull", "-q", df_container.DEFAULT_IMAGE],
            capture_output=True, timeout=600,
        )
    yield


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_live_probe_denies_unmounted_root(tmp_path):
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()
    assert df_container.probe_container(df_container.DEFAULT_IMAGE, str(deny_root), str(ws)) is True


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_live_workspace_writable(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    argv = df_container.build_argv(df_container.DEFAULT_IMAGE, str(ws), [])
    code = "open('probe.txt','w').write('ok')"
    proc = subprocess.run(argv + ["python3", "-c", code], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert (ws / "probe.txt").read_text() == "ok"


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_live_network_none_blocks_egress(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    argv = df_container.build_argv(df_container.DEFAULT_IMAGE, str(ws), [], network="none")
    code = (
        "import socket\n"
        "try:\n"
        "    s = socket.create_connection(('1.1.1.1', 443), timeout=3)\n"
        "    print('CONNECTED')\n"
        "except Exception:\n"
        "    print('DF-EGRESS-BLOCKED')\n"
    )
    proc = subprocess.run(argv + ["python3", "-c", code], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "DF-EGRESS-BLOCKED"
