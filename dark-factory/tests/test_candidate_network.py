import sys

import pytest

import df_sandbox

IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform == "linux"


def test_wrap_prefix_default_network_is_byte_identical(tmp_path):
    backend = df_sandbox.current_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    legacy = backend.wrap_prefix(str(deny), str(ws))
    explicit = backend.wrap_prefix(str(deny), str(ws), network="unrestricted")
    assert legacy == explicit


def test_wrap_prefix_rejects_unknown_network_mode(tmp_path):
    backend = df_sandbox.current_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    with pytest.raises(df_sandbox.SandboxError):
        backend.wrap_prefix(str(deny), str(ws), network="bogus")


@pytest.mark.skipif(not IS_MAC, reason="macOS sandbox-exec backend")
def test_macos_deny_and_loopback_modify_profile(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    deny_argv = backend.wrap_prefix(str(deny), str(ws), network="deny")
    loop_argv = backend.wrap_prefix(str(deny), str(ws), network="loopback")
    assert "(deny network*)" in deny_argv[-1]
    assert "(deny network*)" in loop_argv[-1]
    assert "localhost" in loop_argv[-1]


@pytest.mark.skipif(not IS_LINUX, reason="Linux bwrap backend")
def test_linux_deny_adds_unshare_net_and_loopback_raises(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._LinuxBackend()
    argv = backend.wrap_prefix(str(deny), str(ws), network="deny")
    assert "--unshare-net" in argv
    with pytest.raises(df_sandbox.SandboxError):
        backend.wrap_prefix(str(deny), str(ws), network="loopback")


def test_probe_unrestricted_passes_without_spawning(tmp_path):
    backend = df_sandbox.current_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(tmp_path), str(tmp_path), "unrestricted")
    assert ok is True


@pytest.mark.skipif(not IS_MAC, reason="live macOS sandbox probe")
def test_probe_deny_live_macos(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "deny")
    assert ok is True, reason


@pytest.mark.skipif(not IS_MAC, reason="live macOS sandbox probe")
def test_probe_loopback_live_macos(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "loopback")
    assert ok is True, reason


@pytest.mark.skipif(not IS_LINUX, reason="live bwrap probe")
def test_probe_deny_live_linux(tmp_path):
    deny = tmp_path / "cr"
    ws = tmp_path / "ws"
    deny.mkdir()
    ws.mkdir()
    backend = df_sandbox._LinuxBackend()
    if not backend.available():
        pytest.skip("bwrap not installed")
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "deny")
    assert ok is True, reason


def test_probe_rejects_unknown_network_mode(tmp_path):
    backend = df_sandbox.current_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(tmp_path), str(tmp_path), "bogus")
    assert ok is False


def test_probe_false_for_none_or_unavailable_backend(tmp_path):
    ok, reason = df_sandbox.probe_network_denial(
        None, str(tmp_path), str(tmp_path), "deny")
    assert ok is False
