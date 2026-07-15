import os
import sys

import pytest

import df_sandbox


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec profile string")
def test_macos_profile_denies_both_read_and_write():
    b = df_sandbox.BACKENDS["darwin"]
    pref = b.wrap_prefix("/some/control", "/some/ws")
    assert pref[0] == "sandbox-exec" and pref[1] == "-p"
    profile = pref[2]
    real = os.path.realpath("/some/control")
    assert profile == (
        "(version 1)"
        "(allow default)"
        f'(deny file-read* (subpath "{real}"))'
        f'(deny file-write* (subpath "{real}"))'
    )


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real backend")
def test_probe_passes_and_leaves_no_write_artifacts(tmp_path):
    b = df_sandbox.current_backend()
    if not b.available():
        pytest.skip("OS sandbox primitive not present")
    deny_root = tmp_path / "control"
    deny_root.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    assert df_sandbox.probe_denial(b, str(deny_root), str(ws)) is True
    # No probe artifacts (read canary or write-probe file) left behind.
    leftovers = [n for n in os.listdir(deny_root) if n.startswith(".probe-")]
    assert leftovers == []


class _ReadOnlyDenyBackend:
    """Denies reads but leaks writes through (e.g. an old-style read-only profile).
    The dual probe must catch the write leak and return False."""
    name = "read-only-deny"

    def available(self):
        return True

    def wrap_prefix(self, deny_root, workspace):
        real = os.path.realpath(deny_root)
        profile = (
            "(version 1)"
            "(allow default)"
            f'(deny file-read* (subpath "{real}"))'
        )
        return ["sandbox-exec", "-p", profile]


@pytest.mark.skipif(sys.platform != "darwin", reason="uses sandbox-exec to build a real leaky backend")
def test_probe_rejects_backend_that_denies_reads_but_not_writes(tmp_path):
    deny_root = tmp_path / "control"
    deny_root.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    assert df_sandbox.probe_denial(_ReadOnlyDenyBackend(), str(deny_root), str(ws)) is False
    # The write-probe file must not survive if it leaked through.
    leftovers = [n for n in os.listdir(deny_root) if n.startswith(".probe-")]
    assert leftovers == []


class _PassthroughBackend:
    """No isolation at all — both read and write leak through."""
    name = "passthrough-insecure"

    def available(self):
        return True

    def wrap_prefix(self, deny_root, workspace):
        return []


def test_probe_rejects_passthrough_backend_write_leaks(tmp_path):
    deny_root = tmp_path / "control"
    deny_root.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    assert df_sandbox.probe_denial(_PassthroughBackend(), str(deny_root), str(ws)) is False
    leftovers = os.listdir(deny_root)
    assert leftovers == []


class _WriteOnlyDenyBackend:
    """Denies writes but leaks reads through — the dual probe must catch the read
    leak and return False (proves the read-canary discipline is still enforced,
    not just the new write probe)."""
    name = "write-only-deny"

    def available(self):
        return True

    def wrap_prefix(self, deny_root, workspace):
        real = os.path.realpath(deny_root)
        profile = (
            "(version 1)"
            "(allow default)"
            f'(deny file-write* (subpath "{real}"))'
        )
        return ["sandbox-exec", "-p", profile]


@pytest.mark.skipif(sys.platform != "darwin", reason="uses sandbox-exec to build a real leaky backend")
def test_probe_rejects_backend_that_denies_writes_but_not_reads(tmp_path):
    deny_root = tmp_path / "control"
    deny_root.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    assert df_sandbox.probe_denial(_WriteOnlyDenyBackend(), str(deny_root), str(ws)) is False


class _LaunchFailBackend:
    name = "launch-fail"

    def available(self):
        return True

    def wrap_prefix(self, deny_root, workspace):
        return ["false"]


def test_probe_false_when_wrapped_process_never_runs(tmp_path):
    deny_root = tmp_path / "control"
    deny_root.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    assert df_sandbox.probe_denial(_LaunchFailBackend(), str(deny_root), str(ws)) is False
    assert os.listdir(deny_root) == []


def test_linux_wrap_prefix_still_masks_via_tmpfs():
    # bwrap prefix unchanged: tmpfs already masks both read and write. Sanity-check
    # the shape stays intact after the macOS-only profile change.
    b = df_sandbox.BACKENDS["linux"]
    pref = b.wrap_prefix("/ctrl", "/ws")
    assert pref[0] == "bwrap"
    assert "--tmpfs" in pref and "/ctrl" in pref
    assert pref[-1] == "--"
