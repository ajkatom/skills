import os
import sys

import pytest

import df_sandbox


def test_current_backend_matches_platform():
    b = df_sandbox.current_backend()
    if sys.platform == "darwin":
        assert b is not None and b.name == "macos-sandbox-exec"
    elif sys.platform == "linux":
        assert b is not None and b.name == "linux-bwrap"
    else:
        assert b is None  # unsupported platform (e.g. windows) → no backend


def test_backend_reports_availability_as_bool():
    b = df_sandbox.current_backend()
    if b is not None:
        assert isinstance(b.available(), bool)


def test_wrap_prefix_is_nonempty_arg_list_when_available():
    b = df_sandbox.current_backend()
    if b is not None and b.available():
        pref = b.wrap_prefix("/some/control", "/some/ws")
        assert isinstance(pref, list) and len(pref) >= 1
        assert all(isinstance(x, str) for x in pref)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec")
def test_macos_backend_denies_deny_root_read_but_allows_workspace(tmp_path):
    b = df_sandbox.current_backend()
    if not b.available():
        pytest.skip("sandbox-exec not present")
    deny_root = tmp_path / "control"
    ws = tmp_path / "ws"
    deny_root.mkdir()
    ws.mkdir()
    secret = deny_root / "scenarios.json"
    secret.write_text("TOP-SECRET-HOLDOUT", encoding="utf-8")
    ws_file = ws / "ok.txt"
    ws_file.write_text("workspace-ok", encoding="utf-8")

    pref = b.wrap_prefix(str(deny_root), str(ws))
    import subprocess
    # reading the deny_root secret must FAIL under the sandbox
    denied = subprocess.run(pref + ["cat", str(secret)], capture_output=True, text=True)
    assert denied.returncode != 0
    assert "TOP-SECRET-HOLDOUT" not in denied.stdout
    # reading the workspace file must SUCCEED under the same sandbox
    allowed = subprocess.run(pref + ["cat", str(ws_file)], capture_output=True, text=True)
    assert allowed.returncode == 0 and "workspace-ok" in allowed.stdout


def test_linux_wrap_prefix_construction():
    # Runs on any OS: verify the argv shape without executing bwrap.
    b = df_sandbox.BACKENDS["linux"]
    pref = b.wrap_prefix("/ctrl", "/ws")
    assert pref[0] == "bwrap"
    assert "--tmpfs" in pref and "/ctrl" in pref          # deny_root masked
    assert "--bind" in pref and "/ws" in pref             # workspace writable
    assert "--chdir" in pref
    assert pref[-1] == "--"                                # command follows


@pytest.mark.skipif(sys.platform != "linux", reason="linux bwrap")
def test_linux_backend_denies_deny_root_read(tmp_path):
    b = df_sandbox.current_backend()
    if not b.available():
        pytest.skip("bwrap not present")
    deny_root = tmp_path / "control"; deny_root.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    (deny_root / "scenarios.json").write_text("TOP-SECRET-HOLDOUT", encoding="utf-8")
    (ws / "ok.txt").write_text("workspace-ok", encoding="utf-8")
    pref = b.wrap_prefix(str(deny_root), str(ws))
    import subprocess
    denied = subprocess.run(pref + ["cat", str(deny_root / "scenarios.json")],
                            capture_output=True, text=True)
    assert "TOP-SECRET-HOLDOUT" not in denied.stdout
    allowed = subprocess.run(pref + ["cat", str(ws / "ok.txt")],
                             capture_output=True, text=True)
    assert allowed.returncode == 0 and "workspace-ok" in allowed.stdout


class _PassthroughBackend:
    """A deliberately broken 'sandbox' that does NOT deny anything — the probe must
    reject it (return False), proving fail-closed detection."""
    name = "passthrough-insecure"
    def available(self):
        return True
    def wrap_prefix(self, deny_root, workspace):
        return []  # no isolation at all


def test_probe_rejects_a_passthrough_backend(tmp_path):
    deny_root = tmp_path / "control"; deny_root.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    assert df_sandbox.probe_denial(_PassthroughBackend(), str(deny_root), str(ws)) is False


def test_probe_false_for_none_or_unavailable_backend(tmp_path):
    assert df_sandbox.probe_denial(None, str(tmp_path), str(tmp_path)) is False


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real backend")
def test_probe_passes_with_the_real_backend(tmp_path):
    b = df_sandbox.current_backend()
    if not b.available():
        pytest.skip("OS sandbox primitive not present")
    deny_root = tmp_path / "control"; deny_root.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    assert df_sandbox.probe_denial(b, str(deny_root), str(ws)) is True


def test_probe_cleans_up_canary(tmp_path):
    deny_root = tmp_path / "control"; deny_root.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    df_sandbox.probe_denial(_PassthroughBackend(), str(deny_root), str(ws))
    leftovers = [n for n in os.listdir(deny_root) if n.startswith(".probe-canary-")]
    assert leftovers == []
