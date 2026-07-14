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
