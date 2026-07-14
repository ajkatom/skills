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
        try:
            pref = b.wrap_prefix("/some/control", "/some/ws")
        except df_sandbox.SandboxError:
            pytest.skip("wrap_prefix body lands in Task 2 (macOS) / Task 3 (Linux)")
        assert isinstance(pref, list) and len(pref) >= 1
        assert all(isinstance(x, str) for x in pref)
