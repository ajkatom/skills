"""OS-pluggable read-denial sandbox for dark-factory standard tier. Stdlib only.

A backend denies a wrapped process from READING `deny_root` (the holdout control
root) while leaving `workspace` and the system usable. `current_backend()` returns
the backend for this OS or None (unsupported). No backend is trusted without a
passing `probe_denial` (Task 4) — the probe is the fail-closed safety net.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import uuid


class SandboxError(RuntimeError):
    pass


class _MacOSBackend:
    name = "macos-sandbox-exec"

    def available(self):
        return shutil.which("sandbox-exec") is not None

    def wrap_prefix(self, deny_root, workspace):
        # Filled in Task 2.
        raise SandboxError("macOS wrap_prefix not implemented yet")


class _LinuxBackend:
    name = "linux-bwrap"

    def available(self):
        return shutil.which("bwrap") is not None

    def wrap_prefix(self, deny_root, workspace):
        # Filled in Task 3.
        raise SandboxError("linux wrap_prefix not implemented yet")


BACKENDS = {"darwin": _MacOSBackend(), "linux": _LinuxBackend()}


def current_backend():
    return BACKENDS.get(sys.platform)
