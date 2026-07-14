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
        real = os.path.realpath(deny_root)
        profile = (
            "(version 1)"
            "(allow default)"
            f'(deny file-read* (subpath "{real}"))'
        )
        return ["sandbox-exec", "-p", profile]


class _LinuxBackend:
    name = "linux-bwrap"

    def available(self):
        return shutil.which("bwrap") is not None

    def wrap_prefix(self, deny_root, workspace):
        real_deny = os.path.realpath(deny_root)
        real_ws = os.path.realpath(workspace)
        return [
            "bwrap",
            "--ro-bind", "/", "/",       # whole fs read-only baseline
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", real_deny,        # mask the control root → contents unreadable
            "--bind", real_ws, real_ws,  # workspace read-write
            "--chdir", real_ws,
            "--die-with-parent",
            "--",
        ]


BACKENDS = {"darwin": _MacOSBackend(), "linux": _LinuxBackend()}


def current_backend():
    return BACKENDS.get(sys.platform)


def probe_denial(backend, deny_root, workspace):
    """Fail-closed: True only if a wrapped process provably cannot read a canary
    planted in deny_root. Any error/uncertainty → False."""
    if backend is None or not backend.available():
        return False
    token = "DF-CANARY-" + uuid.uuid4().hex
    canary = os.path.join(deny_root, ".probe-canary-" + uuid.uuid4().hex)
    try:
        with open(canary, "w", encoding="utf-8") as f:
            f.write(token)
        try:
            prefix = backend.wrap_prefix(deny_root, workspace)
        except SandboxError:
            return False
        # Wrapped attempt to read the canary. If the token appears in stdout, the
        # sandbox did NOT deny the read → not isolated → fail closed.
        code = (
            "import sys\n"
            "try:\n"
            "    sys.stdout.write(open(sys.argv[1]).read())\n"
            "except Exception:\n"
            "    sys.stdout.write('DF-READ-DENIED')\n"
        )
        try:
            proc = subprocess.run(
                prefix + [sys.executable, "-c", code, canary],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return token not in proc.stdout
    finally:
        try:
            os.unlink(canary)
        except OSError:
            pass
