"""OS-pluggable read+write-denial sandbox for dark-factory standard tier. Stdlib only.

A backend denies a wrapped process from READING and WRITING `deny_root` (the
holdout control root — scenarios, journal, observation logs) while leaving
`workspace` and the system usable. `current_backend()` returns the backend for
this OS or None (unsupported). No backend is trusted without a passing
`probe_denial` — the probe is the fail-closed safety net, and it proves BOTH
read denial (a planted canary is unreadable) and write denial (a fresh file
cannot be created, and the canary cannot be truncated) before anything relies
on the sandbox.
"""
import os
import shutil
import subprocess
import sys
import uuid


class SandboxError(RuntimeError):
    pass


_READ_DENIAL_MARKER = "DF-READ-DENIED"
_WRITE_DENIAL_MARKER = "DF-WRITE-DENIED"


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
            f'(deny file-write* (subpath "{real}"))'
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
            "--tmpfs", real_deny,        # mask the control root → real contents unreadable
            "--remount-ro", real_deny,   # SEAL the mask read-only (MS_RDONLY): the fresh
                                         # tmpfs is otherwise owner-writable, and a root
                                         # process has CAP_DAC_OVERRIDE so permission BITS
                                         # (chmod) would not stop it — only a read-only
                                         # MOUNT is kernel-enforced regardless of caps.
                                         # bwrap applies args in order, so tmpfs-then-
                                         # remount-ro yields an empty, read-only mount:
                                         # reads denied (empty, shadows real content),
                                         # writes denied (MS_RDONLY). This is what makes
                                         # M12's write-denial half of probe_denial hold on
                                         # a real Linux kernel.
            "--bind", real_ws, real_ws,  # workspace read-write
            "--chdir", real_ws,
            "--die-with-parent",
            "--",
        ]


BACKENDS = {"darwin": _MacOSBackend(), "linux": _LinuxBackend()}


def current_backend():
    return BACKENDS.get(sys.platform)


def probe_denial(backend, deny_root, workspace):
    """Fail-closed: True only if a wrapped process provably cannot READ a canary
    planted in deny_root AND cannot WRITE there either (a fresh file, and a
    truncation of the read canary). Any error/uncertainty → False.

    Any write-probe file that somehow ends up existing in deny_root (i.e. a write
    leaked through despite everything else looking fine) is treated as proof of a
    leak (→ False) and is unconditionally unlinked, same as the canary.
    """
    if backend is None or not backend.available():
        return False
    read_token = "DF-CANARY-" + uuid.uuid4().hex
    canary = os.path.join(deny_root, ".probe-canary-" + uuid.uuid4().hex)
    write_probe = os.path.join(deny_root, ".probe-write-" + uuid.uuid4().hex)
    try:
        try:
            with open(canary, "w", encoding="utf-8") as f:
                f.write(read_token)
        except OSError:
            return False
        try:
            prefix = backend.wrap_prefix(deny_root, workspace)
        except SandboxError:
            return False
        # Wrapped process performs three checks and prints one marker line per
        # check. If the sandbox does NOT deny an operation, the corresponding
        # line will be the real content / a success marker instead of the
        # denial marker → treated as a leak, fail closed.
        code = (
            "import sys\n"
            "canary_path, write_probe_path = sys.argv[1], sys.argv[2]\n"
            "try:\n"
            "    sys.stdout.write(open(canary_path).read())\n"
            "except Exception:\n"
            f"    sys.stdout.write({_READ_DENIAL_MARKER!r})\n"
            "sys.stdout.write(chr(10))\n"
            "try:\n"
            "    open(write_probe_path, 'w').write('leak')\n"
            "    sys.stdout.write('DF-WRITE-LEAKED')\n"
            "except Exception:\n"
            f"    sys.stdout.write({_WRITE_DENIAL_MARKER!r})\n"
            "sys.stdout.write(chr(10))\n"
            "try:\n"
            "    open(canary_path, 'w').write('leak')\n"
            "    sys.stdout.write('DF-WRITE-LEAKED')\n"
            "except Exception:\n"
            f"    sys.stdout.write({_WRITE_DENIAL_MARKER!r})\n"
        )
        try:
            proc = subprocess.run(
                prefix + [sys.executable, "-c", code, canary, write_probe],
                capture_output=True, text=True, errors="replace", timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        # Fail-closed: True only if the wrapped process provably ran AND every
        # check hit its denial branch. Vacuous/short/garbage stdout from a
        # launch failure must NOT be mistaken for a proven denial. A write-probe
        # file that exists on disk (even if the sandbox reported an exception on
        # some other line) is independent, physical proof of a leak.
        if os.path.exists(write_probe):
            return False
        lines = proc.stdout.split("\n")
        if len(lines) < 3:
            return False
        read_denied = lines[0].strip() == _READ_DENIAL_MARKER
        write_open_denied = lines[1].strip() == _WRITE_DENIAL_MARKER
        truncate_denied = lines[2].strip() == _WRITE_DENIAL_MARKER
        return (
            proc.returncode == 0
            and read_denied
            and write_open_denied
            and truncate_denied
        )
    finally:
        try:
            os.unlink(canary)
        except OSError:
            pass
        try:
            os.unlink(write_probe)
        except OSError:
            pass
