"""df_seal: content-addressed freeze / publish / verify primitive (DF-01/M28a Task 1).

Stdlib only. This module is the "seal-first" building block for artifact
binding: it freezes a directory tree into an immutable, content-addressed
object under an object store, and lets any later step verify that object by
identity (recompute-and-compare) rather than trust a mutable workspace path.

Threat model / what this defends against (and what it does not):
  - Defends against: a symlink/special-file/hardlink/hostile-permission entry
    inside the tree being sealed silently escaping the tree during traversal
    or being silently included in the identity; a partially-written or
    corrupted object being reused as if it were valid; a plain overwriting
    rename silently clobbering a previously-published object; the published
    object drifting from its recorded sidecar without detection.
  - Does NOT defend against: a party with write access to the object store
    directory tree deliberately overwriting bytes with the *same* privilege
    level used to publish (no cross-user MAC/DAC enforcement here — that is
    "detection-grade", not "same-user prevention", by design). verify_object
    is exactly the detector for that residual risk.

FD-safe traversal choice (documented per task brief):
  Every directory we open on the *source* (caller-supplied, potentially
  hostile) side of a freeze is opened with O_RDONLY|O_DIRECTORY|O_NOFOLLOW,
  every entry within it is lstat'd via os.stat(name, dir_fd=..,
  follow_symlinks=False) *relative to that already-opened, already-validated
  directory fd* (i.e. via fstatat), and every file we read is opened via
  os.open(name, O_RDONLY|O_NOFOLLOW, dir_fd=..) (i.e. via openat). Because
  every lookup after the first is anchored to a directory fd instead of a
  re-resolved path string, a symlink swapped into the tree *during* traversal
  cannot redirect a later read to a location outside the tree: the kernel
  resolves each name against the fd we already hold, not against the
  original path, and O_NOFOLLOW makes the openat/fstatat calls themselves
  refuse to follow a symlink at the leaf. This is genuine fd-relative
  traversal (not "os.walk + lstat", which re-resolves full path strings and
  is vulnerable to a symlink planted after the lstat but before the open).

  The *destination* (tmp copy / published object) side is plain path-based
  I/O. That is safe because every path on that side is freshly created by
  this process moments earlier under a private, randomly-named,
  mode-0700 `object_store/tmp/<uuid>/` directory that no other actor can
  have guessed or raced into before we finish with it.

Atomic no-overwrite publish:
  Darwin: renamex_np(src, dst, RENAME_EXCL) via ctypes (RENAME_EXCL =
    0x00000004 -- verified live against this platform's <sys/stdio.h>; note
    0x00000002 is RENAME_SWAP, a different flag, on macOS).
  Linux: renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE) via ctypes
    (RENAME_NOREPLACE = 1).
  Anywhere else, or if the symbol can't be resolved: SealError. Never a
  plain os.rename() for the publish step -- that would silently overwrite.
"""
import ctypes
import ctypes.util
import errno as errno_module
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import uuid

from df_common import atomic_write, canonical_json, sha256_str

SEAL_VERSION = "1"

# object_id is always a sha256 hexdigest: 64 lowercase hex chars. Any caller
# passing something else (e.g. a manifest field an attacker tampered with)
# must be refused before it is used to build a filesystem path.
_OBJECT_ID_RE = re.compile(r"\A[0-9a-f]{64}\Z")


class SealError(RuntimeError):
    """Raised on any hostile/unhashable input or any publish that cannot be
    made atomically and without clobbering an existing object."""


# ---------------------------------------------------------------------------
# Canonical manifest: fd-safe scan + hash
# ---------------------------------------------------------------------------


def _check_file_stat(st, rel):
    if st.st_mode & stat.S_ISUID:
        raise SealError(f"setuid file not allowed: {rel}")
    if st.st_mode & stat.S_ISGID:
        raise SealError(f"setgid file not allowed: {rel}")
    if st.st_mode & stat.S_IWOTH:
        raise SealError(f"world-writable file not allowed: {rel}")


def _check_dir_stat(st, rel):
    if st.st_mode & stat.S_IWOTH:
        raise SealError(f"world-writable directory not allowed: {rel}")
    if st.st_mode & stat.S_ISGID:
        raise SealError(f"setgid directory not allowed: {rel}")


def _iter_tree(root_dir):
    """Fd-safe, hostile-rejecting walk of root_dir.

    Yields ("dir", rel_path, None, None) for each subdirectory (top-down,
    before descending into it) and ("file", rel_path, dir_fd, name) for each
    regular file, where dir_fd/name identify the file relative to an
    already-open, already-validated parent directory fd (use with
    os.open(name, ..., dir_fd=dir_fd)). rel_path always uses "/" regardless
    of platform, for canonical/deterministic hashing.

    Raises SealError on any symlink, special file, or hostile-permission
    entry (setuid/setgid/world-writable file, world-writable/setgid dir).
    Never follows a symlink at any point.
    """
    try:
        root_fd = os.open(root_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        raise SealError(f"cannot open root directory {root_dir!r}: {e}") from e
    try:
        root_st = os.fstat(root_fd)
        if not stat.S_ISDIR(root_st.st_mode):
            raise SealError(f"not a directory: {root_dir!r}")
        _check_dir_stat(root_st, ".")
        yield from _iter_dir(root_fd, "")
    finally:
        os.close(root_fd)


def _iter_dir(dir_fd, rel):
    try:
        names = sorted(os.listdir(dir_fd))
    except OSError as e:
        raise SealError(f"cannot list directory {rel or '.'!r}: {e}") from e
    for name in names:
        entry_rel = f"{rel}/{name}" if rel else name
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError as e:
            raise SealError(f"cannot stat {entry_rel}: {e}") from e
        if stat.S_ISLNK(st.st_mode):
            raise SealError(f"symlink not allowed: {entry_rel}")
        if stat.S_ISDIR(st.st_mode):
            _check_dir_stat(st, entry_rel)
            try:
                sub_fd = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd
                )
            except OSError as e:
                raise SealError(f"cannot open directory {entry_rel}: {e}") from e
            try:
                # Re-check against the fd we actually opened (fstat), not just
                # the earlier lstat: closes the TOCTOU window between the
                # lstat above and this open where the entry could have been
                # replaced with a hostile-permission directory.
                sub_st = os.fstat(sub_fd)
                if not stat.S_ISDIR(sub_st.st_mode):
                    raise SealError(f"entry changed type during scan (TOCTOU): {entry_rel}")
                _check_dir_stat(sub_st, entry_rel)
                yield ("dir", entry_rel, None, None)
                yield from _iter_dir(sub_fd, entry_rel)
            finally:
                os.close(sub_fd)
        elif stat.S_ISREG(st.st_mode):
            _check_file_stat(st, entry_rel)
            yield ("file", entry_rel, dir_fd, name)
        else:
            raise SealError(f"special file not allowed: {entry_rel}")


def _sha256_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def _open_file_fd_safe(dir_fd, name, rel):
    """openat(dir_fd, name, O_RDONLY|O_NOFOLLOW|O_NONBLOCK). O_NONBLOCK keeps
    us from ever blocking on a FIFO that got swapped in between the lstat and
    the open (a regular-file open is unaffected by O_NONBLOCK)."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError as e:
        raise SealError(f"cannot open file {rel}: {e}") from e
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode):
        os.close(fd)
        raise SealError(f"entry changed type during scan (TOCTOU): {rel}")
    if fst.st_nlink > 1:
        os.close(fd)
        raise SealError(f"multi-link file not allowed: {rel}")
    # Re-check hostile permission bits against the fd we actually opened, not
    # just the earlier lstat: closes the TOCTOU window between the lstat in
    # _iter_dir and this open where the entry's permissions could have been
    # changed (e.g. setuid added) without changing its type.
    try:
        _check_file_stat(fst, rel)
    except SealError:
        os.close(fd)
        raise
    return fd, fst


def object_manifest(src_dir: str) -> dict:
    """Canonical sidecar dict for src_dir: {seal_version, files, dirs}.

    files: sorted list of {path, size, mode, sha256} (mode = exec-bit
    triplet only, S_IMODE(st_mode) & 0o111). dirs: sorted list of relative
    directory paths, INCLUDING empty directories (structure binding) but
    NOT the root itself.

    Fail-closed: raises SealError on any symlink, special file, multi-link
    file, setuid/setgid/world-writable file, or world-writable/setgid
    directory anywhere in the tree. See module docstring for the fd-safe
    traversal argument.
    """
    files = []
    dirs = []
    for kind, rel, dir_fd, name in _iter_tree(src_dir):
        if kind == "dir":
            dirs.append(rel)
            continue
        fd, fst = _open_file_fd_safe(dir_fd, name, rel)
        try:
            digest = _sha256_fd(fd)
        finally:
            os.close(fd)
        files.append(
            {
                "path": rel,
                "size": fst.st_size,
                "mode": stat.S_IMODE(fst.st_mode) & 0o111,
                "sha256": digest,
            }
        )
    files.sort(key=lambda e: e["path"])
    dirs.sort()
    return {"seal_version": SEAL_VERSION, "files": files, "dirs": dirs}


def object_id_of(manifest: dict) -> str:
    return sha256_str(canonical_json(manifest))


# ---------------------------------------------------------------------------
# Private, trusted-tree copy (destination side; plain path I/O is safe here)
# ---------------------------------------------------------------------------


def _copy_tree_fd_safe(src_dir: str, dst_dir: str) -> None:
    """Copy src_dir's tree into dst_dir (which must already exist, empty).

    Reads the source via the same fd-safe, hostile-rejecting walk as
    object_manifest (so a hostile source is refused here too, before
    anything is published). Writes go to dst_dir by plain path since dst_dir
    is a private, freshly-created, mode-0700 tmp directory this process
    alone controls. Copied file permissions are normalized to 0o600 plus the
    owner-exec bit (never mirror source group/world-writable or setuid/
    setgid bits into the copy). Every file is fsync'd as it is written;
    directories are fsync'd afterwards by the caller (freeze()).
    """
    for kind, rel, dir_fd, name in _iter_tree(src_dir):
        dst_path = os.path.join(dst_dir, *rel.split("/"))
        if kind == "dir":
            os.mkdir(dst_path, mode=0o700)
            continue
        src_fd, fst = _open_file_fd_safe(dir_fd, name, rel)
        try:
            exec_bit = stat.S_IMODE(fst.st_mode) & 0o111
            dst_mode = 0o600 | (0o100 if exec_bit else 0)
            dst_fd = os.open(dst_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dst_mode)
            try:
                os.lseek(src_fd, 0, os.SEEK_SET)
                while True:
                    chunk = os.read(src_fd, 65536)
                    if not chunk:
                        break
                    os.write(dst_fd, chunk)
                os.fsync(dst_fd)
            finally:
                os.close(dst_fd)
        finally:
            os.close(src_fd)


def _fsync_dir_path(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_tree_dirs(root_dir: str) -> None:
    """fsync root_dir and every directory beneath it (our own private tree;
    plain os.walk is fine here -- no untrusted actor can race us in a
    freshly-created mode-0700 tmp directory)."""
    _fsync_dir_path(root_dir)
    for dirpath, dirnames, _filenames in os.walk(root_dir):
        for d in dirnames:
            _fsync_dir_path(os.path.join(dirpath, d))


# ---------------------------------------------------------------------------
# Atomic no-overwrite publish
# ---------------------------------------------------------------------------


def _renamex_np_no_replace(src: str, dst: str) -> None:
    """macOS: renamex_np(src, dst, RENAME_EXCL).

    RENAME_EXCL = 0x00000004 per <sys/stdio.h> on this SDK, verified live:
    with flags=0x4 and dst absent the rename succeeds and dst appears; with
    dst present it fails with errno EEXIST and dst is left untouched. (Note:
    0x00000002 is RENAME_SWAP on macOS, a different, overwriting flag -- do
    not use it here.)
    """
    RENAME_EXCL = 0x00000004
    try:
        libname = ctypes.util.find_library("c") or "libc.dylib"
        libc = ctypes.CDLL(libname, use_errno=True)
        func = libc.renamex_np
    except (OSError, AttributeError) as e:
        raise SealError(f"renamex_np unavailable on this system: {e}") from e
    func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    func.restype = ctypes.c_int
    ctypes.set_errno(0)
    rc = func(os.fsencode(src), os.fsencode(dst), RENAME_EXCL)
    if rc != 0:
        err = ctypes.get_errno()
        if err == errno_module.EEXIST:
            raise SealError(f"object already exists, no-overwrite publish refused: {dst}")
        raise SealError(
            f"renamex_np({src!r}, {dst!r}, RENAME_EXCL) failed: "
            f"errno={err} ({os.strerror(err)})"
        )


def _renameat2_no_replace(src: str, dst: str) -> None:
    """Linux: renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE)."""
    RENAME_NOREPLACE = 1
    AT_FDCWD = -100
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        func = libc.renameat2
    except (OSError, AttributeError) as e:
        raise SealError(f"renameat2 unavailable on this system: {e}") from e
    func.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    func.restype = ctypes.c_int
    ctypes.set_errno(0)
    rc = func(AT_FDCWD, os.fsencode(src), AT_FDCWD, os.fsencode(dst), RENAME_NOREPLACE)
    if rc != 0:
        err = ctypes.get_errno()
        if err == errno_module.EEXIST:
            raise SealError(f"object already exists, no-overwrite publish refused: {dst}")
        raise SealError(
            f"renameat2({src!r}, {dst!r}, RENAME_NOREPLACE) failed: "
            f"errno={err} ({os.strerror(err)})"
        )


def _atomic_publish_dir(tmp_dir: str, dst_dir: str) -> None:
    """Publish tmp_dir as dst_dir with atomic no-overwrite semantics.

    Raises SealError if dst_dir already exists, or if no safe no-overwrite
    rename primitive is available on this platform/build. Never falls back
    to a plain (overwriting) os.rename.
    """
    system = platform.system()
    if system == "Darwin":
        _renamex_np_no_replace(tmp_dir, dst_dir)
    elif system == "Linux":
        _renameat2_no_replace(tmp_dir, dst_dir)
    else:
        raise SealError(
            f"no atomic no-overwrite rename primitive available on platform {system!r}"
        )


def _quarantine(objects_dir: str, dst_dir: str, object_id: str) -> None:
    """Move a present-but-invalid (uncommitted/corrupt) object dir aside.

    Target name is fresh (uuid-suffixed) so plain os.rename cannot clobber
    anything -- this is a cleanup of a known-bad directory, not a publish."""
    q_path = os.path.join(objects_dir, f".corrupt-{object_id}-{uuid.uuid4().hex}")
    try:
        os.rename(dst_dir, q_path)
    except OSError as e:
        raise SealError(f"could not quarantine invalid existing object {dst_dir}: {e}") from e


# ---------------------------------------------------------------------------
# verify_object
# ---------------------------------------------------------------------------


def verify_object(object_store: str, object_id: str) -> bool:
    """Recompute the sidecar over objects/<object_id>/ and require it equals
    the stored sidecar AND object_id_of(recomputed) == object_id.

    Never raises to the caller: any missing object, missing/unreadable/
    invalid sidecar, hostile content planted inside the object dir, or
    mismatch of any kind is a plain False. This is the fail-closed detector;
    it must never be "true by exception being swallowed elsewhere".

    object_id is treated as untrusted (it is expected to be read back from a
    manifest by later callers, e.g. verify/custody, which may have been
    tampered with): it must match a bare 64-char lowercase hex sha256
    digest, or this returns False immediately. This also rules out path
    traversal via a crafted object_id (e.g. "../../etc") reaching outside
    objects_dir through the os.path.join calls below.
    """
    if not isinstance(object_id, str) or not _OBJECT_ID_RE.match(object_id):
        return False

    objects_dir = os.path.join(object_store, "objects")
    obj_path = os.path.join(objects_dir, object_id)
    sidecar_path = os.path.join(objects_dir, object_id + ".json")

    if os.path.islink(obj_path) or not os.path.isdir(obj_path):
        return False
    if os.path.islink(sidecar_path) or not os.path.isfile(sidecar_path):
        return False

    try:
        with open(sidecar_path, "r", encoding="utf-8") as f:
            stored = json.load(f)
    except (OSError, ValueError):
        return False

    try:
        recomputed = object_manifest(obj_path)
    except SealError:
        return False

    if recomputed != stored:
        return False
    if object_id_of(recomputed) != object_id:
        return False
    return True


# ---------------------------------------------------------------------------
# freeze
# ---------------------------------------------------------------------------


def freeze(src_dir: str, object_store: str) -> str:
    """Freeze src_dir into object_store as an immutable content-addressed
    object. Returns the hex object_id.

    Order of operations (why it is race-safe):
      1. Copy src_dir into a private tmp dir (object_store/tmp/<uuid>/),
         fd-safe + hostile-rejecting on the source side.
      2. fsync every copied file (during the copy) and every directory
         (after).
      3. Compute the manifest by SCANNING THE COPY (object_manifest(tmp_dir)),
         never the original src_dir. This is what makes the result immune to
         a source mutated mid-freeze: whatever ends up on disk in tmp_dir
         after step 1 is exactly what step 3 hashes and exactly what step 5
         publishes -- there is no path by which the recorded identity can
         diverge from the published bytes.
      4. If an object with that id is already published and verifies, reuse
         it (idempotent) and discard the redundant tmp copy. If one exists
         but fails verification (uncommitted or corrupt), quarantine it.
      5. Publish tmp_dir -> objects/<object_id>/ via the platform's atomic
         no-overwrite rename primitive.
      6. Write the sidecar LAST (objects/<object_id>.json) -- the commit
         record. If steps 1-5 succeeded but the process dies before step 6,
         the object dir exists without a valid sidecar and is correctly
         treated as uncommitted by verify_object (and will be quarantined
         and re-published by a future freeze() of the same tree).
    """
    src_dir = os.path.abspath(src_dir)
    object_store = os.path.abspath(object_store)
    objects_dir = os.path.join(object_store, "objects")
    tmp_root = os.path.join(object_store, "tmp")
    os.makedirs(objects_dir, exist_ok=True)
    os.makedirs(tmp_root, exist_ok=True)
    try:
        os.chmod(tmp_root, 0o700)
    except OSError:
        pass

    tmp_dir = os.path.join(tmp_root, uuid.uuid4().hex)
    os.mkdir(tmp_dir, mode=0o700)

    published = False
    try:
        _copy_tree_fd_safe(src_dir, tmp_dir)
        _fsync_tree_dirs(tmp_dir)

        # Hash what was published, not the (possibly still-mutating) source.
        manifest = object_manifest(tmp_dir)
        object_id = object_id_of(manifest)

        dst_dir = os.path.join(objects_dir, object_id)
        sidecar_path = os.path.join(objects_dir, object_id + ".json")

        if os.path.lexists(dst_dir):
            if verify_object(object_store, object_id):
                return object_id  # idempotent reuse; tmp_dir discarded below
            _quarantine(objects_dir, dst_dir, object_id)

        try:
            _atomic_publish_dir(tmp_dir, dst_dir)
        except SealError:
            # Someone else may have published the same content concurrently.
            if verify_object(object_store, object_id):
                return object_id
            raise
        published = True

        try:
            _fsync_dir_path(objects_dir)
        except OSError:
            pass

        # Sidecar is the commit record, written LAST.
        atomic_write(sidecar_path, canonical_json(manifest))
        return object_id
    finally:
        if not published and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
