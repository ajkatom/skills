"""lstat-manifest source snapshot (spec section 7.1). Stdlib only.

Builds a history-free copy of an approved source root for the build
workspace: no .git, no symlinks, no special files, no multi-hardlink files
(st_nlink > 1 is the conservative rejection for hardlink escape).
"""
import os
import shutil
import stat

from df_common import canonical_json, sha256_file, sha256_str

EXCLUDE_DIRS = {".git"}


class SnapshotError(ValueError):
    pass


def build_manifest(src_root: str) -> dict:
    src_root = os.path.realpath(src_root)
    entries = []
    for dirpath, dirnames, filenames in os.walk(src_root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                raise SnapshotError(f"symlink not allowed in source: {full}")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                raise SnapshotError(f"symlink not allowed in source: {full}")
            if not stat.S_ISREG(st.st_mode):
                raise SnapshotError(f"special file not allowed in source: {full}")
            if st.st_nlink > 1:
                raise SnapshotError(f"multi-link file not allowed in source: {full}")
            rel = os.path.relpath(full, src_root)
            entries.append(
                {"path": rel, "size": st.st_size, "sha256": sha256_file(full)}
            )
    entries.sort(key=lambda e: e["path"])
    return {"manifest_version": "0.1", "files": entries}


def snapshot(src_root: str, dest_root: str):
    """Copy the manifest's files into dest_root. Returns (manifest, manifest_sha256)."""
    manifest = build_manifest(src_root)
    os.makedirs(dest_root, exist_ok=True)
    for e in manifest["files"]:
        s = os.path.join(src_root, e["path"])
        d = os.path.join(dest_root, e["path"])
        os.makedirs(os.path.dirname(d) or dest_root, exist_ok=True)
        with open(s, "rb") as fs, open(d, "wb") as fd:
            shutil.copyfileobj(fs, fd)
    return manifest, sha256_str(canonical_json(manifest))
