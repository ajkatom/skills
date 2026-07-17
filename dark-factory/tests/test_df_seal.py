import ctypes
import os
import stat

import pytest

import df_seal


def make_tree(root, layout_order="a_then_pkg"):
    """Build a small tree with a file, a subdir file, and an empty dir."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "empty_dir").mkdir()
    if layout_order == "a_then_pkg":
        (root / "a.txt").write_text("alpha", encoding="utf-8")
        (root / "pkg").mkdir()
        (root / "pkg" / "b.txt").write_text("beta", encoding="utf-8")
    else:
        (root / "pkg").mkdir()
        (root / "pkg" / "b.txt").write_text("beta", encoding="utf-8")
        (root / "a.txt").write_text("alpha", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# object_manifest / object_id_of: canonical, order-independent identity
# ---------------------------------------------------------------------------


def test_identical_trees_built_in_different_order_hash_identically(tmp_path):
    t1 = make_tree(tmp_path / "t1", "a_then_pkg")
    t2 = make_tree(tmp_path / "t2", "pkg_then_a")
    m1 = df_seal.object_manifest(str(t1))
    m2 = df_seal.object_manifest(str(t2))
    assert df_seal.object_id_of(m1) == df_seal.object_id_of(m2)


def test_one_byte_change_changes_object_id(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    base_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    (t1 / "a.txt").write_text("alphb", encoding="utf-8")
    new_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    assert base_id != new_id


def test_exec_bit_change_changes_object_id(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    base_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    p = t1 / "a.txt"
    os.chmod(str(p), stat.S_IMODE(os.stat(str(p)).st_mode) | stat.S_IXUSR)
    new_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    assert base_id != new_id


def test_added_file_changes_object_id(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    base_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    (t1 / "new.txt").write_text("new", encoding="utf-8")
    new_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    assert base_id != new_id


def test_removed_file_changes_object_id(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    base_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    (t1 / "pkg" / "b.txt").unlink()
    new_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    assert base_id != new_id


def test_rename_changes_object_id(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    base_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    (t1 / "a.txt").rename(t1 / "a_renamed.txt")
    new_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    assert base_id != new_id


def test_added_empty_directory_changes_object_id(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    base_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    (t1 / "another_empty_dir").mkdir()
    new_id = df_seal.object_id_of(df_seal.object_manifest(str(t1)))
    assert base_id != new_id


def test_empty_directories_are_included_in_manifest(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    m = df_seal.object_manifest(str(t1))
    assert "empty_dir" in m["dirs"]
    assert "pkg" in m["dirs"]


# ---------------------------------------------------------------------------
# Hostile-metadata rejection (fail-closed)
# ---------------------------------------------------------------------------


def test_symlink_file_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    os.symlink("/etc/hosts", t1 / "evil_link")
    with pytest.raises(df_seal.SealError, match="symlink"):
        df_seal.object_manifest(str(t1))


def test_symlinked_dir_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, t1 / "evil_dir")
    with pytest.raises(df_seal.SealError, match="symlink"):
        df_seal.object_manifest(str(t1))


def test_special_file_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    os.mkfifo(t1 / "pipe")
    with pytest.raises(df_seal.SealError, match="special"):
        df_seal.object_manifest(str(t1))


def test_multi_link_file_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    os.link(t1 / "a.txt", t1 / "hard.txt")
    with pytest.raises(df_seal.SealError, match="multi-link"):
        df_seal.object_manifest(str(t1))


def test_setuid_file_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    p = t1 / "a.txt"
    os.chmod(str(p), stat.S_IMODE(os.stat(str(p)).st_mode) | stat.S_ISUID)
    with pytest.raises(df_seal.SealError, match="setuid"):
        df_seal.object_manifest(str(t1))


def test_setgid_file_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    p = t1 / "a.txt"
    os.chmod(str(p), stat.S_IMODE(os.stat(str(p)).st_mode) | stat.S_ISGID)
    with pytest.raises(df_seal.SealError, match="setgid"):
        df_seal.object_manifest(str(t1))


def test_world_writable_file_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    p = t1 / "a.txt"
    os.chmod(str(p), stat.S_IMODE(os.stat(str(p)).st_mode) | stat.S_IWOTH)
    with pytest.raises(df_seal.SealError, match="world-writable"):
        df_seal.object_manifest(str(t1))


def test_world_writable_dir_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    p = t1 / "pkg"
    os.chmod(str(p), stat.S_IMODE(os.stat(str(p)).st_mode) | stat.S_IWOTH)
    with pytest.raises(df_seal.SealError, match="world-writable"):
        df_seal.object_manifest(str(t1))


def test_setgid_dir_rejected(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    p = t1 / "pkg"
    os.chmod(str(p), stat.S_IMODE(os.stat(str(p)).st_mode) | stat.S_ISGID)
    with pytest.raises(df_seal.SealError, match="setgid"):
        df_seal.object_manifest(str(t1))


# ---------------------------------------------------------------------------
# freeze / verify_object round trip
# ---------------------------------------------------------------------------


def test_freeze_then_verify_object_true(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"
    object_id = df_seal.freeze(str(t1), str(store))
    assert len(object_id) == 64
    assert df_seal.verify_object(str(store), object_id) is True


def test_freeze_publishes_expected_layout(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"
    object_id = df_seal.freeze(str(t1), str(store))
    obj_dir = store / "objects" / object_id
    sidecar = store / "objects" / (object_id + ".json")
    assert obj_dir.is_dir()
    assert sidecar.is_file()
    assert (obj_dir / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (obj_dir / "pkg" / "b.txt").read_text(encoding="utf-8") == "beta"
    assert (obj_dir / "empty_dir").is_dir()


def test_mutating_published_object_makes_verify_false(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"
    object_id = df_seal.freeze(str(t1), str(store))
    obj_file = store / "objects" / object_id / "a.txt"
    obj_file.write_text("tampered", encoding="utf-8")
    assert df_seal.verify_object(str(store), object_id) is False


def test_freeze_same_tree_twice_is_idempotent_and_does_not_raise(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"
    id1 = df_seal.freeze(str(t1), str(store))
    id2 = df_seal.freeze(str(t1), str(store))
    assert id1 == id2
    assert df_seal.verify_object(str(store), id1) is True


def test_object_dir_without_sidecar_is_uncommitted(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"
    object_id = df_seal.freeze(str(t1), str(store))
    sidecar = store / "objects" / (object_id + ".json")
    sidecar.unlink()
    assert df_seal.verify_object(str(store), object_id) is False


def test_verify_object_missing_object_is_false(tmp_path):
    store = tmp_path / "store"
    (store / "objects").mkdir(parents=True)
    assert df_seal.verify_object(str(store), "0" * 64) is False


def test_freeze_rejects_hostile_source(tmp_path):
    t1 = make_tree(tmp_path / "t1")
    os.symlink("/etc/hosts", t1 / "evil_link")
    store = tmp_path / "store"
    with pytest.raises(df_seal.SealError):
        df_seal.freeze(str(t1), str(store))


# ---------------------------------------------------------------------------
# Atomic-primitive availability
# ---------------------------------------------------------------------------


def test_freeze_raises_when_no_atomic_primitive_available(tmp_path, monkeypatch):
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"
    monkeypatch.setattr(df_seal.platform, "system", lambda: "Windows")
    with pytest.raises(df_seal.SealError, match="atomic"):
        df_seal.freeze(str(t1), str(store))
    # Nothing should be left published under objects/ for the corresponding tree.
    objects_dir = store / "objects"
    if objects_dir.exists():
        published_dirs = [
            p for p in objects_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
        ]
        assert published_dirs == []


def test_freeze_raises_when_renamex_np_symbol_missing(tmp_path, monkeypatch):
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"

    class _FakeLib:
        pass  # no renamex_np attribute -> AttributeError inside df_seal

    monkeypatch.setattr(df_seal.ctypes, "CDLL", lambda *a, **k: _FakeLib())
    with pytest.raises(df_seal.SealError, match="renamex_np unavailable"):
        df_seal.freeze(str(t1), str(store))


# ---------------------------------------------------------------------------
# Race injection: source mutated mid-freeze
# ---------------------------------------------------------------------------


def test_race_mutation_during_copy_is_never_silently_mismatched(tmp_path, monkeypatch):
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"

    real_copy = df_seal._copy_tree_fd_safe

    def mutating_copy(src_dir, dst_dir):
        real_copy(src_dir, dst_dir)
        # Mutate the SOURCE after the copy has already happened. If freeze()
        # hashes the source (wrong) instead of what it published, this would
        # go undetected. It must hash the already-copied dst_dir instead.
        (t1 / "a.txt").write_text("mutated-after-copy", encoding="utf-8")

    monkeypatch.setattr(df_seal, "_copy_tree_fd_safe", mutating_copy)

    try:
        object_id = df_seal.freeze(str(t1), str(store))
    except df_seal.SealError:
        # Raising instead of publishing is an acceptable fail-closed outcome.
        return

    # If freeze() succeeded, the published object must be internally
    # consistent with its own sidecar (i.e. verify_object is True), and must
    # NOT reflect the post-copy source mutation.
    assert df_seal.verify_object(str(store), object_id) is True
    obj_file = store / "objects" / object_id / "a.txt"
    assert obj_file.read_text(encoding="utf-8") == "alpha"


def test_race_mutation_during_manifest_scan_source_never_used(tmp_path, monkeypatch):
    """A stronger race: mutate the source between the copy finishing and the
    manifest being computed. Because the manifest is computed over the copy
    (dst_dir), not the source, this must not affect the published object."""
    t1 = make_tree(tmp_path / "t1")
    store = tmp_path / "store"

    real_manifest = df_seal.object_manifest
    call_count = {"n": 0}

    def mutating_manifest(path):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First call inside freeze() is over the tmp copy dir; mutate the
            # original source now, which must have zero effect on the result.
            (t1 / "a.txt").write_text("mutated-during-scan", encoding="utf-8")
        return real_manifest(path)

    monkeypatch.setattr(df_seal, "object_manifest", mutating_manifest)

    object_id = df_seal.freeze(str(t1), str(store))
    assert df_seal.verify_object(str(store), object_id) is True
    obj_file = store / "objects" / object_id / "a.txt"
    assert obj_file.read_text(encoding="utf-8") == "alpha"


# ---------------------------------------------------------------------------
# renamex_np live sanity (macOS) — confirms the ctypes signature is correct
# ---------------------------------------------------------------------------


def test_renamex_np_no_replace_refuses_existing_destination(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    with pytest.raises(df_seal.SealError):
        df_seal._renamex_np_no_replace(str(src), str(dst))
    # dst must be untouched (still an empty dir, not replaced by src).
    assert dst.is_dir()
    assert list(dst.iterdir()) == []


def test_renamex_np_no_replace_succeeds_when_destination_absent(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "marker.txt").write_text("x", encoding="utf-8")
    df_seal._renamex_np_no_replace(str(src), str(dst))
    assert dst.is_dir()
    assert (dst / "marker.txt").read_text(encoding="utf-8") == "x"
    assert not src.exists()
