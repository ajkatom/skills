import os

import pytest

import snapshot_source


def make_src(tmp_path):
    src = tmp_path / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "a.txt").write_text("alpha", encoding="utf-8")
    (src / "pkg" / "b.txt").write_text("beta", encoding="utf-8")
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    return src


def test_manifest_lists_files_sorted_and_skips_git(tmp_path):
    src = make_src(tmp_path)
    m = snapshot_source.build_manifest(str(src))
    assert m["manifest_version"] == "0.1"
    assert [e["path"] for e in m["files"]] == ["a.txt", os.path.join("pkg", "b.txt")]
    assert all(len(e["sha256"]) == 64 for e in m["files"])


def test_symlink_is_rejected(tmp_path):
    src = make_src(tmp_path)
    os.symlink("/etc/hosts", src / "evil_link")
    with pytest.raises(snapshot_source.SnapshotError, match="symlink"):
        snapshot_source.build_manifest(str(src))


def test_symlinked_dir_is_rejected(tmp_path):
    src = make_src(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, src / "evil_dir")
    with pytest.raises(snapshot_source.SnapshotError, match="symlink"):
        snapshot_source.build_manifest(str(src))


def test_hardlinked_file_is_rejected(tmp_path):
    src = make_src(tmp_path)
    os.link(src / "a.txt", src / "hard.txt")
    with pytest.raises(snapshot_source.SnapshotError, match="multi-link"):
        snapshot_source.build_manifest(str(src))


def test_fifo_is_rejected(tmp_path):
    src = make_src(tmp_path)
    os.mkfifo(src / "pipe")
    with pytest.raises(snapshot_source.SnapshotError, match="special"):
        snapshot_source.build_manifest(str(src))


def test_snapshot_copies_content_and_hash_is_stable(tmp_path):
    src = make_src(tmp_path)
    dest = tmp_path / "dest"
    m1, h1 = snapshot_source.snapshot(str(src), str(dest))
    assert (dest / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (dest / "pkg" / "b.txt").read_text(encoding="utf-8") == "beta"
    assert not (dest / ".git").exists()
    m2 = snapshot_source.build_manifest(str(src))
    import df_common
    assert h1 == df_common.sha256_str(df_common.canonical_json(m2))


def test_empty_source_gives_empty_manifest(tmp_path):
    src = tmp_path / "empty"
    src.mkdir()
    dest = tmp_path / "dest"
    m, h = snapshot_source.snapshot(str(src), str(dest))
    assert m["files"] == []
    assert os.path.isdir(dest)
