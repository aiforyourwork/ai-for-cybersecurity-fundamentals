"""Tests for the chunker — source-tree walker.

Pure function, no AI, no subprocess. Easy to test exhaustively.
"""
from __future__ import annotations

import pytest

from tutorial_04.chunker import (
    DEFAULT_EXCLUDE_GLOBS,
    DEFAULT_INCLUDE_GLOBS,
    collect_target_files,
)


def _write(p, content=""):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_collect_includes_default_java_paths(tmp_path):
    _write(tmp_path / "src/main/java/com/Foo.java", "class Foo {}")
    _write(tmp_path / "src/main/java/com/Bar.java", "class Bar {}")
    _write(tmp_path / "README.md", "docs")
    fs = collect_target_files(root=tmp_path)
    rel = [p.relative_to(tmp_path).as_posix() for p in fs.files]
    assert "src/main/java/com/Foo.java" in rel
    assert "src/main/java/com/Bar.java" in rel
    assert "README.md" not in rel


def test_collect_excludes_test_and_build(tmp_path):
    _write(tmp_path / "src/main/java/com/A.java", "")
    _write(tmp_path / "src/test/java/com/T.java", "")
    _write(tmp_path / "target/classes/com/B.class", "")
    fs = collect_target_files(root=tmp_path)
    rel = [p.relative_to(tmp_path).as_posix() for p in fs.files]
    assert rel == ["src/main/java/com/A.java"]


def test_collect_is_lexicographic(tmp_path):
    for n in ["Z.java", "A.java", "M.java"]:
        _write(tmp_path / f"src/main/java/com/{n}", "")
    fs = collect_target_files(root=tmp_path)
    names = [p.name for p in fs.files]
    assert names == ["A.java", "M.java", "Z.java"]


def test_max_files_truncates_and_flags(tmp_path):
    for n in range(20):
        _write(tmp_path / f"src/main/java/com/F{n:02d}.java", "")
    fs = collect_target_files(root=tmp_path, max_files=5)
    assert len(fs.files) == 5
    assert fs.truncated is True
    # Below cap → not truncated
    fs2 = collect_target_files(root=tmp_path, max_files=100)
    assert len(fs2.files) == 20
    assert fs2.truncated is False


def test_missing_root_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        collect_target_files(root=tmp_path / "does-not-exist")


def test_root_that_is_file_raises(tmp_path):
    f = tmp_path / "not-a-dir.txt"
    f.write_text("oops")
    with pytest.raises(NotADirectoryError):
        collect_target_files(root=f)


def test_custom_include_glob(tmp_path):
    # Mirrors the shape of DEFAULT_INCLUDE_GLOBS ("src/main/java/**/*.java"):
    # the `**` segment expects at least one directory layer to traverse.
    _write(tmp_path / "src/main/python/pkg/foo.py", "")
    _write(tmp_path / "src/main/python/pkg/bar.py", "")
    _write(tmp_path / "src/main/java/Foo.java", "")
    fs = collect_target_files(
        root=tmp_path,
        include_globs=("src/main/python/**/*.py",),
        exclude_globs=DEFAULT_EXCLUDE_GLOBS,
    )
    rel = [p.relative_to(tmp_path).as_posix() for p in fs.files]
    assert sorted(rel) == ["src/main/python/pkg/bar.py", "src/main/python/pkg/foo.py"]
