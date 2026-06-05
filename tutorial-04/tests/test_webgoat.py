"""Tests for the webgoat path helpers."""
from __future__ import annotations

import pytest

from tutorial_04.webgoat import (
    WEBGOAT_LESSONS_SUBDIR,
    lesson_dirs,
    lesson_name_from_path,
    resolve_webgoat_root,
)


def _make_fake_webgoat(tmp_path):
    """Create a minimal directory layout that resolve_webgoat_root accepts."""
    lessons = tmp_path / WEBGOAT_LESSONS_SUBDIR
    (lessons / "sqlinjection").mkdir(parents=True)
    (lessons / "pathtraversal").mkdir(parents=True)
    (lessons / "sqlinjection" / "Lesson5a.java").write_text("class L {}")
    return tmp_path


def test_resolve_accepts_valid_layout(tmp_path):
    root = _make_fake_webgoat(tmp_path)
    assert resolve_webgoat_root(str(root)).resolve() == root.resolve()


def test_resolve_rejects_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        resolve_webgoat_root(tmp_path / "does-not-exist")


def test_resolve_rejects_layout_without_lessons(tmp_path):
    (tmp_path / "src" / "main").mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        resolve_webgoat_root(tmp_path)


def test_lesson_dirs_enumerates(tmp_path):
    root = _make_fake_webgoat(tmp_path)
    names = [d.name for d in lesson_dirs(root)]
    assert names == ["pathtraversal", "sqlinjection"]


def test_lesson_name_from_path_picks_lesson():
    assert lesson_name_from_path(
        webgoat_root=None,  # not used by the function
        file_path="src/main/java/org/owasp/webgoat/lessons/sqlinjection/Foo.java",
    ) == "sqlinjection"


def test_lesson_name_from_path_returns_none_for_non_lesson():
    assert lesson_name_from_path(
        webgoat_root=None,
        file_path="src/main/java/org/owasp/webgoat/controller/MainController.java",
    ) is None


def test_lesson_name_from_path_handles_bare_marker():
    # The exact marker with no tail → no lesson name to extract.
    assert lesson_name_from_path(
        webgoat_root=None,
        file_path="src/main/java/org/owasp/webgoat/lessons/",
    ) is None
