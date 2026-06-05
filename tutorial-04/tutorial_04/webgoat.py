"""WebGoat-specific helpers — path resolution + lesson-folder enumeration.

WebGoat lives at https://github.com/WebGoat/WebGoat. Its lessons sit
under ``src/main/java/org/owasp/webgoat/lessons/``, each in its own
subdirectory named after the lesson (e.g. ``sqlinjection/``,
``pathtraversal/``).

This module is intentionally small — it just gives the rest of the
pipeline (and tests) a few WebGoat-aware conveniences without spreading
hard-coded paths around.
"""
from __future__ import annotations

from pathlib import Path


WEBGOAT_LESSONS_SUBDIR = "src/main/java/org/owasp/webgoat/lessons"


def resolve_webgoat_root(raw: str | Path) -> Path:
    """Expand ``~`` and resolve a user-supplied WebGoat path.

    Raises ``FileNotFoundError`` with a helpful message when the
    expected layout (``src/main/java/org/owasp/webgoat/lessons/``) isn't
    present — covers the most common mistake: pointing at the GitHub
    URL instead of a cloned directory.
    """
    p = Path(raw).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(
            f"WebGoat source not found at {p}. Clone it first: "
            f"git clone https://github.com/WebGoat/WebGoat {p}"
        )
    lessons = p / WEBGOAT_LESSONS_SUBDIR
    if not lessons.exists():
        raise FileNotFoundError(
            f"{p} doesn't look like a WebGoat checkout — expected "
            f"{lessons} to exist. Did you point --webgoat-source at the "
            f"repository root?"
        )
    return p


def lesson_dirs(webgoat_root: Path) -> list[Path]:
    """Return every lesson-package directory under the WebGoat root."""
    lessons_root = webgoat_root / WEBGOAT_LESSONS_SUBDIR
    return sorted(p for p in lessons_root.iterdir() if p.is_dir())


def lesson_name_from_path(webgoat_root: Path, file_path: str) -> str | None:
    """Extract the lesson package name from a file's relative path.

    ``file_path`` is the report's ``file_path`` field (POSIX-relative to
    the scan root). For ``src/main/java/org/owasp/webgoat/lessons/sqlinjection/
    SqlInjectionLesson5a.java`` this returns ``sqlinjection``.

    Returns None when the file isn't under the lessons tree (e.g. a
    finding in the controller layer rather than a lesson).
    """
    marker = WEBGOAT_LESSONS_SUBDIR + "/"
    idx = file_path.find(marker)
    if idx < 0:
        return None
    tail = file_path[idx + len(marker):]
    if "/" not in tail:
        return None
    return tail.split("/", 1)[0]


__all__ = [
    "WEBGOAT_LESSONS_SUBDIR",
    "lesson_dirs",
    "lesson_name_from_path",
    "resolve_webgoat_root",
]
