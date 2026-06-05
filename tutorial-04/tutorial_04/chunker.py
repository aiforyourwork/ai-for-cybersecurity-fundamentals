"""Source-tree walker — find target files for semgrep to scan.

Pure Python. No AI. No subprocess. Just a deterministic walker that
returns the list of files semgrep should consider. The full WebGoat
repo has many files semgrep would happily ignore (build artefacts,
tests, frontend assets); this module pre-filters to the files that
matter so the per-file budget (``--max-files``) is spent on signal.

Default filter (tuned for WebGoat's Java/Spring Boot layout):

  - INCLUDE: ``.java`` under ``src/main/java/`` (the lesson source)
  - EXCLUDE: ``src/test/``, ``target/``, ``node_modules/``, ``.git/``

Override the filter via ``include_globs`` / ``exclude_globs`` when
pointing at a non-Java codebase.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_INCLUDE_GLOBS: tuple[str, ...] = (
    "src/main/java/**/*.java",
    "src/main/resources/**/*.xml",
)

DEFAULT_EXCLUDE_GLOBS: tuple[str, ...] = (
    "src/test/**",
    "target/**",
    "build/**",
    "node_modules/**",
    ".git/**",
    ".gradle/**",
    ".idea/**",
)


@dataclass(frozen=True)
class FileSet:
    """Result of one walk — the file list plus a quick stat summary."""

    files: list[Path]
    walked: int                # files visited before filtering
    skipped: list[Path] = field(default_factory=list)
    truncated: bool = False    # True iff --max-files capped the result


def collect_target_files(
    *,
    root: Path,
    include_globs: tuple[str, ...] = DEFAULT_INCLUDE_GLOBS,
    exclude_globs: tuple[str, ...] = DEFAULT_EXCLUDE_GLOBS,
    max_files: int | None = None,
) -> FileSet:
    """Walk ``root`` and return the files semgrep should scan.

    Order is deterministic (lexicographic by relative path) so re-runs
    produce identical file lists — important for the report being
    reproducible across runs against an unchanged codebase.

    ``max_files`` caps the result for demo-scoping. When set and the
    pre-cap list is larger, ``FileSet.truncated`` is True so the caller
    can warn the user explicitly (silent truncation reads as "covered
    everything" when it didn't).
    """
    if not root.exists():
        raise FileNotFoundError(f"Source root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Source root is not a directory: {root}")

    matched: list[Path] = []
    walked = 0
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        walked += 1
        rel = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, pat) for pat in exclude_globs):
            continue
        if not any(fnmatch.fnmatch(rel, pat) for pat in include_globs):
            continue
        matched.append(path)

    truncated = False
    if max_files is not None and len(matched) > max_files:
        matched = matched[:max_files]
        truncated = True

    return FileSet(files=matched, walked=walked, truncated=truncated)


def render_fileset_for_terminal(fs: FileSet, *, root: Path) -> str:
    """One-line summary plus first 5 file paths."""
    lines = [
        f"  Files matched : {len(fs.files):,} / {fs.walked:,} walked"
        + (" (truncated by --max-files)" if fs.truncated else "")
    ]
    for f in fs.files[:5]:
        try:
            lines.append(f"    - {f.relative_to(root).as_posix()}")
        except ValueError:
            lines.append(f"    - {f}")
    if len(fs.files) > 5:
        lines.append(f"    ... and {len(fs.files) - 5} more.")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_EXCLUDE_GLOBS",
    "DEFAULT_INCLUDE_GLOBS",
    "FileSet",
    "collect_target_files",
    "render_fileset_for_terminal",
]
