"""Parser for the multi-target file passed via ``--targets-file``.

Format is deliberately simple — readable in a tutorial, no YAML/JSON
ceremony:

- One target per line.
- ``URL`` for a GET-style target (sqlmap tests query-string params), or
  ``URL | DATA`` for a POST body in application/x-www-form-urlencoded form.
- Blank lines are ignored.
- Lines starting with ``#`` are comments.

Example file::

    # WebGoat SQL Injection (intro) lessons
    http://localhost:8080/WebGoat/SqlInjection/assignment5b | login_count=1&userid=1
    http://localhost:8080/WebGoat/SqlInjection/assignment5a | account=Smith&operator=or&injection=1+%3D+1

    # A non-injectable endpoint — proves the analyst can say "no finding"
    http://localhost:8080/WebGoat/service/lessonmenu.mvc

The cookie is **not** per-line. All WebGoat lessons share one JSESSIONID
for a single logged-in session, so ``--cookie`` is one flag on the CLI,
applied to every target.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Target:
    """One target URL plus its optional POST data."""

    url: str
    data: str | None = None


class TargetsFileError(ValueError):
    """Raised on a malformed or empty targets file."""


def parse_targets_file(path: Path) -> list[Target]:
    """Read and parse a targets file.

    Raises :class:`TargetsFileError` if the file is missing, malformed,
    or empty after comment/blank-line stripping (empty input is almost
    always a typo).
    """
    if not path.exists():
        raise TargetsFileError(f"Targets file not found: {path}")
    return parse_targets_text(path.read_text(encoding="utf-8"), source=str(path))


def parse_targets_text(text: str, *, source: str = "<text>") -> list[Target]:
    """Parse the textual contents of a targets file.

    Split out from :func:`parse_targets_file` so it's directly testable
    with in-memory strings.
    """
    targets: list[Target] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) > 2:
            raise TargetsFileError(
                f"{source}:{lineno}: expected 'URL' or 'URL | DATA', "
                f"got too many '|' separators: {raw!r}"
            )
        url = parts[0].strip()
        if not url:
            raise TargetsFileError(f"{source}:{lineno}: empty URL: {raw!r}")
        data = parts[1].strip() if len(parts) == 2 else None
        if data == "":
            data = None
        targets.append(Target(url=url, data=data))
    if not targets:
        raise TargetsFileError(
            f"{source}: no targets found (file empty after comment/blank-line stripping)."
        )
    return targets


__all__ = ["Target", "TargetsFileError", "parse_targets_file", "parse_targets_text"]
