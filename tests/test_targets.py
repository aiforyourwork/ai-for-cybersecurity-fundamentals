"""Tests for ``tutorial_02/targets.py``.

The parser is small and pure — what matters is that:

- Comments and blank lines are stripped.
- URLs alone (GET) and ``URL | DATA`` (POST) both parse.
- Malformed lines raise a clear ``TargetsFileError``.
- Empty-after-stripping files raise too — usually a typo.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tutorial_02.targets import (
    Target,
    TargetsFileError,
    parse_targets_file,
    parse_targets_text,
)


# ─── Happy path ─────────────────────────────────────────────────────────────

def test_parses_get_only_url():
    targets = parse_targets_text("http://example.com/a")
    assert targets == [Target(url="http://example.com/a", data=None)]


def test_parses_url_with_post_data():
    targets = parse_targets_text("http://example.com/a | x=1&y=2")
    assert targets == [Target(url="http://example.com/a", data="x=1&y=2")]


def test_strips_whitespace_around_url_and_data():
    targets = parse_targets_text("   http://example.com/a   |   x=1  ")
    assert targets == [Target(url="http://example.com/a", data="x=1")]


def test_skips_comments_and_blank_lines():
    text = """\
# header comment
http://a/1 | p=1

  # indented comment
http://b/2 | q=2
\t
http://c/3
"""
    targets = parse_targets_text(text)
    assert targets == [
        Target(url="http://a/1", data="p=1"),
        Target(url="http://b/2", data="q=2"),
        Target(url="http://c/3", data=None),
    ]


def test_empty_data_after_pipe_becomes_none():
    """'URL |   ' (pipe with empty data) should be treated as a GET — not
    a POST with empty body. Catches a footgun where the user adds a pipe
    expecting to fill in data later."""
    targets = parse_targets_text("http://example.com/a |   ")
    assert targets == [Target(url="http://example.com/a", data=None)]


# ─── Errors ─────────────────────────────────────────────────────────────────

def test_too_many_pipes_raises():
    with pytest.raises(TargetsFileError, match="too many"):
        parse_targets_text("http://a | x=1 | extra")


def test_empty_url_raises():
    with pytest.raises(TargetsFileError, match="empty URL"):
        parse_targets_text("  | x=1")


def test_empty_file_raises():
    """A file with nothing but blanks/comments is almost always a typo."""
    with pytest.raises(TargetsFileError, match="no targets"):
        parse_targets_text("# only a comment\n\n   \n")


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(TargetsFileError, match="not found"):
        parse_targets_file(tmp_path / "does-not-exist.txt")


# ─── File round-trip ────────────────────────────────────────────────────────

def test_parse_targets_file_round_trip(tmp_path: Path):
    p = tmp_path / "targets.txt"
    p.write_text(
        "# comment\n"
        "http://localhost:8080/WebGoat/SqlInjection/assignment5b | login_count=1&userid=1\n"
        "http://localhost:8080/WebGoat/service/lessonmenu.mvc\n",
        encoding="utf-8",
    )
    targets = parse_targets_file(p)
    assert len(targets) == 2
    assert targets[0].url.endswith("/assignment5b")
    assert targets[0].data == "login_count=1&userid=1"
    assert targets[1].data is None


def test_error_message_includes_line_number_and_source():
    """Helpful diagnostics — point the user at the bad line."""
    with pytest.raises(TargetsFileError, match=r"<text>:2"):
        parse_targets_text(
            "http://ok\n"
            "http://bad | a | b\n",
            source="<text>",
        )
