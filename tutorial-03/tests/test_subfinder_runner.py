"""Subfinder wrapper tests — focused on stdout parsing.

The subprocess call itself isn't unit-tested (would require subfinder
installed locally and would make network calls); the parser that
turns its stdout into a clean tuple is."""
from __future__ import annotations

from tutorial_03.subfinder_runner import _parse_subfinder_stdout


def test_parser_handles_simple_lines():
    out = _parse_subfinder_stdout("a.example.com\nb.example.com\nc.example.com\n")
    assert out == ("a.example.com", "b.example.com", "c.example.com")


def test_parser_dedupes_preserving_order():
    out = _parse_subfinder_stdout("a.example.com\nb.example.com\na.example.com\n")
    assert out == ("a.example.com", "b.example.com")


def test_parser_lowercases():
    out = _parse_subfinder_stdout("A.example.com\nB.EXAMPLE.com\n")
    assert out == ("a.example.com", "b.example.com")


def test_parser_strips_trailing_dot():
    out = _parse_subfinder_stdout("a.example.com.\nb.example.com\n")
    assert out == ("a.example.com", "b.example.com")


def test_parser_skips_blank_lines_and_whitespace_only():
    out = _parse_subfinder_stdout("a.example.com\n\n   \nb.example.com\n")
    assert out == ("a.example.com", "b.example.com")


def test_parser_drops_lines_with_obvious_junk():
    """Lines containing whitespace or URL chars shouldn't survive parsing."""
    out = _parse_subfinder_stdout(
        "a.example.com\n"
        "https://b.example.com/path\n"
        "c.example.com\n"
        "two words.example.com\n"
    )
    assert out == ("a.example.com", "c.example.com")
