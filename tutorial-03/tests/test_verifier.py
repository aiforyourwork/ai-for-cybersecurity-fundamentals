"""Verifier tests — pure-function focus on title extraction."""
from __future__ import annotations

from tutorial_03.verifier import _extract_title


def test_extracts_simple_title():
    assert _extract_title("<html><head><title>Hello world</title></head></html>") == "Hello world"


def test_collapses_inner_whitespace():
    html = "<title>  Spaces\nand\tnewlines  </title>"
    assert _extract_title(html) == "Spaces and newlines"


def test_returns_none_when_no_title_tag():
    assert _extract_title("<html><body>No title</body></html>") is None


def test_returns_none_for_empty_title():
    assert _extract_title("<title></title>") is None
    assert _extract_title("<title>   </title>") is None


def test_truncates_long_titles():
    long = "x" * 500
    out = _extract_title(f"<title>{long}</title>")
    assert out is not None
    assert len(out) <= 160


def test_handles_title_with_attributes():
    """Some servers emit `<title lang="en">`; the regex should still match."""
    assert _extract_title('<title lang="en">Localised page</title>') == "Localised page"
