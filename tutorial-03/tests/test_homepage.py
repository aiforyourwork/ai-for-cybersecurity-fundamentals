"""Homepage extraction tests — pure-function focus."""
from __future__ import annotations

from tutorial_03.homepage import extract_main_text


def test_extracts_title_and_body_text():
    html = """
    <html>
      <head><title>Demo Co — pay your bills</title></head>
      <body>
        <h1>Welcome to Demo Co</h1>
        <p>We help solo founders manage cashflow.</p>
      </body>
    </html>
    """
    title, text = extract_main_text(html)
    assert title == "Demo Co — pay your bills"
    assert "Welcome to Demo Co" in text
    assert "manage cashflow" in text


def test_drops_script_style_noscript_blocks():
    html = """
    <html>
      <body>
        <script>function() { var x = 1; }</script>
        <style>.x { color: red; }</style>
        <noscript>JS off message</noscript>
        <p>Visible paragraph.</p>
      </body>
    </html>
    """
    _title, text = extract_main_text(html)
    assert "Visible paragraph" in text
    assert "function" not in text
    assert "color: red" not in text
    assert "JS off message" not in text


def test_handles_empty_html():
    title, text = extract_main_text("")
    assert title is None
    assert text == ""


def test_handles_html_without_title():
    title, text = extract_main_text("<html><body><p>Hi</p></body></html>")
    assert title is None
    assert "Hi" in text


def test_truncates_long_body_at_word_boundary():
    html = "<html><body>" + ("apples bananas cherries " * 1000) + "</body></html>"
    _title, text = extract_main_text(html, max_chars=200)
    assert len(text) <= 200
    # The truncation should land on a space boundary, not mid-word.
    assert not text.endswith("apple")
    assert not text.endswith("banan")
    assert not text.endswith("cherri")


def test_collapses_paragraph_whitespace():
    html = """
    <html><body>
      <p>Line one.</p>


      <p>Line two.</p>
    </body></html>
    """
    _title, text = extract_main_text(html)
    # No triple-newlines after collapse.
    assert "\n\n\n" not in text
    assert "Line one" in text and "Line two" in text
