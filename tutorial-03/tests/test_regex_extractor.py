"""Regex extractor tests — pure-function HTML parsing.

The regex extractor is the deterministic baseline that Claude's
inference layer adds value on top of. Tests cover both sources:
``<a href>`` attributes and URLs embedded in page text.
"""
from __future__ import annotations

from tutorial_03.regex_extractor import (
    ExtractedCandidate,
    extract_subdomain_candidates,
)


# ─── Basic extraction ───────────────────────────────────────────────────────

def test_extract_from_simple_anchor_href():
    html = '<a href="https://docs.example.com">docs</a>'
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert len(out) == 1
    assert out[0].host == "docs.example.com"
    assert out[0].source_type == "link"


def test_extract_finds_multiple_distinct_links():
    html = """
    <a href="https://docs.example.com">docs</a>
    <a href="https://api.example.com">api</a>
    <a href="https://status.example.com">status</a>
    """
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    hosts = {c.host for c in out}
    assert hosts == {"docs.example.com", "api.example.com", "status.example.com"}


def test_extract_dedupes_repeated_links():
    html = """
    <a href="https://docs.example.com/intro">intro</a>
    <a href="https://docs.example.com/auth">auth</a>
    """
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert len(out) == 1
    assert out[0].host == "docs.example.com"


# ─── In-root filter ─────────────────────────────────────────────────────────

def test_extract_filters_to_root_domain():
    """Only hosts ending in the root domain are kept."""
    html = """
    <a href="https://docs.example.com">in-root</a>
    <a href="https://partner-company.com">out-of-root</a>
    <a href="https://www.unrelated.org/path">out-of-root</a>
    """
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    hosts = {c.host for c in out}
    assert hosts == {"docs.example.com"}


def test_extract_ignores_relative_paths():
    """Relative paths like /careers don't reveal subdomain names."""
    html = """
    <a href="/careers">Careers</a>
    <a href="/support">Support</a>
    <a href="https://docs.example.com">Docs</a>
    """
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert len(out) == 1
    assert out[0].host == "docs.example.com"


def test_extract_ignores_mailto_and_anchors():
    html = """
    <a href="mailto:hello@example.com">email</a>
    <a href="#section">jump</a>
    <a href="javascript:void(0)">noop</a>
    """
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert out == []


# ─── Text-embedded URLs ─────────────────────────────────────────────────────

def test_extract_from_text_embedded_url():
    """A URL in plain text (not in <a href>) should still be found."""
    html = "<p>Read more at https://blog.example.com about it.</p>"
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert len(out) == 1
    assert out[0].host == "blog.example.com"
    assert out[0].source_type == "text"


def test_extract_prefers_link_source_when_url_appears_in_both():
    """If the same host appears in both <a href> and text, the <a href>
    extraction wins (it's the stronger signal)."""
    html = """
    <a href="https://docs.example.com">Docs</a>
    <p>You can also reach https://docs.example.com via the menu.</p>
    """
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert len(out) == 1
    assert out[0].source_type == "link"


# ─── Edge cases ─────────────────────────────────────────────────────────────

def test_extract_handles_empty_html():
    assert extract_subdomain_candidates(html="", root_domain="example.com") == []


def test_extract_handles_html_with_no_urls():
    html = "<p>Just plain text, no links.</p>"
    assert extract_subdomain_candidates(html=html, root_domain="example.com") == []


def test_extract_case_insensitive_matching():
    """DNS is case-insensitive — extracted hosts come out lower-cased."""
    html = '<a href="https://Docs.Example.COM">Docs</a>'
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert len(out) == 1
    assert out[0].host == "docs.example.com"


def test_extract_handles_http_and_https():
    html = """
    <a href="http://blog.example.com">HTTP link</a>
    <a href="https://docs.example.com">HTTPS link</a>
    """
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    hosts = {c.host for c in out}
    assert hosts == {"blog.example.com", "docs.example.com"}


def test_extract_strips_trailing_dot():
    """A host like `docs.example.com.` should normalise to `docs.example.com`."""
    html = '<a href="https://docs.example.com./">docs</a>'
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert len(out) == 1
    assert out[0].host == "docs.example.com"


def test_extract_keeps_bare_root_when_linked():
    """A link to the root domain itself is a valid extraction."""
    html = '<a href="https://example.com/about">About</a>'
    out = extract_subdomain_candidates(html=html, root_domain="example.com")
    assert len(out) == 1
    assert out[0].host == "example.com"
