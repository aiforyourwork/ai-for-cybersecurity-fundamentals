"""Extract subdomain candidates from HTML content via deterministic parsing.

This is the EXTRACTION layer of the candidate-generation stage. It finds
subdomains the homepage *explicitly references* — fully-qualified URLs in
``<a href>`` attributes or embedded in the page text. It does no inference.

Why it exists: a real homepage usually links to its customer-facing
subdomains (``docs.``, ``status.``, ``support.``, ``api.``, etc.). Without
this stage the Claude generator would be doing extraction work a regex
does for free, and the AI's contribution would be muddled by "candidates
the model definitely could have read off the page" mixed in with the
inferred ones.

With this stage we make Claude's value-add visible: the AI's job is
*inference of what isn't linked* (internal infra, non-prod environments,
engineering surfaces) on top of the regex's *extraction of what is*.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from bs4 import BeautifulSoup


# Matches a host portion of an http(s) URL — letters/digits/hyphen labels
# separated by dots. Loose on purpose; the caller filters to in-root hosts.
URL_HOST_RE = re.compile(
    r"\bhttps?://([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExtractedCandidate:
    """One subdomain candidate found in HTML content via extraction."""

    host: str
    source_type: str  # "link" — from <a href>; "text" — from prose URL


def extract_subdomain_candidates(
    *,
    html: str,
    root_domain: str,
) -> list[ExtractedCandidate]:
    """Extract subdomain candidates from an HTML document.

    Pure-function extraction — no inference, no network, no LLM call. Returns
    the deduplicated list of hosts whose suffix matches ``root_domain``.

    Sources scanned:
        - ``<a href="https://...">`` attributes via BeautifulSoup
        - URLs embedded in the page's visible text (``"...visit
          https://api.example.com/..."``)

    Relative paths (``/careers``) are NOT counted — they don't expose a
    subdomain name. Same-origin marketing pages live behind paths, not
    subdomains, so a regex-only baseline finds nothing about them.
    """
    if not html:
        return []

    root = root_domain.lower().rstrip(".")
    seen: dict[str, ExtractedCandidate] = {}

    soup = BeautifulSoup(html, "html.parser")

    # 1) <a href="..."> attributes — strongest signal.
    for a in soup.find_all("a", href=True):
        host = _host_from_url(a["href"])
        if host and _in_root(host, root) and host not in seen:
            seen[host] = ExtractedCandidate(host=host, source_type="link")

    # 2) URLs anywhere in text content. BeautifulSoup's get_text strips
    #    markup; we then regex over the resulting prose for URL-shaped
    #    strings. This catches things like inline "see docs at
    #    https://docs.example.com" mentions that aren't wrapped in <a>.
    text = soup.get_text(separator=" ", strip=True)
    for m in URL_HOST_RE.finditer(text):
        host = m.group(1).lower().rstrip(".")
        if _in_root(host, root) and host not in seen:
            seen[host] = ExtractedCandidate(host=host, source_type="text")

    return list(seen.values())


def _host_from_url(url: str) -> str | None:
    """Pull the host portion out of an ``http(s)://...`` URL, lower-cased.

    Returns None for relative paths (``/careers``), mailto links, anchor
    fragments — anything that doesn't resolve to a hostname.
    """
    m = URL_HOST_RE.search(url or "")
    if not m:
        return None
    return m.group(1).lower().rstrip(".")


def _in_root(host: str, root: str) -> bool:
    """Return True iff ``host`` ends with ``root`` (or IS ``root``)."""
    h = host.lower().rstrip(".")
    return h == root or h.endswith("." + root)


__all__ = [
    "ExtractedCandidate",
    "URL_HOST_RE",
    "extract_subdomain_candidates",
]
