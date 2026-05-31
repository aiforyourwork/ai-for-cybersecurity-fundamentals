"""Fetch a target's homepage and extract clean text for the AI generator.

The generator prompt asks Claude to infer business context from the
homepage — that needs *prose*, not the raw HTML soup. So we:

1. Send one HTTP ``GET`` to ``https://<domain>/`` with a benign UA.
2. Parse with BeautifulSoup.
3. Strip ``<script>``, ``<style>``, ``<noscript>``, navigation chrome.
4. Collapse whitespace and truncate to ~6000 chars — Claude doesn't
   need the whole page, just enough to read the business signal.

The fetch is best-effort: if the site is down, returns CAPTCHA, or
returns a JS-only SPA shell, we surface the empty/short result and the
generator's prompt explicitly handles "couldn't extract enough context".
"""
from __future__ import annotations

from dataclasses import dataclass

import requests
from bs4 import BeautifulSoup


DEFAULT_TIMEOUT_SEC = 15
DEFAULT_MAX_CHARS = 6000
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; AIForCybersecurityFundamentalsT3/1.0)"
TAGS_TO_DROP = ("script", "style", "noscript", "iframe", "svg")


class HomepageFetchError(RuntimeError):
    """Wraps requests / parsing failures so the CLI can emit clean errors."""


@dataclass(frozen=True)
class Homepage:
    """One target's fetched homepage, post-cleaning."""

    url: str
    status_code: int
    title: str | None
    text: str         # cleaned, whitespace-collapsed, truncated to max_chars
    raw_html: str     # original HTML; consumed by the regex extractor

    @property
    def is_useful(self) -> bool:
        """True iff the cleaned text is long enough to feed the generator.

        The 200-char threshold is a heuristic — below that the page is
        almost certainly a redirect shell, a CAPTCHA, or a JS-only SPA
        with no server-rendered content. The generator's prompt handles
        the empty-context case, but we surface the signal here so the
        CLI can warn the user.
        """
        return self.text and len(self.text) >= 200


def fetch_homepage(
    domain: str,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_chars: int = DEFAULT_MAX_CHARS,
    user_agent: str = DEFAULT_USER_AGENT,
    session: requests.Session | None = None,
) -> Homepage:
    """Fetch ``https://<domain>/`` and return cleaned text.

    Tries HTTPS first; falls back to HTTP if the HTTPS request fails
    outright (some bug-bounty scopes' apex still redirects via HTTP).
    """
    sess = session or requests.Session()
    sess.headers.setdefault("User-Agent", user_agent)

    url_https = f"https://{domain}/"
    url_http = f"http://{domain}/"
    last_exc: Exception | None = None
    response: requests.Response | None = None

    for url in (url_https, url_http):
        try:
            response = sess.get(url, timeout=timeout_sec, allow_redirects=True)
            break
        except requests.RequestException as exc:
            last_exc = exc
            response = None

    if response is None:
        raise HomepageFetchError(
            f"Could not fetch homepage of {domain}: {last_exc}"
        )

    return _build_homepage(
        url=response.url,
        status_code=response.status_code,
        html=response.text,
        max_chars=max_chars,
    )


def _build_homepage(
    *,
    url: str,
    status_code: int,
    html: str,
    max_chars: int,
) -> Homepage:
    title, text = extract_main_text(html, max_chars=max_chars)
    return Homepage(
        url=url,
        status_code=status_code,
        title=title,
        text=text,
        raw_html=html or "",
    )


def extract_main_text(html: str, *, max_chars: int = DEFAULT_MAX_CHARS) -> tuple[str | None, str]:
    """Strip an HTML document to (title, clean prose body).

    Pure function — exposed so unit tests can hit it directly without
    spinning up an HTTP fixture server.
    """
    soup = BeautifulSoup(html or "", "html.parser")

    # Title — used as a quick signal in the report; sometimes the only
    # signal on a JS-only homepage.
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else None

    # Drop non-content tags entirely. The generator prompt should never
    # see "function() { ... }" javascript or CSS rules.
    for tag_name in TAGS_TO_DROP:
        for tag in soup.find_all(tag_name):
            tag.decompose()

    # Body text — paragraphs joined with single newline so Claude reads
    # them as separate ideas.
    body = soup.body if soup.body else soup
    text = body.get_text(separator="\n", strip=True) if body else ""

    # Collapse runs of whitespace and drop empties. Multiple blank lines
    # waste tokens; single newlines preserve paragraph structure.
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    text = "\n".join(lines)

    if len(text) > max_chars:
        text = text[:max_chars].rsplit(" ", 1)[0]   # cut at a word boundary

    return title, text


__all__ = [
    "DEFAULT_MAX_CHARS",
    "DEFAULT_TIMEOUT_SEC",
    "DEFAULT_USER_AGENT",
    "Homepage",
    "HomepageFetchError",
    "extract_main_text",
    "fetch_homepage",
]
