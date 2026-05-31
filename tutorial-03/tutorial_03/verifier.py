"""Light HTTP verification for resolved candidates.

One ``GET https://<host>/`` per resolved host with a short timeout
captures: status code, page title, server header. That's enough signal
to triage live-web vs. parked/DNS-only and to feed the ranker with
something better than a bare hostname.

Concurrent via a thread pool, same shape as the resolver.

This step is OPTIONAL — the CLI's ``--no-verify`` flag skips it
entirely for true zero-touch passive runs. When enabled, it should be
covered by the engagement's authorisation (a single GET to the apex of
a discovered host is the kind of thing most bug-bounty programs treat
as in-scope reconnaissance, but always re-verify per program).
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests


DEFAULT_TIMEOUT_SEC = 6
DEFAULT_MAX_WORKERS = 12
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; AIForCybersecurityFundamentalsT3/1.0)"
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
MAX_TITLE_CHARS = 160
RESPONSE_READ_LIMIT = 64 * 1024   # 64 KiB is plenty to find <title>


@dataclass(frozen=True)
class HostProbe:
    """One HTTP probe outcome."""

    host: str
    scheme: str           # "https" or "http"
    url: str              # final URL after redirects (or attempted URL on error)
    status_code: int | None
    title: str | None
    server: str | None
    live: bool            # True iff we got any HTTP response (any status code)
    error: str | None     # short error string when live=False


def verify_many(
    hosts: list[str],
    *,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    max_workers: int = DEFAULT_MAX_WORKERS,
    user_agent: str = DEFAULT_USER_AGENT,
) -> list[HostProbe]:
    """Probe every host with a single HTTPS GET; HTTP fallback on connect failure.

    Output ordering matches input ordering (see :py:func:`resolve_many`
    for the same idiom).
    """
    results: list[HostProbe | None] = [None] * len(hosts)
    if not hosts:
        return []

    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})

    try:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as pool:
            future_to_index = {
                pool.submit(_probe_one, host, session, timeout_sec): i
                for i, host in enumerate(hosts)
            }
            for fut in as_completed(future_to_index):
                idx = future_to_index[fut]
                results[idx] = fut.result()
    finally:
        session.close()

    return [r for r in results if r is not None]


def _probe_one(host: str, session: requests.Session, timeout_sec: float) -> HostProbe:
    """Probe one host. HTTPS first; HTTP fallback only on connection failure."""
    h = host.strip().lower().rstrip(".")
    https_url = f"https://{h}/"
    http_url = f"http://{h}/"
    last_exc: Exception | None = None
    for url, scheme in ((https_url, "https"), (http_url, "http")):
        try:
            r = session.get(url, timeout=timeout_sec, allow_redirects=True)
            body_chunk = r.text[:RESPONSE_READ_LIMIT] if r.text else ""
            return HostProbe(
                host=h,
                scheme=scheme,
                url=r.url,
                status_code=r.status_code,
                title=_extract_title(body_chunk),
                server=r.headers.get("Server"),
                live=True,
                error=None,
            )
        except requests.RequestException as exc:
            last_exc = exc
            # Try HTTP if HTTPS failed at the connection layer; if HTTP also
            # fails we drop out of the loop with last_exc set.

    return HostProbe(
        host=h,
        scheme="https",
        url=https_url,
        status_code=None,
        title=None,
        server=None,
        live=False,
        error=str(last_exc) if last_exc else "no response",
    )


def _extract_title(html: str) -> str | None:
    """Pull <title>...</title> out of an HTML chunk; truncate to 160 chars."""
    if not html:
        return None
    m = TITLE_RE.search(html)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    if not title:
        return None
    if len(title) > MAX_TITLE_CHARS:
        title = title[:MAX_TITLE_CHARS - 1] + "…"
    return title


__all__ = [
    "DEFAULT_MAX_WORKERS",
    "DEFAULT_TIMEOUT_SEC",
    "DEFAULT_USER_AGENT",
    "HostProbe",
    "verify_many",
]
