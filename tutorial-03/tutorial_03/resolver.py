"""DNS resolution for candidate subdomains.

Resolution is the funnel's first deterministic check: a name that
doesn't resolve to an A/AAAA record can't host a web service, so it
falls out of the candidate set here before we consider any HTTP work.

Uses ``socket.getaddrinfo`` in a thread pool — stdlib-only, no
``dnspython`` dependency. For a list of ~100 candidates with a 3-sec
per-host timeout, a 16-thread pool finishes in under 15 sec wall time.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


DEFAULT_TIMEOUT_SEC = 3
DEFAULT_MAX_WORKERS = 16


@dataclass(frozen=True)
class ResolvedHost:
    """One resolution attempt's outcome."""

    host: str
    resolved: bool
    addresses: tuple[str, ...]   # empty when resolved=False
    error: str | None            # short error string when resolved=False


def resolve_many(
    hosts: list[str],
    *,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> list[ResolvedHost]:
    """Resolve every host in parallel; return one ResolvedHost per input.

    Order in the output matches order in the input — useful when the
    caller needs to align resolution results with their source list.
    Deduplication is the caller's responsibility (we don't second-guess
    whether two identical hosts in the input are intentional).
    """
    # Pre-build the result slot list so we can write back by index and
    # preserve input ordering despite as_completed's race-y order.
    results: list[ResolvedHost | None] = [None] * len(hosts)

    if not hosts:
        return []

    old_default = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_sec)
    try:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as pool:
            future_to_index = {
                pool.submit(_resolve_one, host): i
                for i, host in enumerate(hosts)
            }
            for fut in as_completed(future_to_index):
                idx = future_to_index[fut]
                results[idx] = fut.result()
    finally:
        socket.setdefaulttimeout(old_default)

    # results is fully populated at this point — every future ran.
    return [r for r in results if r is not None]


def _resolve_one(host: str) -> ResolvedHost:
    """Resolve one host via getaddrinfo. Never raises."""
    h = host.strip().lower().rstrip(".")
    if not h:
        return ResolvedHost(host=host, resolved=False, addresses=(), error="empty host")
    try:
        infos = socket.getaddrinfo(
            h, None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        return ResolvedHost(host=h, resolved=False, addresses=(), error=str(exc))
    except (OSError, UnicodeError) as exc:
        return ResolvedHost(host=h, resolved=False, addresses=(), error=str(exc))

    addresses: list[str] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        # IPv4: (ip, port); IPv6: (ip, port, flow, scope). Take ip only.
        if sockaddr and sockaddr[0] and sockaddr[0] not in seen:
            seen.add(sockaddr[0])
            addresses.append(sockaddr[0])

    return ResolvedHost(
        host=h,
        resolved=bool(addresses),
        addresses=tuple(addresses),
        error=None if addresses else "no A/AAAA records",
    )


__all__ = [
    "DEFAULT_MAX_WORKERS",
    "DEFAULT_TIMEOUT_SEC",
    "ResolvedHost",
    "resolve_many",
]
