"""Thin subprocess wrapper around ProjectDiscovery's ``subfinder``.

We invoke subfinder in passive-only mode (``-silent``; no active brute
force; no DNS queries to the target's own infrastructure) and capture
its stdout — one subdomain per line. Failure modes are surfaced as
typed exceptions rather than raw ``CalledProcessError`` so the CLI can
emit clean error messages.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass


class SubfinderMissingError(RuntimeError):
    """subfinder is not on PATH."""

    def __init__(self) -> None:
        super().__init__(
            "subfinder is not installed or not on PATH. Install via:\n"
            "  Ubuntu/Debian:  go install github.com/projectdiscovery/"
            "subfinder/v2/cmd/subfinder@latest\n"
            "  Or download a prebuilt binary from\n"
            "    https://github.com/projectdiscovery/subfinder/releases\n"
            "Verify with: subfinder -version"
        )


@dataclass(frozen=True)
class SubfinderResult:
    """Captured subfinder output for one domain run."""

    domain: str
    subdomains: tuple[str, ...]   # deduplicated + lower-cased
    returncode: int
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_subfinder(
    *,
    domain: str,
    timeout_sec: int = 180,
    extra_args: list[str] | None = None,
) -> SubfinderResult:
    """Run ``subfinder -d <domain> -silent`` and capture the output.

    ``-silent`` makes subfinder print only the subdomain list on stdout
    (no banner, no source-by-source progress noise) — exactly what we
    want to feed into the next pipeline stage. ``-passive`` is the
    default execution mode in modern subfinder; we don't pass it
    explicitly to avoid binding to a specific subfinder version's flag
    semantics, but the sources it queries (crt.sh, AlienVault OTX,
    VirusTotal, Anubis, etc.) are all passive by construction — they
    never resolve or scan the target.

    Returns a :py:class:`SubfinderResult`. Non-zero exit codes are
    surfaced via the result (not raised) so the pipeline can keep going
    with whatever partial output landed.
    """
    cmd = ["subfinder", "-d", domain, "-silent"]
    if extra_args:
        cmd.extend(extra_args)

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise SubfinderMissingError() from exc
    except subprocess.TimeoutExpired:
        return SubfinderResult(
            domain=domain,
            subdomains=(),
            returncode=124,
            stderr=f"subfinder timed out after {timeout_sec}s",
        )

    subs = _parse_subfinder_stdout(completed.stdout)
    return SubfinderResult(
        domain=domain,
        subdomains=subs,
        returncode=completed.returncode,
        stderr=completed.stderr or "",
    )


def _parse_subfinder_stdout(stdout: str) -> tuple[str, ...]:
    """Turn subfinder's -silent stdout into a deduped, lower-cased tuple.

    Subfinder occasionally emits a stray colour escape or blank line
    even with ``-silent``; strip whitespace + skip empties + lowercase
    + dedupe (preserving first-occurrence order).
    """
    seen: dict[str, None] = {}
    for raw in stdout.splitlines():
        host = raw.strip().lower().rstrip(".")
        if not host:
            continue
        # Drop anything that isn't plausibly a hostname (subfinder rarely
        # leaks junk, but a stray ANSI escape sequence would survive a
        # raw .strip()).
        if any(c in host for c in (" ", "\t", "/", "?", "(", ")")):
            continue
        seen.setdefault(host, None)
    return tuple(seen.keys())


__all__ = [
    "SubfinderMissingError",
    "SubfinderResult",
    "run_subfinder",
]
