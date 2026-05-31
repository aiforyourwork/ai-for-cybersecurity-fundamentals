"""Scope file parser + host matcher — the safety hinge of this tool.

A scope file lists the wildcard patterns the engagement authorises.
Every host the pipeline touches (DNS, HTTP) is checked against this
list FIRST; anything not matching is hard-filtered before any network
call. ``--scope <path>`` is a mandatory CLI argument — the CLI refuses
to run without one — so there is no "default scope = everything" mode.

Pattern grammar
---------------

One pattern per line. ``#`` and blank lines ignored. Patterns are the
shell-glob form supported by Python's ``fnmatch`` module, restricted
to the cases that make sense for DNS labels:

  ``*.example.com``          any subdomain of example.com (one or more labels)
  ``*.dev.example.com``      any subdomain of dev.example.com
  ``exact.example.com``      only the exact host
  ``example.com``            only the bare domain (no www., no sub.)

Patterns are case-folded before matching — DNS is case-insensitive,
and accepting ``Foo.Example.COM`` from subfinder while rejecting it
from Claude would be a footgun.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path


class ScopeError(ValueError):
    """Raised when the scope file is missing, empty, or malformed."""


@dataclass(frozen=True)
class Scope:
    """A parsed set of wildcard patterns. Use :py:meth:`matches` per host."""

    patterns: tuple[str, ...]

    def matches(self, host: str) -> bool:
        """Return True iff ``host`` matches at least one pattern in scope.

        Case-insensitive. A host with a trailing dot (``foo.example.com.``)
        is treated identically to one without — DNS allows both shapes.
        """
        h = host.lower().rstrip(".")
        return any(fnmatch.fnmatchcase(h, p) for p in self.patterns)

    def filter(self, hosts: list[str]) -> tuple[list[str], list[str]]:
        """Partition ``hosts`` into (in_scope, out_of_scope) lists.

        Order is preserved in each output list, deduplication is NOT
        performed — callers may want to keep duplicates (different sources)
        and dedupe themselves with a stable ordering choice.
        """
        in_scope: list[str] = []
        out_of_scope: list[str] = []
        for h in hosts:
            (in_scope if self.matches(h) else out_of_scope).append(h)
        return in_scope, out_of_scope

    def permits_root(self, domain: str) -> bool:
        """Return True iff the scope authorises touching ``domain`` itself.

        A domain is "permitted as a root" when EITHER it matches a pattern
        directly, OR some pattern is the wildcard ``*.{domain}`` (which
        implies authorisation for the root the user wants to enumerate
        under). This is more permissive than :py:meth:`matches`, and is
        the right check to use when deciding whether the CLI can fetch
        the root's own homepage in addition to subdomains.
        """
        d = domain.lower().rstrip(".")
        if self.matches(d):
            return True
        wildcard_form = f"*.{d}"
        return wildcard_form in self.patterns


def parse_scope_file(path: Path) -> Scope:
    """Load a scope file from disk.

    Raises ``ScopeError`` for missing files, empty files, or lines that
    look broken (a pattern containing only ``*`` would let every host in
    — clearly not what the user meant).
    """
    if not path.exists():
        raise ScopeError(f"Scope file not found: {path}")
    if not path.is_file():
        raise ScopeError(f"Scope path is not a file: {path}")

    raw_lines = path.read_text(encoding="utf-8").splitlines()
    patterns: list[str] = []
    for lineno, raw in enumerate(raw_lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "*" or line == "**":
            raise ScopeError(
                f"Scope file {path} line {lineno}: pattern '{line}' would "
                f"match every host. Refuse-to-load — this is almost certainly "
                f"a mistake."
            )
        if line.lower() != line:
            # Case-fold once at parse time. DNS is case-insensitive; carrying
            # the user's casing forward would only enable mistakes.
            line = line.lower()
        patterns.append(line)

    if not patterns:
        raise ScopeError(
            f"Scope file {path} contains no patterns (after stripping "
            f"comments + blanks). At least one wildcard pattern is required."
        )
    return Scope(patterns=tuple(patterns))


__all__ = ["Scope", "ScopeError", "parse_scope_file"]
