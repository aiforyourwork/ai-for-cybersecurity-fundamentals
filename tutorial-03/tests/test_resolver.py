"""Resolver tests — uses a host that definitely fails to resolve.

The happy-path test deliberately uses a real DNS lookup against
``localhost`` because mocking ``socket.getaddrinfo`` cleanly isn't
worth the maintenance burden. Tests should run in <1 sec total."""
from __future__ import annotations

from tutorial_03.resolver import resolve_many


def test_resolver_returns_empty_for_empty_input():
    assert resolve_many([]) == []


def test_resolver_resolves_localhost():
    out = resolve_many(["localhost"])
    assert len(out) == 1
    assert out[0].resolved
    assert out[0].addresses  # at least one address


def test_resolver_fails_cleanly_on_garbage_host():
    """A host with no possibility of resolution should produce a clear
    ResolvedHost(resolved=False) without raising."""
    out = resolve_many(["this-host-will-never-exist-x9y8z7.invalid"])
    assert len(out) == 1
    assert not out[0].resolved
    assert out[0].error  # some error string


def test_resolver_preserves_input_order():
    """resolve_many is parallel; output should still be in input order."""
    inputs = ["localhost", "definitely-not-real-x9y.invalid", "localhost"]
    out = resolve_many(inputs)
    assert len(out) == 3
    assert out[0].resolved is True
    assert out[1].resolved is False
    assert out[2].resolved is True
