"""Scope file parser + host matcher tests.

This is the safety hinge — anything that gets past `Scope.matches`
reaches the network. Test it harder than anything else."""
from __future__ import annotations

import pytest

from tutorial_03.scope import Scope, ScopeError, parse_scope_file


# ─── Pattern matching ───────────────────────────────────────────────────────

def test_wildcard_matches_one_label():
    s = Scope(patterns=("*.example.com",))
    assert s.matches("api.example.com")
    assert s.matches("careers.example.com")


def test_wildcard_matches_multiple_labels():
    """fnmatch's `*` happily eats dots — *.example.com matches a.b.example.com."""
    s = Scope(patterns=("*.example.com",))
    assert s.matches("foo.bar.example.com")


def test_wildcard_does_not_match_bare_domain():
    s = Scope(patterns=("*.example.com",))
    assert not s.matches("example.com")


def test_match_is_case_insensitive():
    s = Scope(patterns=("*.example.com",))
    assert s.matches("Api.Example.COM")
    assert s.matches("CAREERS.EXAMPLE.COM")


def test_match_strips_trailing_dot():
    """DNS allows trailing dots; matching shouldn't care."""
    s = Scope(patterns=("*.example.com",))
    assert s.matches("api.example.com.")


def test_match_does_not_cross_root():
    s = Scope(patterns=("*.example.com",))
    assert not s.matches("api.evil.com")
    assert not s.matches("example.com.evil.com")


def test_exact_pattern_only_matches_that_host():
    s = Scope(patterns=("only.example.com",))
    assert s.matches("only.example.com")
    assert not s.matches("admin.only.example.com")
    assert not s.matches("example.com")


def test_multiple_patterns_any_match():
    s = Scope(patterns=("*.alpha.com", "*.beta.com"))
    assert s.matches("a.alpha.com")
    assert s.matches("b.beta.com")
    assert not s.matches("c.gamma.com")


def test_filter_partitions_in_and_out_of_scope():
    s = Scope(patterns=("*.example.com",))
    in_scope, out = s.filter(["a.example.com", "evil.com", "b.example.com"])
    assert in_scope == ["a.example.com", "b.example.com"]
    assert out == ["evil.com"]


# ─── permits_root ───────────────────────────────────────────────────────────

def test_permits_root_when_wildcard_pattern_implies_it():
    """`*.example.com` implicitly authorises example.com itself — fetching
    the root's homepage is part of any subdomain-enum workflow."""
    s = Scope(patterns=("*.example.com",))
    assert s.permits_root("example.com")


def test_permits_root_when_pattern_matches_directly():
    s = Scope(patterns=("example.com",))
    assert s.permits_root("example.com")


def test_permits_root_rejects_unrelated_domain():
    s = Scope(patterns=("*.example.com",))
    assert not s.permits_root("evil.com")


def test_permits_root_case_insensitive():
    s = Scope(patterns=("*.example.com",))
    assert s.permits_root("EXAMPLE.com")


# ─── Scope file parsing ─────────────────────────────────────────────────────

def test_parse_scope_file_basic(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("*.example.com\n*.dev.example.com\n", encoding="utf-8")
    s = parse_scope_file(p)
    assert s.patterns == ("*.example.com", "*.dev.example.com")


def test_parse_scope_file_strips_comments_and_blanks(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text(
        "# header comment\n"
        "\n"
        "*.example.com\n"
        "   # indented comment is also a comment\n"
        "*.evil.test\n",
        encoding="utf-8",
    )
    s = parse_scope_file(p)
    assert s.patterns == ("*.example.com", "*.evil.test")


def test_parse_scope_file_lowercases(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("*.Example.COM\n", encoding="utf-8")
    s = parse_scope_file(p)
    assert s.patterns == ("*.example.com",)


def test_parse_scope_file_missing_raises(tmp_path):
    p = tmp_path / "no-such-file.txt"
    with pytest.raises(ScopeError, match="not found"):
        parse_scope_file(p)


def test_parse_scope_file_empty_raises(tmp_path):
    p = tmp_path / "empty.txt"
    p.write_text("# only comments\n\n# nothing else\n", encoding="utf-8")
    with pytest.raises(ScopeError, match="no patterns"):
        parse_scope_file(p)


def test_parse_scope_file_refuses_match_everything(tmp_path):
    p = tmp_path / "evil.txt"
    p.write_text("*\n", encoding="utf-8")
    with pytest.raises(ScopeError, match="would match every host"):
        parse_scope_file(p)
