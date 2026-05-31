"""Generator schema + root-filter tests. No live Claude calls."""
from __future__ import annotations

from tutorial_03.generator import (
    CandidateList,
    CandidateSubdomain,
    filter_to_root,
)


def test_candidate_schema_accepts_minimal_input():
    c = CandidateSubdomain(host="careers.example.com", rationale="Careers link.")
    assert c.host == "careers.example.com"


def test_candidate_list_schema_default_empty():
    cl = CandidateList()
    assert cl.candidates == []


def test_filter_to_root_keeps_matching_hosts():
    cands = [
        CandidateSubdomain(host="api.example.com", rationale="x"),
        CandidateSubdomain(host="careers.example.com", rationale="x"),
    ]
    out = filter_to_root(cands, "example.com")
    assert {c.host for c in out} == {"api.example.com", "careers.example.com"}


def test_filter_to_root_drops_invented_hosts():
    cands = [
        CandidateSubdomain(host="api.example.com", rationale="x"),
        CandidateSubdomain(host="other-company.com", rationale="x"),
        CandidateSubdomain(host="careers.example.org", rationale="x"),
    ]
    out = filter_to_root(cands, "example.com")
    assert {c.host for c in out} == {"api.example.com"}


def test_filter_to_root_case_insensitive():
    cands = [CandidateSubdomain(host="API.Example.COM", rationale="x")]
    out = filter_to_root(cands, "example.com")
    assert len(out) == 1


def test_filter_to_root_handles_trailing_dot():
    cands = [CandidateSubdomain(host="api.example.com.", rationale="x")]
    out = filter_to_root(cands, "example.com")
    assert len(out) == 1


def test_filter_to_root_accepts_bare_root():
    cands = [CandidateSubdomain(host="example.com", rationale="x")]
    out = filter_to_root(cands, "example.com")
    assert len(out) == 1
