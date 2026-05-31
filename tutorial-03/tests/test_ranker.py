"""Ranker schema + priority-sort tests. No live Claude calls."""
from __future__ import annotations

from tutorial_03.ranker import (
    PRIORITY_ORDER,
    RankedHost,
    RankingReport,
    _format_host_table,
    sort_by_priority,
)


def test_ranked_host_schema_accepts_minimal_input():
    h = RankedHost(host="api.example.com", priority="high", value="Swagger UI exposed.")
    assert h.priority == "high"


def test_ranking_report_default_empty_hosts():
    r = RankingReport(headline="None found.")
    assert r.hosts == []


def test_priority_order_constants_are_total():
    assert PRIORITY_ORDER == {"high": 0, "medium": 1, "low": 2}


def test_sort_by_priority_high_first_then_medium_then_low():
    inp = [
        RankedHost(host="a", priority="low", value="x"),
        RankedHost(host="b", priority="high", value="x"),
        RankedHost(host="c", priority="medium", value="x"),
        RankedHost(host="d", priority="high", value="x"),
    ]
    out = sort_by_priority(inp)
    assert [h.host for h in out] == ["b", "d", "c", "a"]


def test_format_host_table_handles_missing_fields():
    table = _format_host_table([
        {"host": "a.example.com", "status_code": 200, "title": "Home", "server": "nginx"},
        {"host": "b.example.com", "status_code": None, "title": None, "server": None},
    ])
    assert "a.example.com" in table
    assert "200" in table
    assert "nginx" in table
    assert "(no title)" in table
    assert "(no server hdr)" in table


def test_format_host_table_renders_one_line_per_host():
    table = _format_host_table([
        {"host": "a", "status_code": 200, "title": "x", "server": "y"},
        {"host": "b", "status_code": 200, "title": "x", "server": "y"},
        {"host": "c", "status_code": 200, "title": "x", "server": "y"},
    ])
    assert table.count("\n") == 2  # 3 lines, 2 newlines
