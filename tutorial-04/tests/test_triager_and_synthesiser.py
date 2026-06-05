"""Schema + render tests for triager and synthesiser.

We don't call Claude in unit tests — the full mock pipeline is exercised
in test_cli.py via the CLI's --mock mode (which uses the same fixture
shapes a real call would return).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from tutorial_04.semgrep_runner import SemgrepFinding
from tutorial_04.synthesiser import FindingHeadline, SynthesisedReport
from tutorial_04.triager import TriagedFinding, TriageVerdict


def _make_finding():
    return SemgrepFinding(
        rule_id="tutorial-04/sqli",
        file_path="src/main/java/com/Foo.java",
        start_line=10, end_line=10,
        matched_code="statement.executeQuery(\"...\" + x)",
        message="m",
        severity="ERROR",
    )


def test_verdict_accepts_each_rank():
    for rank in ("high", "medium", "low", "false-positive"):
        v = TriageVerdict(
            exploitability=rank,
            rationale="r",
            exploitation_guidance="g" if rank in ("high", "medium") else None,
        )
        assert v.exploitability == rank


def test_verdict_rejects_unknown_rank():
    with pytest.raises(ValidationError):
        TriageVerdict(exploitability="extreme", rationale="r")


def test_triaged_finding_pairs_match_with_verdict():
    f = _make_finding()
    v = TriageVerdict(
        exploitability="high",
        rationale="user input flows to executeQuery",
        exploitation_guidance="send `'OR 1=1`",
    )
    t = TriagedFinding(finding=f, verdict=v, code_context="...")
    assert t.finding.file_path == "src/main/java/com/Foo.java"
    assert t.verdict.exploitability == "high"


def test_synthesised_report_round_trip():
    r = SynthesisedReport(
        headline="Critical — two confirmed SQLi sinks.",
        executive_summary="Two confirmed; one false-positive.",
        confirmed_high=[
            FindingHeadline(
                file_path="src/.../Foo.java", line=10,
                exploitability="high",
                headline="SQLi via executeQuery on `account`",
            ),
        ],
    )
    again = SynthesisedReport.model_validate(r.model_dump())
    assert again.headline == r.headline
    assert len(again.confirmed_high) == 1
    assert again.confirmed_high[0].headline.startswith("SQLi via")


def test_finding_headline_required_fields():
    with pytest.raises(ValidationError):
        FindingHeadline(headline="x", exploitability="high")  # missing file_path + line


def test_synthesised_report_optional_lists_default_empty():
    r = SynthesisedReport(headline="Informational — no findings.", executive_summary="None.")
    assert r.confirmed_high == []
    assert r.confirmed_medium == []
    assert r.low_and_false_positives == []
