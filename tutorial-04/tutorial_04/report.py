"""Structured JSON report + compact terminal renderer.

The JSON written to ``--output`` is the canonical record — every field
the pipeline produces is preserved. The terminal renderer is the
30-second walk-the-room view: overall verdict + counts + the top
findings, designed to read as a single screen.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .rule_generator import GeneratedRule
from .synthesiser import SynthesisedReport
from .triager import TriagedFinding


@dataclass(frozen=True)
class FullReport:
    """The end-to-end artefact carrying every field from the pipeline.

    What lands in ``report.json`` is ``FullReport.to_json_dict()``.
    The structure is intentionally a flat dict at the top level so
    downstream consumers (defensive triage tutorials, future report
    aggregators) don't need to plumb nested model classes.
    """

    target: str                          # human-readable scan target description
    concern: str                         # the original NL concern
    rule: GeneratedRule                  # Claude's generated semgrep rule
    triaged: list[TriagedFinding]        # every per-finding triage verdict
    synthesis: SynthesisedReport         # the reduce-phase consolidated report

    def to_json_dict(self) -> dict:
        return {
            "target": self.target,
            "concern": self.concern,
            "generated_rule_id": self.rule.rule_id,
            "generated_rule_yaml": self.rule.yaml_body,
            "rule_rationale": self.rule.rationale,
            "counts": self.counts(),
            "headline": self.synthesis.headline,
            "executive_summary": self.synthesis.executive_summary,
            "findings": [
                {
                    "file": t.finding.file_path,
                    "line": t.finding.start_line,
                    "rule_id": t.finding.rule_id,
                    "semgrep_severity": t.finding.severity,
                    "matched_code": t.finding.matched_code,
                    "exploitability": t.verdict.exploitability,
                    "rationale": t.verdict.rationale,
                    "exploitation_guidance": t.verdict.exploitation_guidance,
                }
                for t in self.triaged
            ],
            "confirmed_high": [h.model_dump() for h in self.synthesis.confirmed_high],
            "confirmed_medium": [h.model_dump() for h in self.synthesis.confirmed_medium],
            "low_and_false_positives": [
                h.model_dump() for h in self.synthesis.low_and_false_positives
            ],
        }

    def counts(self) -> dict[str, int]:
        c = {"high": 0, "medium": 0, "low": 0, "false-positive": 0, "raw": len(self.triaged)}
        for t in self.triaged:
            c[t.verdict.exploitability] = c.get(t.verdict.exploitability, 0) + 1
        return c


def save_report(report: FullReport, path: Path) -> None:
    """Persist the full report as pretty-printed JSON."""
    path.write_text(
        json.dumps(report.to_json_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def render_for_terminal(report: FullReport) -> str:
    """30-second walk-the-room view of the report."""
    c = report.counts()
    lines = [
        f"Scanned     : {report.target}",
        f"Concern     : {report.concern}",
        f"Rule        : {report.rule.rule_id}",
        "",
        f"Raw findings: {c['raw']}",
        f"  → high             : {c['high']}",
        f"  → medium           : {c['medium']}",
        f"  → low              : {c['low']}",
        f"  → false-positive   : {c['false-positive']}",
        "",
        f"Verdict — {report.synthesis.headline}",
        "",
        "Summary:",
        f"  {report.synthesis.executive_summary}",
    ]

    if report.synthesis.confirmed_high:
        lines.append("")
        lines.append("Confirmed HIGH:")
        for h in report.synthesis.confirmed_high:
            lines.append(f"  ✗ {h.file_path}:{h.line}  {h.headline}")

    if report.synthesis.confirmed_medium:
        lines.append("")
        lines.append("Confirmed MEDIUM:")
        for h in report.synthesis.confirmed_medium:
            lines.append(f"  • {h.file_path}:{h.line}  {h.headline}")

    if report.synthesis.low_and_false_positives:
        lines.append("")
        lines.append("Low / false-positive:")
        for h in report.synthesis.low_and_false_positives:
            lines.append(f"    {h.file_path}:{h.line}  ({h.exploitability})  {h.headline}")

    return "\n".join(lines)


__all__ = [
    "FullReport",
    "render_for_terminal",
    "save_report",
]
