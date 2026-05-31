"""Pretty-print + JSON-serialise the unified pipeline report.

The pipeline produces five intermediate artefacts (passive enum,
generated candidates, resolved hosts, verified hosts, ranked hosts);
this module stitches them into one shape for the terminal funnel print
and the canonical ``report.json`` audit-trail artefact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from .generator import CandidateSubdomain
from .ranker import PRIORITY_ORDER, RankedHost


# ─── Structured report (canonical JSON form) ────────────────────────────────

class PipelineCounts(BaseModel):
    """The four-stage funnel's headline numbers.

    Three candidate sources are tracked separately so the funnel print can
    show the regex-extracted vs Claude-inferred split — the load-bearing
    pedagogical contrast of the tutorial. ``ai_only`` is the inference
    value-add: candidates Claude proposed that neither the regex extractor
    nor subfinder surfaced.
    """

    passive: int = Field(..., description="From subfinder (CT-log historicals).")
    regex_extracted: int = Field(..., description="From a deterministic HTML scrape of the homepage.")
    ai_inferred: int = Field(..., description="From Claude (total proposed; includes overlap with regex).")
    ai_only: int = Field(
        ...,
        description=(
            "Candidates ONLY Claude found — neither in subfinder's output nor "
            "in the regex extraction. This is the inference value-add."
        ),
    )
    total_candidates: int = Field(..., description="Union of all three sources, deduplicated.")
    in_scope: int = Field(..., description="Candidates within the scope file.")
    resolved: int = Field(..., description="Candidates with at least one A/AAAA record.")
    live_web: int = Field(..., description="Resolved hosts that returned an HTTP response.")
    ranked: int = Field(..., description="Hosts the ranker assigned a priority to.")


class HostRecord(BaseModel):
    """Per-host record in the final report — joined across pipeline stages."""

    host: str
    sources: list[str] = Field(
        default_factory=list,
        description="Where the host came from — 'subfinder' and/or 'ai'.",
    )
    in_scope: bool = True
    resolved: bool = False
    addresses: list[str] = Field(default_factory=list)
    live_web: bool = False
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    priority: str | None = None
    value: str | None = None


class Report(BaseModel):
    """The final pipeline report."""

    root_domain: str
    scope_patterns: list[str]
    counts: PipelineCounts
    headline: str
    hosts: list[HostRecord]


# ─── Intermediate join state ────────────────────────────────────────────────
#
# The CLI builds up a HostState per candidate as the pipeline progresses,
# then serialises the final list into a Report at the end.

@dataclass
class HostState:
    """Per-host accumulator threaded through the pipeline.

    Mutable on purpose — each stage adds new fields as it learns them.
    Caller is responsible for keeping the canonical ordering (e.g.
    deduplicated insertion order).
    """

    host: str
    sources: list[str] = field(default_factory=list)
    in_scope: bool = True
    resolved: bool = False
    addresses: list[str] = field(default_factory=list)
    live_web: bool = False
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    priority: str | None = None
    value: str | None = None
    ai_rationale: str | None = None

    def to_record(self) -> HostRecord:
        return HostRecord(
            host=self.host,
            sources=list(self.sources),
            in_scope=self.in_scope,
            resolved=self.resolved,
            addresses=list(self.addresses),
            live_web=self.live_web,
            status_code=self.status_code,
            title=self.title,
            server=self.server,
            priority=self.priority,
            value=self.value,
        )


# ─── Terminal funnel renderer ───────────────────────────────────────────────

def render_funnel(report: Report) -> str:
    """The headline visual — the four-stage funnel as a text block.

    Stage 1 shows the regex-vs-Claude split explicitly. The ``ai_only``
    line is the load-bearing pedagogical contrast: candidates Claude
    proposed that the regex baseline (and subfinder) missed — i.e.
    inference, not extraction.
    """
    c = report.counts
    lines: list[str] = []
    lines.append("─── Stage 1: candidate generation " + "─" * 27)
    lines.append(f"  subfinder        : {c.passive:>4} candidate(s)  (CT-log historicals)")
    lines.append(f"  regex extractor  : {c.regex_extracted:>4} candidate(s)  (linked from homepage)")
    lines.append(f"  claude generator : {c.ai_inferred:>4} candidate(s)  (total proposed)")
    lines.append(f"  net-new from AI  : {c.ai_only:>4} candidate(s)  (regex + subfinder would have missed)")
    lines.append(f"  total unique     : {c.total_candidates:>4}")
    out_of_scope = c.total_candidates - c.in_scope
    if out_of_scope:
        lines.append(f"  (dropped out-of-scope: {out_of_scope})")
    lines.append("─── Stage 2: DNS resolution " + "─" * 32)
    lines.append(f"  resolved         : {c.resolved:>4} / {c.in_scope}")
    lines.append("─── Stage 3: HTTP verification " + "─" * 29)
    lines.append(f"  live web         : {c.live_web:>4} / {c.resolved}")
    lines.append("─── Stage 4: AI ranking " + "─" * 36)
    lines.append(f"  ranked           : {c.ranked:>4} host(s)")
    lines.append("")

    by_priority = _bucket_by_priority(report.hosts)
    for level in ("high", "medium", "low"):
        bucket = by_priority.get(level, [])
        if not bucket:
            continue
        lines.append(f"  [{level}]")
        for h in bucket:
            status = str(h.status_code) if h.status_code is not None else "-"
            value = h.value or ""
            lines.append(f"    {h.host:<48} {status:>3}   {value}")
        lines.append("")

    lines.append(f"Headline: {report.headline}")
    return "\n".join(lines)


def _bucket_by_priority(hosts: list[HostRecord]) -> dict[str, list[HostRecord]]:
    buckets: dict[str, list[HostRecord]] = {"high": [], "medium": [], "low": []}
    ranked = [h for h in hosts if h.priority]
    ranked.sort(key=lambda h: PRIORITY_ORDER.get(h.priority or "", 3))
    for h in ranked:
        bucket = buckets.setdefault(h.priority or "low", [])
        bucket.append(h)
    return buckets


# ─── Report assembly ────────────────────────────────────────────────────────

def build_report(
    *,
    root_domain: str,
    scope_patterns: list[str],
    states: list[HostState],
    headline: str,
) -> Report:
    """Bind the accumulated host states into a final report shape.

    Counts each source ('subfinder', 'regex', 'ai') as a separate dimension
    so the funnel print can show the regex-vs-AI contrast. ``ai_only`` is
    the inference-net-of-extraction count and the load-bearing headline
    number.
    """
    counts = PipelineCounts(
        passive=sum(1 for s in states if "subfinder" in s.sources),
        regex_extracted=sum(1 for s in states if "regex" in s.sources),
        ai_inferred=sum(1 for s in states if "ai" in s.sources),
        ai_only=sum(
            1 for s in states
            if "ai" in s.sources
            and "regex" not in s.sources
            and "subfinder" not in s.sources
        ),
        total_candidates=len(states),
        in_scope=sum(1 for s in states if s.in_scope),
        resolved=sum(1 for s in states if s.resolved),
        live_web=sum(1 for s in states if s.live_web),
        ranked=sum(1 for s in states if s.priority),
    )
    hosts = [s.to_record() for s in states]
    return Report(
        root_domain=root_domain,
        scope_patterns=list(scope_patterns),
        counts=counts,
        headline=headline,
        hosts=hosts,
    )


__all__ = [
    "HostRecord",
    "HostState",
    "PipelineCounts",
    "Report",
    "build_report",
    "render_funnel",
]
