"""Claude call #3 — the reduce phase.

After the triager has produced one verdict per finding, the synthesiser
consumes the full triaged list and produces a single executive summary
plus a prioritised bug list. Same shape as T2's analyst report —
designed to be the "what to tell my engagement lead in 30 seconds"
artefact.

Why a separate call rather than just sorting + templating? Two reasons:

1. **Cross-finding judgment** — multiple findings sometimes describe
   the same underlying bug at different sinks (e.g. a SQLi rule fires
   on Statement.executeQuery AND PreparedStatement-without-parameters
   in the same method). The synthesiser dedupes by lesson + bug-class.

2. **Severity calibration across the set** — the per-finding triager
   has no visibility into how many other high-severity findings exist.
   The synthesiser sets the overall verdict (Critical/High/Medium/...)
   based on the worst confirmed finding AND the count of confirmed
   findings, which is impossible to do at the map stage.
"""
from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from .triager import TriagedFinding


# ─── Output schema ──────────────────────────────────────────────────────────

class FindingHeadline(BaseModel):
    """One line of the prioritised list in the executive report."""

    file_path: str = Field(
        ...,
        description=(
            "The source file (POSIX-relative to the scan root) where the "
            "bug lives. Echoes the matching triaged finding's file_path."
        ),
    )
    line: int = Field(
        ..., description="The matching finding's start_line.",
    )
    exploitability: str = Field(
        ...,
        description=(
            "Echoes the triager's verdict — high / medium / low / "
            "false-positive."
        ),
    )
    headline: str = Field(
        ...,
        description=(
            "ONE short sentence (≤ 120 chars) summarising the bug AND the "
            "exploitation shape. The analyst reads this in a terminal next "
            "to the file:line; keep it tight."
        ),
    )


class SynthesisedReport(BaseModel):
    """The structured output of the reduce-phase synthesiser."""

    headline: str = Field(
        ...,
        description=(
            "Single sentence starting with a severity word "
            "(Critical / High / Medium / Low / Informational) reflecting "
            "the worst confirmed finding, followed by the concrete "
            "consequence in business-friendly language."
        ),
    )
    executive_summary: str = Field(
        ...,
        description=(
            "Two to four sentences. Reader is a developer or PM, not a "
            "static-analysis specialist. Should answer: what was scanned, "
            "what was found, what an analyst should do about it. No "
            "jargon without a one-line explanation."
        ),
    )
    confirmed_high: list[FindingHeadline] = Field(
        default_factory=list,
        description="Every triaged finding ranked high — in confidence order.",
    )
    confirmed_medium: list[FindingHeadline] = Field(
        default_factory=list,
        description="Every triaged finding ranked medium — in confidence order.",
    )
    low_and_false_positives: list[FindingHeadline] = Field(
        default_factory=list,
        description=(
            "Low + false-positive findings, surfaced briefly so the analyst "
            "knows they were considered. The headline should explain why "
            "the rule fired but the bug isn't real."
        ),
    )


# ─── System prompt ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security engineer producing the final report for a static-\
analysis engagement against a Java codebase.

You will receive the original natural-language concern, the semgrep \
rule that was run, and a list of per-finding triage verdicts produced \
by a per-finding triager Claude call.

Your job is to synthesise this into ONE executive report. Call the \
``record_synthesised_report`` tool with the result.

Three things you MUST do:

1. **Set the overall ``headline`` honestly.** Start with one of \
   Critical / High / Medium / Low / Informational. This severity \
   reflects the worst CONFIRMED (high or medium) finding AND the count: \
   one confirmed high SQLi in an internet-facing endpoint is Critical; \
   one confirmed medium that requires authentication is High; five \
   confirmed lows with no clear path to exploitation is Medium; zero \
   confirmed is Informational.
2. **Dedupe near-duplicate findings.** If the same bug class fires at \
   two adjacent sinks in the same method (e.g. Statement.executeQuery \
   AND ResultSet retrieval in the same SQLi method), surface ONE entry \
   in the confirmed_high or confirmed_medium list with a headline that \
   mentions both sinks.
3. **Keep each ``headline`` ≤ 120 characters.** The headline appears \
   in a terminal column next to the file:line; long sentences wrap and \
   ruin the layout. Lead with the bug-class verb (e.g. \"SQLi via\", \
   \"Path traversal in\", \"Command injection through\").

The ``executive_summary`` is 2-4 sentences. Assume the reader is a dev \
or PM. Answer: what was scanned, what was found, what to do next.

WebGoat is deliberately vulnerable — the report can be unambiguous \
about the findings being real without needing to hedge. But mention it: \
\"WebGoat lessons are intentionally vulnerable; equivalent patterns in \
production code would be Critical-by-default.\"
"""


# ─── Claude call ────────────────────────────────────────────────────────────

class SynthesisError(RuntimeError):
    """Raised when the synthesiser fails (missing key, refusal)."""


def synthesise(
    *,
    triaged: list[TriagedFinding],
    concern: str,
    rule_yaml: str,
    model: str = "claude-haiku-4-5",
    api_key: str | None = None,
    max_tokens: int = 2048,
) -> SynthesisedReport:
    """Reduce phase — synthesise the triaged findings into one executive report.

    Uses tool-use forced output. ``SynthesisedReport``'s schema lets the
    Anthropic SDK validate the response shape before returning, so a
    malformed response can't reach the caller.
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise SynthesisError(
            "ANTHROPIC_API_KEY not set. Add it to .env or pass --api-key."
        )

    # Lazy import — schema tests don't need anthropic installed.
    from anthropic import Anthropic

    tool_schema = SynthesisedReport.model_json_schema()
    tool = {
        "name": "record_synthesised_report",
        "description": (
            "Record the consolidated executive report across all triaged "
            "findings — overall verdict, summary, and prioritised lists."
        ),
        "input_schema": tool_schema,
    }

    triage_block = _format_triage_for_prompt(triaged)
    user_message = (
        f"Original security concern: {concern.strip()}\n\n"
        f"Semgrep rule that was run:\n"
        f"```yaml\n{rule_yaml.strip()}\n```\n\n"
        f"Per-finding triage verdicts ({len(triaged)} total):\n\n"
        f"{triage_block}\n\n"
        f"Call the record_synthesised_report tool with one consolidated "
        f"report across these findings. Set overall severity based on the "
        f"worst confirmed finding; produce confirmed_high / "
        f"confirmed_medium / low_and_false_positives lists."
    )

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        tools=[tool],
        tool_choice={"type": "tool", "name": tool["name"]},
        messages=[{"role": "user", "content": user_message}],
    )

    tool_use = _find_tool_use(response.content, tool["name"])
    if tool_use is None:
        raise SynthesisError(
            "Claude did not invoke record_synthesised_report. "
            f"Stop reason: {response.stop_reason}."
        )
    return SynthesisedReport.model_validate(tool_use["input"])


def _format_triage_for_prompt(triaged: list[TriagedFinding]) -> str:
    """Render the triage verdicts as a compact block for the synthesiser prompt."""
    blocks: list[str] = []
    for idx, t in enumerate(triaged, start=1):
        f = t.finding
        v = t.verdict
        block_lines = [
            f"--- finding {idx} ---",
            f"  file       : {f.file_path}:{f.start_line}",
            f"  severity   : {f.severity}",
            f"  rule_msg   : {f.message}",
            f"  matched    : {f.matched_code[:200]}"
            + ("..." if len(f.matched_code) > 200 else ""),
            f"  triage     : {v.exploitability}",
            f"  rationale  : {v.rationale}",
        ]
        if v.exploitation_guidance:
            block_lines.append(f"  exploit    : {v.exploitation_guidance}")
        blocks.append("\n".join(block_lines))
    return "\n\n".join(blocks)


def _find_tool_use(content_blocks: list[Any], tool_name: str) -> dict | None:
    """Pick the tool_use block matching ``tool_name`` from a response."""
    for block in content_blocks:
        if getattr(block, "type", None) == "tool_use":
            if getattr(block, "name", None) == tool_name:
                return {"name": block.name, "input": block.input}
    return None


__all__ = [
    "FindingHeadline",
    "SYSTEM_PROMPT",
    "SynthesisError",
    "SynthesisedReport",
    "synthesise",
]
