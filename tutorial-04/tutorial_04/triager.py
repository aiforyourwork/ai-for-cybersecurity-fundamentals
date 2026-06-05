"""Claude call #2 — per-finding exploitability triage (the map phase).

One Claude call per semgrep finding, run in parallel via a thread
pool. Each call answers a single question: *"is this finding a real
bug, and if so, how exploitable is it?"*

The triager doesn't know about other findings — it sees one match in
isolation, plus a window of surrounding source for context. Cross-
finding judgment (deduplication, prioritisation, executive summary)
happens in the synthesiser (Claude call #3, the reduce phase).

Per-finding budget: ~1k input tokens (match + ~30 lines of context +
the original concern), ~150 output. With 8–15 findings in flight at
once, the map phase wall-time is dominated by the slowest single call,
not by N × per-call latency.
"""
from __future__ import annotations

import concurrent.futures as _futures
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from .semgrep_runner import SemgrepFinding


# ─── Output schema ──────────────────────────────────────────────────────────

ExploitabilityRank = Literal["high", "medium", "low", "false-positive"]


class TriageVerdict(BaseModel):
    """The structured per-finding verdict — one of these per semgrep match."""

    exploitability: ExploitabilityRank = Field(
        ...,
        description=(
            "Rank this finding's exploitability:\n"
            "- ``high``: a real bug; user input reaches a dangerous sink; "
            "exploitation requires only off-the-shelf tooling.\n"
            "- ``medium``: a real bug; reach is plausible but requires "
            "additional preconditions (auth, specific config).\n"
            "- ``low``: a code-smell match; the pattern fires but the bug "
            "class is unlikely to be reachable in practice.\n"
            "- ``false-positive``: the rule pattern matches but the match "
            "is NOT an instance of the bug class — wrong sink, sanitised "
            "input, test fixture, etc.\n"
            "Be calibrated: most false positives come from rule-pattern "
            "broadness, not from analyst overcaution."
        ),
    )
    rationale: str = Field(
        ...,
        description=(
            "One short sentence (≤ 160 chars) explaining the verdict. Name "
            "the specific input source (e.g. 'request.getParameter') AND "
            "the sink (e.g. 'Statement.executeQuery'). For false-positives, "
            "name what makes the match wrong (e.g. 'value is hard-coded "
            "lesson scaffolding, not user input')."
        ),
    )
    exploitation_guidance: str | None = Field(
        None,
        description=(
            "For high/medium findings: ONE line on how an attacker would "
            "land this. Example: \"Send `?account=1' OR '1'='1' --` to "
            "/SqlInjection/assignment5b to dump the user_data table.\" "
            "Omit (return null) for low and false-positive."
        ),
    )


@dataclass(frozen=True)
class TriagedFinding:
    """A semgrep finding paired with its Claude triage verdict.

    Carries every field the report and synthesiser will need. The raw
    SemgrepFinding is preserved so downstream consumers don't have to
    join two parallel lists.
    """

    finding: SemgrepFinding
    verdict: TriageVerdict
    code_context: str       # ±15 lines around the match — what Claude was shown


# ─── System prompt ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security engineer triaging the output of a semgrep static-\
analysis rule against a Java codebase.

You will receive ONE semgrep finding at a time — the rule message, the \
file path, the matched code, and ~30 lines of surrounding source for \
context. You will also receive the original natural-language concern \
that generated the rule.

Your job is to decide whether THIS finding is a real instance of the \
bug class the concern described, and if so, how exploitable it is.

Output one TriageVerdict by calling the ``record_triage_verdict`` tool.

Ranking guidance:

- ``high``: user input demonstrably reaches a dangerous sink with no \
  meaningful sanitisation; an attacker with no special access can \
  trigger the vulnerability with off-the-shelf tooling (curl, sqlmap, \
  Burp). For SQLi this is the classic concatenation pattern. For path \
  traversal this is request param → File constructor with no \
  normalisation.
- ``medium``: a real bug, but exploitation requires preconditions an \
  attacker would need to obtain first — authenticated session, specific \
  configuration, a precondition file existing on disk.
- ``low``: the rule pattern fires but the bug class is unlikely to be \
  reachable. Example: a SQLi-pattern match where the "user input" is \
  actually a hard-coded constant the lesson framework passes in.
- ``false-positive``: the rule's PATTERN matches but the match is NOT \
  an instance of the concern's bug class. Examples: sink looks like \
  SQL execution but is actually a HQL parameterised query, "user \
  input" turns out to be the result of a previous prepared statement, \
  the match is in a test fixture or comment.

Be calibrated. WebGoat is a deliberately-vulnerable lab: the BASE rate \
of true positives is very high here, and triage should mostly confirm \
real bugs while catching the small fraction of rule-pattern over-reach. \
If you're unsure, prefer ``medium`` over ``high`` — the synthesiser \
will surface the high-confidence ones in the executive summary.

``rationale``: ONE short sentence, ≤ 160 characters. Name the specific \
input source and sink. Don't restate the rule message verbatim — the \
analyst already saw it.

``exploitation_guidance``: ONE line, only for high/medium. Concrete: \
say the endpoint and the payload shape. Omit (null) for low and \
false-positive — those don't get exploited.
"""


# ─── Claude calls ───────────────────────────────────────────────────────────

class TriageError(RuntimeError):
    """Raised when the triager fails (missing key, refusal)."""


def triage_one(
    *,
    finding: SemgrepFinding,
    code_context: str,
    concern: str,
    model: str = "claude-haiku-4-5",
    api_key: str | None = None,
    max_tokens: int = 512,
) -> TriagedFinding:
    """Triage a single semgrep finding via one Claude call.

    Synchronous. Used both directly (for tests) and as the unit of work
    inside ``triage_all`` (which parallelises N of these via threads).
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise TriageError(
            "ANTHROPIC_API_KEY not set. Add it to .env or pass --api-key."
        )

    # Lazy import — schema tests don't need anthropic installed.
    from anthropic import Anthropic

    tool_schema = TriageVerdict.model_json_schema()
    tool = {
        "name": "record_triage_verdict",
        "description": (
            "Record this finding's exploitability verdict and rationale."
        ),
        "input_schema": tool_schema,
    }

    user_message = (
        f"Original security concern: {concern.strip()}\n\n"
        f"Semgrep finding:\n"
        f"  rule_id  : {finding.rule_id}\n"
        f"  file     : {finding.file_path}:{finding.start_line}\n"
        f"  severity : {finding.severity}\n"
        f"  message  : {finding.message}\n\n"
        f"Matched code:\n```java\n{finding.matched_code}\n```\n\n"
        f"Surrounding source (±15 lines for context):\n"
        f"```java\n{code_context}\n```\n\n"
        f"Call the record_triage_verdict tool with your assessment."
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
        raise TriageError(
            f"Claude did not invoke record_triage_verdict for "
            f"{finding.file_path}:{finding.start_line}. Stop reason: "
            f"{response.stop_reason}."
        )
    verdict = TriageVerdict.model_validate(tool_use["input"])
    return TriagedFinding(
        finding=finding, verdict=verdict, code_context=code_context,
    )


def triage_all(
    *,
    findings: list[SemgrepFinding],
    concern: str,
    source_root: Path,
    workers: int = 8,
    model: str = "claude-haiku-4-5",
    api_key: str | None = None,
    progress_callback=None,
) -> list[TriagedFinding]:
    """Map phase — triage every finding in parallel.

    Wall time is dominated by the slowest single call, not by the sum.
    ``workers`` caps concurrency at the Anthropic-tier-appropriate
    level (default 8 — comfortable on the standard tier).

    ``progress_callback(done, total, triaged)`` if supplied is invoked
    after each triage completes; useful for the CLI to render a live
    counter.

    Order in the returned list matches the order in ``findings`` (NOT
    completion order) — keeps the JSON report stable across runs.
    """
    if not findings:
        return []

    contexts = [_read_code_context(source_root, f) for f in findings]
    total = len(findings)
    results: list[TriagedFinding | None] = [None] * total

    def _work(idx_finding_ctx):
        idx, f, ctx = idx_finding_ctx
        return idx, triage_one(
            finding=f,
            code_context=ctx,
            concern=concern,
            model=model,
            api_key=api_key,
        )

    work = [(i, f, c) for i, (f, c) in enumerate(zip(findings, contexts))]
    done = 0
    with _futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for future in _futures.as_completed(
            pool.submit(_work, item) for item in work
        ):
            idx, triaged = future.result()
            results[idx] = triaged
            done += 1
            if progress_callback is not None:
                progress_callback(done, total, triaged)

    # Every slot must be populated — None would mean a swallowed exception.
    out: list[TriagedFinding] = []
    for r in results:
        assert r is not None, "triage_all: unfilled slot"
        out.append(r)
    return out


# ─── Helpers ────────────────────────────────────────────────────────────────

_CONTEXT_LINES = 15


def _read_code_context(source_root: Path, finding: SemgrepFinding) -> str:
    """Read ±15 lines around the finding from the source file.

    Returns ``"(file not readable)"`` rather than raising — the triage
    call still goes through with the matched-code-only view; rationale
    will be slightly less informed.
    """
    abs_path = source_root / finding.file_path
    try:
        lines = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(file not readable)"
    start = max(0, finding.start_line - 1 - _CONTEXT_LINES)
    end = min(len(lines), finding.end_line + _CONTEXT_LINES)
    return "\n".join(
        f"{idx + 1:5d}  {line}" for idx, line in enumerate(lines[start:end], start=start)
    )


def _find_tool_use(content_blocks: list[Any], tool_name: str) -> dict | None:
    """Pick the tool_use block matching ``tool_name`` from a response."""
    for block in content_blocks:
        if getattr(block, "type", None) == "tool_use":
            if getattr(block, "name", None) == tool_name:
                return {"name": block.name, "input": block.input}
    return None


__all__ = [
    "ExploitabilityRank",
    "SYSTEM_PROMPT",
    "TriageError",
    "TriageVerdict",
    "TriagedFinding",
    "triage_all",
    "triage_one",
]
