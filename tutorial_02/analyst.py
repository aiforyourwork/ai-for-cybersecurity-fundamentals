"""Claude as a security analyst — reads N sqlmap sessions, returns a structured report.

The whole tutorial's payoff lives in this one function call. sqlmap
produces 100–500 lines of progress chatter, payload attempts, and table
dumps **per target**. Scan four or five targets and the captured stdout
is several thousand lines of mixed signal and noise. A human (or a
regex-based parser) would take a while to extract the headline from
that. Claude does it reliably in one round-trip with structured output.

Two design choices worth flagging:

1. **Lazy SDK import.** ``anthropic`` is only imported when we actually
   call the model. Lets the schema tests run without the SDK installed.

2. **Tool-use for structured output.** We pass ``SqliReport``'s JSON
   schema as a tool definition and force Claude to use it. This is more
   reliable than asking for "JSON in the response body" and parsing
   loosely — the SDK validates the tool input against the schema before
   returning.
"""
from __future__ import annotations

import os
import re
from typing import Any

from pydantic import BaseModel, Field


# ─── Output schema ──────────────────────────────────────────────────────────

class TableSummary(BaseModel):
    """One extracted table from a target database."""

    name: str = Field(..., description="Table name as reported by sqlmap.")
    columns: list[str] = Field(
        default_factory=list,
        description=(
            "Column names. Empty when sqlmap saw the table but didn't "
            "enumerate columns (e.g. --dump skipped due to size)."
        ),
    )
    row_count: int | None = Field(
        None,
        description="Rows extracted, when sqlmap reported a count.",
    )
    sample_data: str | None = Field(
        None,
        description=(
            "A short, redacted-if-needed sample of extracted rows. "
            "One line per row, truncated to keep the report readable."
        ),
    )


class TargetFinding(BaseModel):
    """Per-target findings — one of these per ``=== TARGET k/N: <url> ===`` banner."""

    target_url: str = Field(
        ...,
        description=(
            "The URL sqlmap attacked. MUST match the URL on the matching "
            "TARGET banner exactly."
        ),
    )
    vulnerability_confirmed: bool = Field(
        ...,
        description=(
            "True iff sqlmap proved at least one parameter on this target "
            "is injectable. Treat sqlmap's 'all tested parameters do not "
            "appear to be injectable' line as confirmation=false."
        ),
    )
    vulnerable_parameter: str | None = Field(
        None,
        description=(
            "The parameter sqlmap found injectable on this target. None "
            "when no injection was confirmed for this target."
        ),
    )
    injection_type: str | None = Field(
        None,
        description=(
            "Type of injection sqlmap landed on — e.g. "
            "'UNION query (NULL) - 7 columns', "
            "'boolean-based blind - WHERE or HAVING clause', "
            "'time-based blind'. None when no injection was confirmed."
        ),
    )
    database_engine: str | None = Field(
        None,
        description="The DBMS sqlmap fingerprinted, e.g. 'HSQLDB', 'MySQL >= 5.5'.",
    )
    tables: list[TableSummary] = Field(
        default_factory=list,
        description="Tables sqlmap enumerated for this target.",
    )
    notes: str | None = Field(
        None,
        description=(
            "One short sentence on this target specifically — e.g. "
            "'userid was injectable via UNION; login_count tested clean.' "
            "or 'sqlmap could not confirm injection — the JSON response "
            "envelope is too uniform for boolean/time-based discrimination.'"
        ),
    )


class SqliReport(BaseModel):
    """The structured analyst report. Claude is constrained to this shape."""

    targets: list[TargetFinding] = Field(
        default_factory=list,
        description=(
            "One TargetFinding per sqlmap session. There must be exactly "
            "one entry per '=== TARGET k/N: <url> ===' banner in the input — "
            "even targets where sqlmap found nothing."
        ),
    )
    plain_english_summary: str = Field(
        ...,
        description=(
            "2–4 sentences explaining the overall findings across all targets, "
            "in business-friendly language. Assumes the reader is a developer "
            "or PM, not a SQL injection expert."
        ),
    )
    business_impact: str = Field(
        ...,
        description=(
            "One sentence overall verdict. Must start with a severity word "
            "(Critical / High / Medium / Low / Informational) reflecting the "
            "worst finding across the scanned targets, followed by the concrete "
            "consequence."
        ),
    )


# ─── Claude analyst call ────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security analyst reviewing the output of one or more sqlmap \
sessions that were run against intentionally-vulnerable lab targets \
(OWASP WebGoat) during an authorised pentest exercise.

The captured stdout you'll receive contains output from N sqlmap runs, \
one per target. Each run is preceded by a banner line of the form:

    === TARGET k/N: <url> ===

Your job is to produce **one TargetFinding per banner** — even when \
sqlmap found nothing for that target. The TargetFinding's ``target_url`` \
must match the URL in the matching banner exactly.

For each target:

- Set ``vulnerability_confirmed=true`` only when sqlmap printed a \
  "Parameter: X (...)" block with one or more "Type: ..." entries below it.
- Set ``vulnerability_confirmed=false`` when sqlmap printed \
  "all tested parameters do not appear to be injectable" — or when sqlmap \
  errored out, hit a wall of 4xx/5xx responses, or otherwise produced no \
  confirmed finding.
- When ``--dump`` produced table data for this target, extract the table \
  names + column lists + a few representative sample rows (truncate long \
  rows). Do NOT invent table or column names — only report what sqlmap \
  actually printed.
- ``notes`` MUST be a single short phrase, ideally ≤80 characters, never \
  more than one sentence. This field appears on a single terminal line \
  next to the per-target finding — keep it tight. Examples of the right \
  shape: "userid injectable; login_count clean" / "uniform JSON envelope \
  foils response-diff heuristic" / "no params present".

Keep the OUTPUT COMPACT. The terminal rendering shows two lines per target \
plus a one-line verdict and a one-line summary — don't waste that budget. \
The top-level ``plain_english_summary`` is at most two short sentences \
describing what the scan found overall. The top-level ``business_impact`` \
is a single sentence starting with one of: Critical / High / Medium / Low / \
Informational — followed by the headline consequence in clipped, \
business-friendly language. The severity reflects the worst finding across \
all scanned targets.

Be calibrated: WebGoat lessons are deliberately easy. A clean dump from \
WebGoat is Critical-by-construction but worth noting that the lab is \
intentionally vulnerable.
"""


# ─── Pre-flight log compression ─────────────────────────────────────────────
#
# sqlmap at engagement-grade verbosity (-v 3) plus --level=3 --risk=2 produces
# logs in the 1-5 million-character range for a multi-target scan. That's:
#   - over Haiku 4.5's 200k token context window (a 1.4M-char log is ~210k tokens)
#   - way over Anthropic's standard-tier per-minute input rate limit (50k tokens)
#   - mostly internal sqlmap state and per-attempt journey, not analytical signal
#
# Compression strategy: keep the *destinations*, drop the *journey*. sqlmap's
# value to an analyst is in its decisions — "POST parameter X is injectable
# via technique Y with payload Z" — not in the thousands of failed attempts
# along the way to that decision. Concretely:
#
# DROPPED (journey noise — ~80% of a --thorough log):
#   - [DEBUG] lines (internal state: cookie set, header set, hostname resolved)
#   - Timestamp prefixes ([12:27:05]) — useless to an offline analyst
#   - [PAYLOAD] lines — the per-attempt payload strings. The *successful*
#     payload appears verbatim in the conclusion block ("Payload: ..."), so
#     dropping per-attempt [PAYLOAD] lines loses nothing the conclusion already
#     captures. Voluminous at -v 3.
#   - [INFO] "testing 'X'" lines — sqlmap's narration of which technique it's
#     trying. The outcome (injectable / not injectable) is preserved below.
#   - [INFO] "testing if ... is dynamic" lines — likewise narration.
#   - sqlmap banner art and legal disclaimer
#   - "[*] starting @" / "[*] ending @" timing markers
#   - Consecutive identical lines (sqlmap retries the same probe)
#
# KEPT VERBATIM (signal — the conclusions an analyst would read):
#   - All "=== TARGET k/N: <url> ===" banners (load-bearing for the analyst prompt)
#   - The "Parameter:/Type:/Title:/Payload:" conclusion blocks
#   - "sqlmap identified the following injection point(s)" lines
#   - "back-end DBMS" identification
#   - Schema/table dumps (Database:, Table:, [N entries], | rows |, +---+)
#   - [WARNING] decisions ("does not seem to be injectable", "false positive")
#   - [CRITICAL] (all tested clean / no params found)
#   - [ERROR] lines
#   - Any [INFO] line containing the word "injectable" (positive decision)
#
# The full uncompressed log still gets written to disk — that's the audit
# trail. Compression only affects what goes to the LLM. Typical reduction
# on a --thorough scan: 80-90% chars stripped.

_TIMESTAMP_PREFIX = re.compile(r"^\[\d\d:\d\d:\d\d\]\s+")

# Lines to drop outright — internal state and journey noise.
_NOISE_PATTERNS = [
    re.compile(r"^\[DEBUG\]"),                                           # internal state
    re.compile(r"^\[PAYLOAD\]"),                                         # per-attempt payloads (gold lives in conclusion block)
    re.compile(r"^\[INFO\] testing '"),                                  # "testing 'AND boolean-based blind'..."
    re.compile(r"^\[INFO\] testing if (?:GET|POST|HTTP) parameter '\S+' is dynamic$"),
    re.compile(r"^\[INFO\] testing if the target URL"),                  # "testing if target URL content is stable"
    re.compile(r"^\[INFO\] testing connection to the target URL$"),
    re.compile(r"^\[INFO\] heuristic \(basic\) test"),
    re.compile(r"^\[INFO\] heuristic \(parsing\) test"),
    re.compile(r"^\[\*\] starting @"),                                   # "[*] starting @ 12:27:05"
    re.compile(r"^\[\*\] ending @"),
    re.compile(r"^\[!\] legal disclaimer"),
    re.compile(r"^\s*[_|]"),                                             # sqlmap ASCII-art banner art
    re.compile(r"^\s*\{\d[\w.]*\}"),                                     # version banner
    re.compile(r"^\s+https://sqlmap\.org$"),
]


def compress_sqlmap_log(sqlmap_stdout: str) -> str:
    """Strip noise channels from sqlmap stdout before sending to the analyst.

    Returns the compressed log. The full uncompressed input is unaffected —
    keep it on disk separately for the engagement audit trail.

    Compression keeps the destinations (conclusions, decisions, schema
    dumps) and drops the journey (per-attempt payload chatter, technique
    narration, internal state). Typical reduction on a ``--thorough``
    scan: 80-90% chars stripped. See module-level docstring above for
    the full list of dropped vs kept patterns.
    """
    kept: list[str] = []
    prev: str | None = None
    for raw in sqlmap_stdout.splitlines():
        # Strip timestamp prefix first so the noise patterns can match
        # without having to embed timestamp matchers in each one.
        stripped = _TIMESTAMP_PREFIX.sub("", raw)
        if any(p.match(stripped) for p in _NOISE_PATTERNS):
            continue
        # Consecutive identical lines (after timestamp + noise stripping)
        # collapse to one — sqlmap retries the same probe repeatedly.
        if stripped == prev and stripped.strip():
            continue
        kept.append(stripped)
        prev = stripped
    return "\n".join(kept)


class AnalystError(RuntimeError):
    """Raised when the analyst call fails (missing key, refusal, etc.)."""


def analyse_sqlmap_output(
    *,
    sqlmap_stdout: str,
    target_urls: list[str],
    model: str = "claude-haiku-4-5",
    api_key: str | None = None,
    max_tokens: int = 4096,
) -> SqliReport:
    """Call Claude with the concatenated sqlmap output and return a SqliReport.

    Uses tool-use forced output: Claude is required to invoke the
    ``record_sqli_report`` tool, whose input schema IS ``SqliReport``.
    The SDK validates the tool input against the schema for us, so a
    malformed response is impossible — it would be raised as an SDK
    error before reaching this code.

    ``target_urls`` is the ordered list of URLs that were scanned. It's
    included in the user message so Claude can cross-check banners
    against the expected target set, and so the prompt makes the
    "produce one TargetFinding per URL" instruction unambiguous.
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise AnalystError(
            "ANTHROPIC_API_KEY not set. Add it to .env or pass --api-key."
        )

    # Lazy import — schema tests don't need anthropic installed.
    from anthropic import Anthropic

    tool_schema = SqliReport.model_json_schema()
    tool = {
        "name": "record_sqli_report",
        "description": (
            "Record the structured SQL-injection findings from one or more "
            "sqlmap runs. Produce one TargetFinding per scanned URL."
        ),
        "input_schema": tool_schema,
    }

    target_list = "\n".join(f"  {i}. {u}" for i, u in enumerate(target_urls, start=1))
    user_message = (
        f"sqlmap was run against {len(target_urls)} target(s):\n\n"
        f"{target_list}\n\n"
        "Below is the captured stdout for every target, concatenated and "
        "delimited by lines of the form ``=== TARGET k/N: <url> ===``.\n\n"
        "```\n"
        f"{sqlmap_stdout}\n"
        "```\n\n"
        "Call the record_sqli_report tool. Produce exactly one TargetFinding "
        "entry per target above (in the same order), then write the top-level "
        "plain_english_summary and business_impact across all targets."
    )

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        tools=[tool],
        tool_choice={"type": "tool", "name": "record_sqli_report"},
        messages=[{"role": "user", "content": user_message}],
    )

    tool_use_block = _find_tool_use(response.content, "record_sqli_report")
    if tool_use_block is None:
        raise AnalystError(
            "Claude did not invoke the record_sqli_report tool. "
            f"Stop reason: {response.stop_reason}. "
            f"Raw content: {response.content!r}"
        )

    return SqliReport.model_validate(tool_use_block["input"])


def _find_tool_use(content_blocks: list[Any], tool_name: str) -> dict | None:
    """Pick the tool_use block matching ``tool_name`` from a response."""
    for block in content_blocks:
        if getattr(block, "type", None) == "tool_use":
            if getattr(block, "name", None) == tool_name:
                return {"name": block.name, "input": block.input}
    return None


def render_report_for_terminal(report: SqliReport) -> str:
    """Format a SqliReport for human reading in a terminal.

    Deliberately compact — the structured JSON at ``report.json`` is the
    canonical form with every field intact. This terminal view is the
    "what would I show to my engagement lead in 30 seconds" summary,
    designed to maximise the visual contrast against sqlmap's noisy log.
    Two lines per target max; one-sentence overall verdict; the whole
    thing fits on a laptop screen.
    """
    lines: list[str] = []
    total = len(report.targets)
    confirmed = sum(1 for t in report.targets if t.vulnerability_confirmed)
    lines.append(
        f"Scanned {total} target(s); {confirmed}/{total} confirmed injectable."
    )
    lines.append("")

    for idx, t in enumerate(report.targets, start=1):
        icon = "✓" if t.vulnerability_confirmed else "✗"
        path = _short_path(t.target_url)
        lines.append(f"  [{idx}/{total}] {icon}  {path}")
        detail = _format_finding_detail(t)
        if detail:
            lines.append(f"           {detail}")

    lines.append("")
    lines.append(f"Verdict — {report.business_impact}")
    lines.append("")
    lines.append(f"Summary: {report.plain_english_summary}")
    return "\n".join(lines)


def _short_path(url: str) -> str:
    """Trim the URL to just its path for compact display.

    The host:port is identical across every WebGoat target in a single
    scan; printing it on every line is noise. The path is what readers
    need to identify the target.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.path or url


def _format_finding_detail(t: TargetFinding) -> str:
    """Build the second line per target — the one-line "what we found".

    Returns an empty string when there's nothing useful to add (e.g. a
    not-confirmed target with no notes), so the renderer can skip the
    line entirely and keep the report dense.
    """
    if t.vulnerability_confirmed:
        bits: list[str] = []
        if t.vulnerable_parameter:
            bits.append(f"{t.vulnerable_parameter} (POST)")
        if t.injection_type:
            bits.append(t.injection_type)
        if t.tables:
            for tbl in t.tables:
                row_part = f"{tbl.row_count} rows" if tbl.row_count is not None else "rows unknown"
                bits.append(f"→ {tbl.name} ({row_part})")
        return "; ".join(bits) if bits else (t.notes or "confirmed injectable")
    # Not confirmed — surface the notes if any, otherwise stay quiet.
    return t.notes or ""


__all__ = [
    "AnalystError",
    "SYSTEM_PROMPT",
    "SqliReport",
    "TableSummary",
    "TargetFinding",
    "analyse_sqlmap_output",
    "compress_sqlmap_log",
    "render_report_for_terminal",
]
