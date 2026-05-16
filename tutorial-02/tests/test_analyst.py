"""Tests for ``tutorial_02/analyst.py``.

The ``analyse_sqlmap_output`` call hits Claude live — we don't test
that here (would cost money and require network). What we DO test:

- ``SqliReport``, ``TargetFinding``, and ``TableSummary`` round-trip
  cleanly through Pydantic's validate/dump cycle.
- Required-field enforcement.
- ``render_report_for_terminal`` produces readable output for the mixed
  multi-target case.
- The schema exported for Anthropic tool-use has the right shape.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from tutorial_02.analyst import (
    SqliReport,
    TableSummary,
    TargetFinding,
    compress_sqlmap_log,
    render_report_for_terminal,
)


def _confirmed_finding() -> TargetFinding:
    return TargetFinding(
        target_url="http://localhost:8080/WebGoat/SqlInjection/assignment5b",
        vulnerability_confirmed=True,
        vulnerable_parameter="userid",
        injection_type="UNION query (NULL) - 7 columns",
        database_engine="HSQLDB",
        tables=[
            TableSummary(
                name="user_data",
                columns=["userid", "first_name", "password"],
                row_count=14,
                sample_data="101 / Joe / passwd1",
            ),
        ],
        notes="userid injectable via UNION; login_count clean.",
    )


def _not_confirmed_finding() -> TargetFinding:
    return TargetFinding(
        target_url="http://localhost:8080/WebGoat/SqlInjection/assignment5a",
        vulnerability_confirmed=False,
        notes="No params confirmed — uniform JSON envelope tripped sqlmap.",
    )


def _multi_target_report() -> SqliReport:
    return SqliReport(
        targets=[_confirmed_finding(), _not_confirmed_finding()],
        plain_english_summary=(
            "Of two endpoints scanned, one is exploitable via SQL injection "
            "on the 'userid' parameter; the other tested clean at default "
            "settings."
        ),
        business_impact=(
            "Critical — credential extraction confirmed on the userid "
            "parameter of assignment5b."
        ),
    )


# ─── Schema round-trip ──────────────────────────────────────────────────────

def test_sqli_report_roundtrips_through_json():
    report = _multi_target_report()
    as_json = report.model_dump_json()
    parsed = SqliReport.model_validate_json(as_json)
    assert parsed == report


def test_sqli_report_allows_no_targets_confirmed():
    """All-clean scan: every target tested negative. Still a valid report
    shape — sqlmap-found-nothing is information, not error."""
    report = SqliReport(
        targets=[_not_confirmed_finding()],
        plain_english_summary="sqlmap found no injection on the scanned target.",
        business_impact="Informational — no exploitable injection found.",
    )
    assert all(not t.vulnerability_confirmed for t in report.targets)
    assert report.targets[0].vulnerable_parameter is None
    assert report.targets[0].tables == []


def test_sqli_report_requires_summary_and_impact():
    """Both prose fields are required — Claude must always produce them."""
    with pytest.raises(ValidationError):
        SqliReport(  # type: ignore[call-arg]
            targets=[_confirmed_finding()],
            # plain_english_summary and business_impact omitted
        )


def test_target_finding_requires_url_and_confirmed_flag():
    with pytest.raises(ValidationError):
        TargetFinding(  # type: ignore[call-arg]
            vulnerability_confirmed=True,
            # target_url omitted
        )
    with pytest.raises(ValidationError):
        TargetFinding(  # type: ignore[call-arg]
            target_url="http://x",
            # vulnerability_confirmed omitted
        )


def test_table_summary_optional_fields_default_safely():
    """row_count and sample_data are optional; columns defaults to []."""
    tbl = TableSummary(name="just_a_table")
    assert tbl.columns == []
    assert tbl.row_count is None
    assert tbl.sample_data is None


def test_sqli_report_targets_defaults_to_empty_list():
    """When sqlmap couldn't run at all, the analyst can produce a report
    with no targets and just the prose fields — useful for hard errors."""
    report = SqliReport(
        plain_english_summary="sqlmap exited before testing any target.",
        business_impact="Informational — scan did not run to completion.",
    )
    assert report.targets == []


# ─── Terminal rendering ─────────────────────────────────────────────────────
#
# The rendering is deliberately compact (max ~2 lines per target + a
# one-line verdict + a one-line summary). Tests cover what's load-bearing:
# the overview count, per-target icon/path, the confirmed-target detail
# line, and the overall verdict/summary placement.

def test_render_report_for_terminal_includes_overview_line():
    out = render_report_for_terminal(_multi_target_report())
    assert "Scanned 2 target(s); 1/2 confirmed injectable" in out


def test_render_report_for_terminal_includes_each_target():
    out = render_report_for_terminal(_multi_target_report())
    assert "[1/2] ✓" in out
    assert "[2/2] ✗" in out
    assert "assignment5b" in out
    assert "assignment5a" in out


def test_render_report_for_terminal_shows_finding_detail_for_confirmed():
    """Confirmed target gets a second line with parameter, technique, table info."""
    out = render_report_for_terminal(_multi_target_report())
    assert "userid (POST)" in out
    assert "UNION query (NULL) - 7 columns" in out
    assert "user_data" in out


def test_render_report_for_terminal_clean_target_stays_minimal():
    """A clean target shouldn't surface Parameter / Injection / Database lines."""
    report = SqliReport(
        targets=[_not_confirmed_finding()],
        plain_english_summary="Nothing found.",
        business_impact="Informational — no finding.",
    )
    out = render_report_for_terminal(report)
    # Old labelled-field lines should be gone in the compact rendering.
    assert "Injection type" not in out
    assert "Database engine" not in out
    assert "Extracted schema" not in out


def test_render_report_for_terminal_includes_verdict_and_summary():
    out = render_report_for_terminal(_multi_target_report())
    assert "Verdict —" in out
    assert "Summary:" in out
    assert "Critical" in out


def test_render_report_for_terminal_renders_target_with_unknown_columns():
    """Tables with no row_count should render as 'rows unknown' (no crash)."""
    report = SqliReport(
        targets=[
            TargetFinding(
                target_url="http://x/path",
                vulnerability_confirmed=True,
                vulnerable_parameter="x",
                injection_type="boolean-based blind",
                tables=[TableSummary(name="users")],
            ),
        ],
        plain_english_summary="Confirmed.",
        business_impact="High — read access on users.",
    )
    out = render_report_for_terminal(report)
    assert "users (rows unknown)" in out


def test_render_report_for_terminal_stays_compact():
    """The full report for a 2-target case should fit in ~10 lines.

    The whole pedagogical point of the rendering is the visual contrast
    against sqlmap's many-thousands-of-lines log. If we ever bloat this
    back to labelled-field-per-line, the contrast vanishes.
    """
    out = render_report_for_terminal(_multi_target_report())
    n_lines = len(out.splitlines())
    assert n_lines <= 12, f"Expected ≤12 lines for a 2-target report, got {n_lines}:\n{out}"


# ─── Log compression ────────────────────────────────────────────────────────
#
# The compressor strips noise channels before the log goes to Claude. Tests
# verify the right things stay (signal) and the right things go (noise).
# The full log on disk is unaffected — only the analyst-bound copy is shrunk.

def test_compress_strips_debug_and_narration_lines():
    """[DEBUG] is internal sqlmap state. [INFO] narration like 'testing
    connection to the target URL' is journey, not destination — both
    types are dropped. What stays: positive decisions, conclusion blocks,
    final verdicts."""
    log = (
        "[12:27:05] [DEBUG] cleaning up configuration parameters\n"
        "[12:27:05] [DEBUG] setting the HTTP Cookie header\n"
        "[12:27:05] [INFO] testing connection to the target URL\n"
        "[12:27:05] [INFO] POST parameter 'userid' is 'UNION query' injectable\n"
    )
    out = compress_sqlmap_log(log)
    assert "DEBUG" not in out
    assert "testing connection to the target URL" not in out  # journey narration
    # The decision line stays.
    assert "POST parameter 'userid' is 'UNION query' injectable" in out


def test_compress_drops_payload_lines_but_keeps_conclusion_block_payload():
    """[PAYLOAD] *log lines* are per-attempt journey noise — sqlmap fires
    dozens of payloads per parameter, most failing. The successful payload
    that sqlmap actually landed on appears separately in the conclusion
    block ('Payload: ...' under 'Parameter: X / Type: Y / Title: Z'), and
    that conclusion-block 'Payload:' line is preserved."""
    log = (
        "[12:27:05] [INFO] testing for SQL injection on POST parameter 'name'\n"
        "[12:27:05] [PAYLOAD] name=a' AND 4719=4719-- -\n"
        "[12:27:05] [PAYLOAD] name=b\" AND 9999=9999-- -\n"
        "[12:27:05] [INFO] POST parameter 'name' appears to be injectable\n"
        "Parameter: name (POST)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "    Payload: name=a' AND 4719=4719-- -&auth_tan=1\n"
    )
    out = compress_sqlmap_log(log)
    # Per-attempt [PAYLOAD] lines are stripped (journey, not destination).
    assert "[PAYLOAD]" not in out
    # The conclusion-block "Payload: ..." line stays — that's the gold.
    assert "Payload: name=a' AND 4719=4719-- -&auth_tan=1" in out
    # And the positive-decision INFO line stays too.
    assert "POST parameter 'name' appears to be injectable" in out


def test_compress_strips_timestamps():
    """Timestamps are useless to the analyst — they tokenize as their own
    cluster and inflate the prompt without helping interpretation."""
    log = (
        "[12:27:05] [INFO] testing connection\n"
        "[12:27:06] [INFO] target URL content is stable\n"
    )
    out = compress_sqlmap_log(log)
    assert "[12:27:" not in out
    # Bare INFO content survives.
    assert "[INFO] testing connection" in out
    assert "[INFO] target URL content is stable" in out


def test_compress_collapses_consecutive_duplicates():
    """sqlmap sometimes prints the same WARNING repeatedly while retrying.
    Collapse runs of identical-after-stripping lines to one occurrence."""
    log = (
        "[12:27:05] [WARNING] POST parameter 'x' does not appear to be dynamic\n"
        "[12:27:06] [WARNING] POST parameter 'x' does not appear to be dynamic\n"
        "[12:27:07] [WARNING] POST parameter 'x' does not appear to be dynamic\n"
    )
    out = compress_sqlmap_log(log)
    assert out.count("does not appear to be dynamic") == 1


def test_compress_preserves_target_banners():
    """The === TARGET k/N: <url> === banners are the load-bearing delimiters
    the analyst prompt depends on. Must survive compression unchanged."""
    log = (
        "=== TARGET 1/2: http://localhost/a ===\n"
        "[12:27:05] [DEBUG] noise\n"
        "[12:27:05] [INFO] hi\n"
        "=== TARGET 2/2: http://localhost/b ===\n"
    )
    out = compress_sqlmap_log(log)
    assert "=== TARGET 1/2: http://localhost/a ===" in out
    assert "=== TARGET 2/2: http://localhost/b ===" in out


def test_compress_substantially_reduces_volume_on_realistic_input():
    """End-to-end sanity check: a chunk that looks like a real --thorough
    sqlmap log should shrink by at least 80%. Realistic logs are mostly
    [DEBUG], [PAYLOAD] retries, and "testing 'X'..." narration."""
    log_lines = []
    techniques = [
        "AND boolean-based blind - WHERE or HAVING clause",
        "Boolean-based blind - Parameter replace (original value)",
        "Generic inline queries",
        "Generic UNION query (NULL) - 1 to 10 columns",
        "HSQLDB stacked queries (heavy query - comment)",
    ]
    for sec in range(60):
        ts = f"[12:27:{sec:02d}]"
        log_lines.append(f"{ts} [DEBUG] resolving hostname 'localhost'")
        log_lines.append(f"{ts} [DEBUG] setting the HTTP Cookie header")
        log_lines.append(f"{ts} [INFO] testing connection to the target URL")
        log_lines.append(f"{ts} [INFO] testing if POST parameter 'name' is dynamic")
        for tech in techniques:
            log_lines.append(f"{ts} [INFO] testing '{tech}'")
            log_lines.append(f"{ts} [PAYLOAD] name={sec}-{tech[:10]}")
    log = "\n".join(log_lines)
    out = compress_sqlmap_log(log)
    reduction_pct = 100 * (1 - len(out) / len(log))
    assert reduction_pct >= 80, f"Expected ≥80% reduction, got {reduction_pct:.0f}%"


def test_compress_keeps_conclusion_block_intact():
    """The Parameter:/Type:/Title:/Payload: conclusion block is the gold
    — every line must survive compression in order, intact."""
    log = (
        "[12:27:05] [DEBUG] noise\n"
        "[12:27:05] [INFO] testing 'AND boolean-based blind'\n"
        "[12:27:05] [PAYLOAD] noise-attempt-1\n"
        "[12:27:05] [INFO] POST parameter 'userid' is 'UNION query' injectable\n"
        "sqlmap identified the following injection point(s) with a total of 73 HTTP(s) requests:\n"
        "---\n"
        "Parameter: userid (POST)\n"
        "    Type: UNION query\n"
        "    Title: Generic UNION query (NULL) - 7 columns\n"
        "    Payload: login_count=1&userid=1 UNION ALL SELECT NULL,...\n"
        "---\n"
        "[12:27:05] [INFO] the back-end DBMS is HSQLDB\n"
        "back-end DBMS: HSQLDB\n"
    )
    out = compress_sqlmap_log(log)
    # Conclusion block intact.
    for line in [
        "sqlmap identified the following injection point(s)",
        "Parameter: userid (POST)",
        "    Type: UNION query",
        "    Title: Generic UNION query (NULL) - 7 columns",
        "    Payload: login_count=1&userid=1 UNION ALL SELECT NULL,...",
        "back-end DBMS: HSQLDB",
    ]:
        assert line in out, f"Expected to keep conclusion line: {line!r}"
    # Journey noise dropped.
    assert "[DEBUG]" not in out
    assert "[PAYLOAD] noise-attempt-1" not in out
    assert "[INFO] testing '" not in out


# ─── Tool definition (schema export) ────────────────────────────────────────

def test_sqli_report_model_json_schema_is_valid_for_anthropic_tool_use():
    """The model_json_schema() output is what we pass as the tool input schema
    to Claude. Sanity-check the shape so the wiring works on first run."""
    schema = SqliReport.model_json_schema()
    assert schema["type"] == "object"
    # Top-level properties.
    assert "targets" in schema["properties"]
    assert "plain_english_summary" in schema["properties"]
    assert "business_impact" in schema["properties"]
    # Required top-level fields — Claude must always set these.
    required = set(schema.get("required", []))
    assert {"plain_english_summary", "business_impact"}.issubset(required)
    # Nested TargetFinding shape is reachable via $defs.
    defs = schema.get("$defs", {})
    assert "TargetFinding" in defs
    finding_props = defs["TargetFinding"]["properties"]
    assert "target_url" in finding_props
    assert "vulnerability_confirmed" in finding_props
    assert "notes" in finding_props
