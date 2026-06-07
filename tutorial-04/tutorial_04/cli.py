"""CLI for the T4 source-code analysis pipeline.

Three execution modes:

- **Normal**: rule generation (Claude #1) → semgrep → triage (Claude #2,
  parallel) → synthesis (Claude #3) → JSON + terminal output.
- **--dry-run**: rule generation + semgrep only. No triage, no synthesis,
  no API spend on the map+reduce phase. Useful for sanity-checking the
  semgrep step in isolation.
- **--mock**: skip everything external. Uses fixture data baked into
  this file. Lets you smoke-test the orchestration without ``semgrep``
  installed and without an API key.

Outputs:

- A compact human-readable summary to stdout.
- ``report.json`` — the canonical structured artefact.
- ``generated_rules.yml`` — the semgrep rule Claude wrote (reusable
  against any codebase via ``semgrep --config=generated_rules.yml``).
- ``semgrep_raw.json`` — raw semgrep output, pre-triage.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

from .chunker import collect_target_files, render_fileset_for_terminal
from .report import FullReport, render_for_terminal, save_report
from .rule_generator import (
    GeneratedRule,
    RuleGenerationError,
    generate_rule,
    render_rule_for_terminal,
)
from .semgrep_runner import (
    SemgrepFinding,
    SemgrepMissingError,
    SemgrepResult,
    SemgrepRunError,
    render_findings_for_terminal,
    run_semgrep,
)
from .synthesiser import (
    FindingHeadline,
    SynthesisError,
    SynthesisedReport,
    synthesise,
)
from .triager import (
    TriageError,
    TriageVerdict,
    TriagedFinding,
    triage_all,
)
from .webgoat import resolve_webgoat_root


DEFAULT_MODEL = "claude-haiku-4-5"
DEFAULT_OUTPUT = "report.json"
DEFAULT_RULES_OUT = "generated_rules.yml"
DEFAULT_SEMGREP_RAW = "semgrep_raw.json"
DEFAULT_WORKERS = 8
DEFAULT_MAX_FILES = 1000  # WebGoat has ~300+ Java files; 200 cap clipped it.


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m tutorial_04",
        description=(
            "AI-augmented static-code analysis: translate an English "
            "concern into a semgrep rule (Claude), run it across the "
            "target source tree (semgrep), then triage every finding by "
            "exploitability (Claude, parallel). Educational use against "
            "intentionally-vulnerable codebases — bring documented "
            "authorisation for anything else."
        ),
    )
    p.add_argument(
        "--webgoat-source", required=True,
        help=(
            "Path to a cloned WebGoat repo (or any Java source tree). "
            "Resolves ~. Must contain "
            "src/main/java/org/owasp/webgoat/lessons/."
        ),
    )
    p.add_argument(
        "--concern", required=True,
        help=(
            "Natural-language security concern in quotes. Example: "
            "'Find SQL injection patterns where user input flows into "
            "JDBC queries'. See concerns.example.txt for the shape."
        ),
    )
    p.add_argument(
        "--triage-workers", type=int, default=DEFAULT_WORKERS,
        help=(
            f"Max concurrent Claude calls during the per-finding map "
            f"phase (default {DEFAULT_WORKERS}). Lower for Anthropic "
            f"free-tier rate limits."
        ),
    )
    p.add_argument(
        "--max-files", type=int, default=DEFAULT_MAX_FILES,
        help=(
            f"Cap the number of files semgrep scans (default "
            f"{DEFAULT_MAX_FILES}). Demo-scoping; raise for "
            f"engagement-grade runs."
        ),
    )
    p.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Claude model for all three calls (default: {DEFAULT_MODEL}).",
    )
    p.add_argument(
        "--api-key", default=None,
        help="Anthropic API key. Defaults to ANTHROPIC_API_KEY env var.",
    )
    p.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Where to write the structured JSON report (default: {DEFAULT_OUTPUT}).",
    )
    p.add_argument(
        "--rules-out", default=DEFAULT_RULES_OUT,
        help=(
            f"Where to write the generated semgrep rule (default: "
            f"{DEFAULT_RULES_OUT}). Re-runnable against any codebase via "
            f"semgrep --config=<file>."
        ),
    )
    p.add_argument(
        "--semgrep-raw", default=DEFAULT_SEMGREP_RAW,
        help=(
            f"Where to write the raw semgrep JSON output (default: "
            f"{DEFAULT_SEMGREP_RAW}). Pass empty string to skip."
        ),
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help=(
            "Run rule generation + semgrep. Skip the Claude triage AND "
            "synthesis steps. Saves cost while sanity-checking the rule."
        ),
    )
    p.add_argument(
        "--mock", action="store_true",
        help=(
            "Skip semgrep AND Claude entirely. Uses fixture data — for "
            "smoke tests and end-to-end CI."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    load_dotenv(override=True)
    parser = build_parser()
    args = parser.parse_args(argv)

    print("=" * 64)
    print("T4 — AI-augmented static code analysis")
    print("=" * 64)
    print(f"  Source tree     : {args.webgoat_source}")
    print(f"  Concern         : {args.concern}")
    mode = "MOCK" if args.mock else ("DRY-RUN" if args.dry_run else "LIVE")
    print(f"  Mode            : {mode}")
    if not args.mock:
        print(f"  Triage workers  : {args.triage_workers}")
        print(f"  Max files       : {args.max_files}")
        print(f"  Model           : {args.model}")
    print()

    # ── Mock mode short-circuits everything ────────────────────────
    if args.mock:
        report = _mock_full_report(
            source_root=args.webgoat_source, concern=args.concern,
        )
        _print_and_save_outputs(
            report,
            output_path=Path(args.output),
            rules_out_path=Path(args.rules_out),
            semgrep_raw_path=Path(args.semgrep_raw) if args.semgrep_raw else None,
            semgrep_raw_dict={"results": [], "mock": True},
        )
        return 0

    # ── Resolve source tree ────────────────────────────────────────
    try:
        webgoat_root = resolve_webgoat_root(args.webgoat_source)
    except FileNotFoundError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    print(f"[walk] enumerating target files under {webgoat_root}")
    fs = collect_target_files(root=webgoat_root, max_files=args.max_files)
    print(render_fileset_for_terminal(fs, root=webgoat_root))
    if fs.truncated:
        print(
            f"[warn] --max-files {args.max_files} truncated the file list. "
            f"Raise the cap for engagement-grade scans."
        )
    print()

    # ── Phase 1: rule generation ───────────────────────────────────
    print("[rule] generating semgrep rule from concern via Claude...")
    try:
        rule = generate_rule(
            concern=args.concern, model=args.model, api_key=args.api_key,
        )
    except RuleGenerationError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    print(render_rule_for_terminal(rule))
    rules_path = Path(args.rules_out)
    rules_path.write_text(rule.yaml_body, encoding="utf-8")
    print(f"[ok] semgrep rule written to {rules_path}")
    print()

    # ── Phase 2: semgrep ───────────────────────────────────────────
    print(f"[semgrep] running rule across {len(fs.files)} file(s)...")
    try:
        semgrep_result = run_semgrep(
            rule_yaml=rule.yaml_body,
            target_dir=webgoat_root,
            rules_file_path=rules_path,
            max_files=args.max_files,
        )
    except (SemgrepMissingError, SemgrepRunError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    findings = semgrep_result.findings
    print(f"[semgrep] {len(findings)} raw finding(s).")
    if args.semgrep_raw:
        import json as _json
        Path(args.semgrep_raw).write_text(
            _json.dumps(semgrep_result.raw_json, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[ok] raw semgrep JSON written to {args.semgrep_raw}")
    print(render_findings_for_terminal(findings, limit=5))
    print()

    if args.dry_run:
        print(
            "[dry-run] Skipping triage + synthesis. Re-run without --dry-run "
            "for the AI-triaged report."
        )
        return 0

    if not findings:
        print(
            "[ok] No semgrep findings; nothing to triage. Try a broader "
            "concern, raise --max-files, or point --webgoat-source at a "
            "different code tree."
        )
        return 0

    # ── Phase 3: triage (parallel map) ─────────────────────────────
    print(
        f"[triage] triaging {len(findings)} finding(s) in parallel "
        f"(workers={args.triage_workers})..."
    )

    def _on_done(done: int, total: int, triaged):
        verdict = triaged.verdict.exploitability
        f = triaged.finding
        print(f"  [{done}/{total}] {verdict:>16}  {f.file_path}:{f.start_line}")

    try:
        triaged = triage_all(
            findings=findings,
            concern=args.concern,
            source_root=webgoat_root,
            workers=args.triage_workers,
            model=args.model,
            api_key=args.api_key,
            progress_callback=_on_done,
        )
    except TriageError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    print()

    # ── Phase 4: synthesis (reduce) ────────────────────────────────
    print("[synth] consolidating triaged findings into the executive report...")
    try:
        synth = synthesise(
            triaged=triaged,
            concern=args.concern,
            rule_yaml=rule.yaml_body,
            model=args.model,
            api_key=args.api_key,
        )
    except SynthesisError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    print()

    report = FullReport(
        target=f"{webgoat_root} ({len(fs.files)} files scanned)",
        concern=args.concern,
        rule=rule,
        triaged=triaged,
        synthesis=synth,
    )
    _print_and_save_outputs(
        report,
        output_path=Path(args.output),
        rules_out_path=rules_path,
        semgrep_raw_path=None,  # already saved above
        semgrep_raw_dict=None,
    )
    return 0


def _print_and_save_outputs(
    report: FullReport,
    *,
    output_path: Path,
    rules_out_path: Path,
    semgrep_raw_path: Path | None,
    semgrep_raw_dict: dict | None,
) -> None:
    """Persist all artefacts to disk and print the terminal view."""
    save_report(report, output_path)
    if semgrep_raw_path is not None and semgrep_raw_dict is not None:
        import json as _json
        semgrep_raw_path.write_text(
            _json.dumps(semgrep_raw_dict, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[ok] mock semgrep JSON written to {semgrep_raw_path}")
    if not rules_out_path.exists():
        rules_out_path.write_text(report.rule.yaml_body, encoding="utf-8")
        print(f"[ok] semgrep rule written to {rules_out_path}")
    print()
    print("─── T4 report " + "─" * 48)
    print(render_for_terminal(report))
    print("─" * 60)
    print(f"\n[ok] Structured report saved to {output_path}")


# ─── Mock fixtures ──────────────────────────────────────────────────────────

# Mirrors T2's mock-fixture pattern — canned data lets the CLI exercise the
# whole pipeline shape without semgrep installed and without API spend. The
# shipped fixtures cover the SQLi concern (callback to T2's running-app
# attack) at a depth that lets readers see what a real run would produce.

_MOCK_RULE_YAML = """\
rules:
  - id: tutorial-04/sqli-jdbc-user-input
    message: User input concatenated into a JDBC statement — classic SQLi sink.
    languages: [java]
    severity: ERROR
    pattern-either:
      - pattern: |
          $STMT.executeQuery($Q)
      - pattern: |
          $STMT.executeUpdate($Q)
      - pattern: |
          $STMT.execute($Q)
    pattern-not-inside: |
      $X.prepareStatement($Q)
"""


def _mock_full_report(*, source_root: str, concern: str) -> FullReport:
    """Build a FullReport using canned fixtures.

    Matches the shape of a real run against WebGoat's SQLi lessons —
    covers lesson 5a (numeric, sqlmap-confirmed in T2), lesson 5b
    (another numeric variant), and one false-positive to show triage
    catches over-broad pattern matches.
    """
    rule = GeneratedRule(
        rule_id="tutorial-04/sqli-jdbc-user-input",
        yaml_body=_MOCK_RULE_YAML,
        rationale=(
            "Matches any Statement.execute*() call whose argument isn't "
            "supplied by prepareStatement — covers the classic "
            "string-concatenation SQLi shape."
        ),
    )

    fixtures = [
        (
            SemgrepFinding(
                rule_id="tutorial-04/sqli-jdbc-user-input",
                file_path="src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java",
                start_line=73, end_line=73,
                matched_code='statement.executeQuery("SELECT * FROM user_data WHERE userid = " + accountName)',
                message="User input concatenated into a JDBC statement — classic SQLi sink.",
                severity="ERROR",
            ),
            TriageVerdict(
                exploitability="high",
                rationale=(
                    "Direct concatenation of `accountName` (from request.getParameter) "
                    "into a Statement.executeQuery — classic textbook SQLi."
                ),
                exploitation_guidance=(
                    "Send `account=1 UNION ALL SELECT NULL,...` to "
                    "/SqlInjection/assignment5a to dump the user_data table — "
                    "the exact payload sqlmap landed in T2."
                ),
            ),
        ),
        (
            SemgrepFinding(
                rule_id="tutorial-04/sqli-jdbc-user-input",
                file_path="src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5b.java",
                start_line=80, end_line=80,
                matched_code='statement.execute("SELECT * FROM user_data WHERE login_count = " + loginCount + " AND userid = " + accountName)',
                message="User input concatenated into a JDBC statement — classic SQLi sink.",
                severity="ERROR",
            ),
            TriageVerdict(
                exploitability="high",
                rationale=(
                    "Two user-controlled values (login_count, userid) "
                    "concatenated into one query — same shape as 5a."
                ),
                exploitation_guidance=(
                    "Inject via `userid` (login_count is integer-typed and "
                    "less convenient); same UNION payload as 5a works."
                ),
            ),
        ),
        (
            SemgrepFinding(
                rule_id="tutorial-04/sqli-jdbc-user-input",
                file_path="src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionAdvanced.java",
                start_line=42, end_line=42,
                matched_code='statement.execute(initSql)',
                message="User input concatenated into a JDBC statement — classic SQLi sink.",
                severity="ERROR",
            ),
            TriageVerdict(
                exploitability="false-positive",
                rationale=(
                    "`initSql` is a hard-coded schema-setup string used "
                    "during lesson bootstrap; no user input reaches this sink."
                ),
                exploitation_guidance=None,
            ),
        ),
    ]

    triaged = [
        TriagedFinding(
            finding=f, verdict=v,
            code_context="(mock fixture — no actual code read)",
        )
        for f, v in fixtures
    ]

    synth = SynthesisedReport(
        headline=(
            "Critical — WebGoat exposes two textbook SQL-injection sinks in "
            "the introductory lesson set. Equivalent patterns in production "
            "would compromise the user table on first request."
        ),
        executive_summary=(
            "Scanned the WebGoat introductory SQL injection lesson package "
            "for the concatenation-into-JDBC pattern. Two high-confidence "
            "true positives (lessons 5a + 5b) match the bug class exactly "
            "and reproduce T2's sqlmap exploitation; one false-positive "
            "fires on schema-setup boilerplate. Action: replace the "
            "concatenation sites with PreparedStatement bind parameters. "
            "WebGoat lessons are intentionally vulnerable; the same pattern "
            "in production code is critical-by-default."
        ),
        confirmed_high=[
            FindingHeadline(
                file_path=triaged[0].finding.file_path,
                line=triaged[0].finding.start_line,
                exploitability="high",
                headline="SQLi via Statement.executeQuery on `accountName` from request",
            ),
            FindingHeadline(
                file_path=triaged[1].finding.file_path,
                line=triaged[1].finding.start_line,
                exploitability="high",
                headline="SQLi via Statement.execute on `userid` + `login_count` concatenation",
            ),
        ],
        confirmed_medium=[],
        low_and_false_positives=[
            FindingHeadline(
                file_path=triaged[2].finding.file_path,
                line=triaged[2].finding.start_line,
                exploitability="false-positive",
                headline="rule fires on schema-bootstrap SQL with no user input",
            ),
        ],
    )

    return FullReport(
        target=f"{source_root} (mock fixture)",
        concern=concern,
        rule=rule,
        triaged=triaged,
        synthesis=synth,
    )


__all__ = ["build_parser", "main"]
