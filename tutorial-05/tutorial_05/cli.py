"""CLI: consolidate T2/T3/T4 report.json into an assessment report (md/html/json[/pdf])."""
from __future__ import annotations

import argparse
import os
import sys
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

from .analyst import DEFAULT_MODEL, AnalystError, analyse
from .loaders import build_evidence
from .render import render_html, render_markdown, render_pdf


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m tutorial_05",
                                description="Turn Phase-1 tool output into a client assessment report.")
    p.add_argument("--sqli", help="Path to T2 SQLi report.json")
    p.add_argument("--subdomains", help="Path to T3 subdomain report.json")
    p.add_argument("--sast", help="Path to T4 SAST report.json")
    p.add_argument("--client", default="Client")
    p.add_argument("--engagement", default="Phase-1 security assessment")
    p.add_argument("--date", default=None, help="Report date (YYYY-MM-DD; default: today).")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--api-key", default=None)
    p.add_argument("--output", default="assessment", help="Output path prefix (writes .json/.md/.html[/.pdf]).")
    p.add_argument("--pdf", action="store_true", help="Also render a PDF (needs WeasyPrint).")
    p.add_argument("--mock", action="store_true", help="Offline: render a canned assessment (no API key).")
    return p


def main(argv: list[str] | None = None) -> int:
    load_dotenv(override=True)
    args = build_parser().parse_args(argv)
    on_date = args.date or date.today().isoformat()

    if args.mock:
        from .fixtures import MOCK_ASSESSMENT as assessment
    else:
        if not (args.sqli or args.subdomains or args.sast):
            print("[error] provide at least one of --sqli / --subdomains / --sast (or --mock).",
                  file=sys.stderr)
            return 2
        try:
            evidence = build_evidence(sqli=args.sqli, subdomains=args.subdomains, sast=args.sast)
            print(f"[analyst] consolidating {len(evidence):,} chars of evidence via {args.model}...")
            assessment = analyse(evidence, client_name=args.client, engagement=args.engagement,
                                 model=args.model, api_key=args.api_key)
        except (AnalystError, ValueError, FileNotFoundError) as exc:
            print(f"[error] {exc}", file=sys.stderr)
            return 1

    prefix = Path(os.path.expanduser(args.output))
    if prefix.parent and not prefix.parent.exists():
        prefix.parent.mkdir(parents=True, exist_ok=True)

    kw = dict(client=args.client, engagement=args.engagement, on_date=on_date)
    prefix.with_suffix(".json").write_text(assessment.model_dump_json(indent=2), encoding="utf-8")
    prefix.with_suffix(".md").write_text(render_markdown(assessment, **kw), encoding="utf-8")
    html_str = render_html(assessment, **kw)
    prefix.with_suffix(".html").write_text(html_str, encoding="utf-8")

    written = [prefix.with_suffix(s) for s in (".json", ".md", ".html")]
    if args.pdf:
        try:
            render_pdf(html_str, prefix.with_suffix(".pdf"))
            written.append(prefix.with_suffix(".pdf"))
        except RuntimeError as exc:
            print(f"[warn] PDF skipped: {exc}", file=sys.stderr)

    print(f"\n=== Assessment: {assessment.overall_severity} - {len(assessment.findings)} finding(s) ===")
    for f in assessment.findings:
        print(f"  [{f.severity:<8}] {f.title}")
    print("\n[ok] wrote: " + ", ".join(str(p) for p in written))
    print("      Review and sign off before sharing.")
    return 0


__all__ = ["build_parser", "main"]
