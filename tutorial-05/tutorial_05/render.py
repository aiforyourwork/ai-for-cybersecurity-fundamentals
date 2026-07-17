"""Render an Assessment to Markdown, styled HTML, and (optionally) PDF."""
from __future__ import annotations

import html as _html
import re
from collections import Counter
from pathlib import Path

from .schemas import Assessment, Finding

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
SEV_COLOR = {"Critical": "#b3261e", "High": "#c0362c", "Medium": "#9a6b00",
             "Low": "#1a7f4b", "Informational": "#5b6b86"}


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9))


def _sev_counts(a: Assessment) -> str:
    c = Counter(f.severity for f in a.findings)
    return " · ".join(f"{k}: {c.get(k, 0)}" for k in ["Critical", "High", "Medium", "Low", "Informational"] if c.get(k))


def _fw(cwe, owasp, attack) -> str:
    bits = [x for x in (cwe, owasp, (", ".join(attack) if attack else None)) if x]
    return " · ".join(bits) or "—"


def _denum(s: str) -> str:
    """Drop any leading '1. ' / '2) ' the model added — the renderer numbers the list itself."""
    return re.sub(r"^\s*\d+[.)]\s*", "", (s or "").strip())


# ── Markdown ────────────────────────────────────────────────────────────────
def render_markdown(a: Assessment, *, client: str, engagement: str, on_date: str) -> str:
    L: list[str] = []
    w = L.append
    w(f"# Security Assessment — {client}")
    w("")
    w(f"**Engagement:** {engagement}  ")
    w(f"**Date:** {on_date}  ")
    w(f"**Overall severity:** {a.overall_severity}")
    w("")
    w("> _AI-assisted draft — must be reviewed and signed off by a human before release._  ")
    w("> Reviewed by: ______________________  Date: __________")
    w("")
    w("## Executive summary")
    w("")
    w(a.executive_summary.strip())
    w("")
    w("## Findings")
    w("")
    w("| # | Severity | Confidence | Finding | Asset | CWE / OWASP / ATT&CK |")
    w("| --- | --- | --- | --- | --- | --- |")
    for i, f in enumerate(_ordered(a.findings), 1):
        w(f"| {i} | {f.severity} | {f.confidence} | {f.title} | `{f.asset}` | {_fw(f.cwe, f.owasp, f.mitre_attack)} |")
    w("")
    for i, f in enumerate(_ordered(a.findings), 1):
        w(f"### F{i}. {f.title}")
        w(f"*{f.severity} · confidence {f.confidence} · {f.source}*")
        w("")
        w(f"- **Asset:** `{f.asset}`")
        w(f"- **Classification:** {_fw(f.cwe, f.owasp, f.mitre_attack)}")
        w(f"- **Evidence:** {f.evidence}")
        w(f"- **Remediation:** {f.remediation}")
        w("")
    if a.attack_surface_notes:
        w("## Attack surface")
        w("")
        w(a.attack_surface_notes.strip())
        w("")
    if a.recommendations:
        w("## Recommendations")
        w("")
        for r in a.recommendations:
            w(f"1. {_denum(r)}")
        w("")
    w("## Methodology & scope")
    w("")
    w("Findings were produced by automated tools — dynamic SQL-injection testing (sqlmap), "
      "static code analysis (semgrep with AI-authored rules), and external attack-surface "
      "enumeration — against authorised lab targets. The tool output was consolidated and "
      "prioritized by a language model and **reviewed by a human analyst** before release. "
      "Severities reflect the real-world impact of each pattern.")
    w("")
    return "\n".join(L)


# ── HTML (styled, print-ready) ──────────────────────────────────────────────
_CSS = """
@page { size: A4; margin: 22mm 18mm; @bottom-center { content: "Confidential — " counter(page); font-size: 9px; color: #888; } }
* { box-sizing: border-box; }
body { font: 12px/1.5 "Helvetica Neue", Arial, sans-serif; color: #1a2233; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 22px 0 8px; border-bottom: 2px solid #e1e7f0; padding-bottom: 4px; }
h3 { font-size: 13px; margin: 16px 0 4px; }
.meta { color: #5b6b86; font-size: 12px; }
.review { background: #fff8e8; border-left: 4px solid #9a6b00; padding: 8px 12px; margin: 12px 0; font-size: 11px; }
.badge { display: inline-block; color: #fff; padding: 1px 8px; border-radius: 99px; font-size: 10px; font-weight: 700; }
table { border-collapse: collapse; width: 100%; font-size: 11px; margin: 8px 0; }
th, td { border: 1px solid #e1e7f0; padding: 5px 7px; text-align: left; vertical-align: top; }
th { background: #f0f4fa; }
code { background: #eef2f8; padding: 1px 4px; border-radius: 4px; font-size: 10.5px; }
.finding { border: 1px solid #e1e7f0; border-left: 4px solid #ccc; border-radius: 6px; padding: 8px 12px; margin: 8px 0; }
.finding p { margin: 3px 0; }
.rec { margin: 4px 0; }
.small { color: #5b6b86; font-size: 10px; }
"""


def _esc(s) -> str:
    return _html.escape(str(s or ""))


def render_html(a: Assessment, *, client: str, engagement: str, on_date: str) -> str:
    P: list[str] = []
    w = P.append
    w(f"<h1>Security Assessment — {_esc(client)}</h1>")
    w(f"<p class='meta'>Engagement: {_esc(engagement)} · Date: {_esc(on_date)} · "
      f"Overall severity: <span class='badge' style='background:{SEV_COLOR.get(a.overall_severity,'#5b6b86')}'>"
      f"{_esc(a.overall_severity)}</span></p>")
    w(f"<p class='small'>{_esc(_sev_counts(a))}</p>")
    w("<div class='review'><b>AI-assisted draft.</b> Must be reviewed and signed off by a human "
      "analyst before release. Reviewed by: ____________________ &nbsp; Date: __________</div>")
    w("<h2>Executive summary</h2>")
    w(f"<p>{_esc(a.executive_summary.strip())}</p>")

    w("<h2>Findings</h2>")
    w("<table><tr><th>#</th><th>Severity</th><th>Conf.</th><th>Finding</th><th>Asset</th>"
      "<th>CWE / OWASP / ATT&amp;CK</th></tr>")
    ordered = _ordered(a.findings)
    for i, f in enumerate(ordered, 1):
        w(f"<tr><td>{i}</td>"
          f"<td><span class='badge' style='background:{SEV_COLOR.get(f.severity,'#5b6b86')}'>{_esc(f.severity)}</span></td>"
          f"<td>{_esc(f.confidence)}</td><td>{_esc(f.title)}</td>"
          f"<td><code>{_esc(f.asset)}</code></td><td>{_esc(_fw(f.cwe, f.owasp, f.mitre_attack))}</td></tr>")
    w("</table>")

    for i, f in enumerate(ordered, 1):
        w(f"<div class='finding' style='border-left-color:{SEV_COLOR.get(f.severity,'#ccc')}'>")
        w(f"<h3>F{i}. {_esc(f.title)} "
          f"<span class='badge' style='background:{SEV_COLOR.get(f.severity,'#5b6b86')}'>{_esc(f.severity)}</span></h3>")
        w(f"<p class='small'>confidence {_esc(f.confidence)} · {_esc(f.source)}</p>")
        w(f"<p><b>Asset:</b> <code>{_esc(f.asset)}</code></p>")
        w(f"<p><b>Classification:</b> {_esc(_fw(f.cwe, f.owasp, f.mitre_attack))}</p>")
        w(f"<p><b>Evidence:</b> {_esc(f.evidence)}</p>")
        w(f"<p><b>Remediation:</b> {_esc(f.remediation)}</p>")
        w("</div>")

    if a.attack_surface_notes:
        w("<h2>Attack surface</h2>")
        w(f"<p>{_esc(a.attack_surface_notes.strip())}</p>")
    if a.recommendations:
        w("<h2>Recommendations</h2><ol>")
        for r in a.recommendations:
            w(f"<li class='rec'>{_esc(_denum(r))}</li>")
        w("</ol>")
    w("<h2>Methodology &amp; scope</h2>")
    w("<p class='small'>Automated tools — dynamic SQL-injection testing (sqlmap), static code "
      "analysis (semgrep + AI), and external attack-surface enumeration — against authorised lab "
      "targets. Tool output was consolidated and prioritized by a language model and reviewed by "
      "a human analyst before release.</p>")

    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>Security Assessment — {_esc(client)}</title><style>{_CSS}</style></head>"
            f"<body>{''.join(P)}</body></html>")


def render_pdf(html_str: str, out_path: Path) -> None:
    try:
        from weasyprint import HTML
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "PDF output needs WeasyPrint. Install it: `pip install weasyprint` "
            "(Ubuntu also: `sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 "
            "libgdk-pixbuf-2.0-0 libffi-dev libcairo2`)."
        ) from exc
    HTML(string=html_str).write_pdf(str(out_path))


__all__ = ["render_markdown", "render_html", "render_pdf"]
