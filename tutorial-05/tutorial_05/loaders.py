"""Deterministic preprocessing: parse each tool's report.json into a compact,
noise-free 'evidence pack' — the text Claude actually reads. Trimming here (drop
404 placeholder hosts, the semgrep rule YAML, unconfirmed SQLi detail) keeps the
prompt small and the cost low, exactly like T2's log-compression step.
"""
from __future__ import annotations

import json
from pathlib import Path


def _load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sqli_evidence(d: dict) -> str:
    targets = d.get("targets", [])
    confirmed = [t for t in targets if t.get("vulnerability_confirmed")]
    out = [f"## Dynamic testing — SQL injection (sqlmap): {len(confirmed)}/{len(targets)} confirmed"]
    for t in confirmed:
        line = f"- {t['target_url']} — parameter `{t.get('vulnerable_parameter')}`, {t.get('injection_type')}"
        if t.get("database_engine"):
            line += f", DBMS {t['database_engine']}"
        if t.get("notes"):
            line += f". {t['notes']}"
        out.append(line)
    if d.get("business_impact"):
        out.append(f"- tool verdict: {d['business_impact']}")
    return "\n".join(out)


def sast_evidence(d: dict) -> str:
    counts = d.get("counts", {})
    out = [
        f"## Static analysis — SAST (semgrep + AI). Concern: {d.get('concern')}",
        f"target: {d.get('target')}; findings by exploitability: "
        f"high={counts.get('high', 0)}, medium={counts.get('medium', 0)}, low={counts.get('low', 0)}",
    ]
    for f in d.get("findings", []):
        line = (f"- {f.get('file')}:{f.get('line')} — exploitability {f.get('exploitability')} — "
                f"{f.get('rationale')}")
        if f.get("exploitation_guidance"):
            line += f" Exploit path: {f['exploitation_guidance']}"
        out.append(line)
    if d.get("executive_summary"):
        out.append(f"- tool summary: {d['executive_summary']}")
    return "\n".join(out)


def subdomain_evidence(d: dict) -> str:
    hosts = d.get("hosts", [])
    notable = [h for h in hosts if h.get("live_web") and h.get("priority") in ("high", "medium")]
    counts = d.get("counts", {})
    out = [f"## Attack surface — subdomain enumeration of {d.get('root_domain')} "
           f"({counts.get('live_web', len(hosts))} live hosts)"]
    if d.get("headline"):
        out.append(f"headline: {d['headline']}")
    for h in notable:
        out.append(f"- {h['host']} [{h.get('priority')}] HTTP {h.get('status_code')} "
                   f"\"{h.get('title')}\" — {h.get('value')}")
    low = sum(1 for h in hosts if h.get("priority") == "low")
    if low:
        out.append(f"- plus {low} low-priority / placeholder hosts (mostly HTTP 404).")
    return "\n".join(out)


def build_evidence(*, sqli: str | None = None, subdomains: str | None = None,
                   sast: str | None = None) -> str:
    """Load whichever inputs are provided, in report order: recon -> dynamic -> static."""
    parts = []
    if subdomains:
        parts.append(subdomain_evidence(_load(subdomains)))
    if sqli:
        parts.append(sqli_evidence(_load(sqli)))
    if sast:
        parts.append(sast_evidence(_load(sast)))
    if not parts:
        raise ValueError("No inputs provided (need at least one of --sqli/--subdomains/--sast).")
    return "\n\n".join(parts)


__all__ = ["build_evidence", "sqli_evidence", "sast_evidence", "subdomain_evidence"]
