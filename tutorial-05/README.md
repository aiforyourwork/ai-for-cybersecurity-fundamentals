# T5 — AI-Assisted Security Assessment Report

Companion code for *AI for Cybersecurity Fundamentals* Tutorial 5.

Reporting is the deliverable a client pays for — and it's the biggest time sink in an
engagement. This tool takes the `report.json` outputs from the earlier tutorials —
**T2 (SQLi, dynamic)**, **T3 (subdomain recon)**, **T4 (SAST, static)** — normalizes and
de-noises them, and makes **one Claude call** to produce a consolidated, prioritized
assessment: an executive summary, per-finding severity + CWE/OWASP/MITRE ATT&CK +
remediation, and an attack-surface summary. Output as **Markdown, styled HTML, JSON, and
(optionally) a client-ready PDF**.

> **AI drafts; you sign off.** Never ship an unreviewed security report — the AI can
> mis-classify or hallucinate. The tool stamps every report with a review line.

## What it does — a straight line, not an "orchestrator"
1. **Load** the three `report.json` files.
2. **Normalize + de-noise** them into a compact evidence pack (drops 404 hosts, the semgrep
   rule YAML, unconfirmed detail).
3. **One Claude call** (forced tool-use → a Pydantic `Assessment`): severity, CWE/OWASP/ATT&CK,
   remediation, exec summary — and it **correlates** the static + dynamic SQLi into one
   high-confidence finding instead of double-counting.
4. **Render** → `assessment.{json,md,html}` and, with `--pdf`, `assessment.pdf`.

## Install (Ubuntu 24.04)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env        # add ANTHROPIC_API_KEY

# For PDF output (optional):
pip install -e ".[pdf]"     # WeasyPrint
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev libcairo2
```

## Run
```bash
# Offline sanity check (no key, no PDF) — renders a canned report:
python -m tutorial_05 --mock --output assessment

# Real run against your Phase-1 outputs:
python -m tutorial_05 \
    --sqli       ~/aifc/out/sqli.json \
    --subdomains ~/aifc/out/subdomains.json \
    --sast       ~/aifc/out/sast.json \
    --client "Acme Corp" --engagement "Phase-1 assessment" \
    --pdf --output ~/aifc/out/assessment
```
Writes `assessment.json`, `assessment.md`, `assessment.html`, and (with `--pdf`)
`assessment.pdf`. Provide any subset of `--sqli/--subdomains/--sast`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--sqli` / `--subdomains` / `--sast` | — | Paths to the T2 / T3 / T4 `report.json` (≥1 required) |
| `--client` / `--engagement` | `Client` / `Phase-1 security assessment` | Report header |
| `--date` | today | Report date |
| `--model` | `claude-haiku-4-5` | `--model claude-opus-4-8` for a richer exec narrative |
| `--output` | `assessment` | Output path **prefix** |
| `--pdf` | off | Also render a PDF (needs WeasyPrint) |
| `--mock` | off | Offline canned report (no key) |

## Cost
One Haiku call over a few KB of evidence → ~1–2¢ per report. The finding *facts* come from
the deterministic tools; only the narrative varies between runs.
