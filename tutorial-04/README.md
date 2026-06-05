# Tutorial 04 — AI-Augmented Static Code Analysis

Companion code for *AI for Cybersecurity Fundamentals* Tutorial 4.

You hand the tool an English security concern (*"Find SQL injection patterns where user input flows into JDBC queries"*). Claude translates it into a [semgrep](https://semgrep.dev/) YAML rule. Semgrep runs the rule across the source tree (WebGoat in the demo). Claude triages every match by exploitability. You get a structured JSON report plus a compact terminal view.

Three Claude calls; one map-reduce. Pattern detection is deterministic (semgrep). Rule authoring and exploitability judgment are AI (Claude).

## Why this shape — *and not "just feed the codebase to Claude"*

The plan dedicates a section ([plans/aifc-t4-source-code-analysis.md § Decisions #3](../../../plans/aifc-t4-source-code-analysis.md)) to justifying this architecture against the obvious alternative of giving Claude the whole codebase in one prompt. Short version:

| Dimension | Option A (whole codebase to Claude) | Option B (this tool — semgrep + Claude triage) |
| --- | --- | --- |
| Scaling | Works on ~5k LOC. Breaks on 50k+. | Linear in findings, not codebase size. |
| Cost per run | ~$0.20 (180k input tokens at Haiku rates) | ~$0.03–0.05 (15-25k tokens total) |
| Determinism | Non-deterministic — same input → different findings | Semgrep findings deterministic; only triage varies |
| Right-tool-right-job | Asks Claude to do pattern matching (weakness) AND judgment (strength) | Each tool plays to its strength |
| Reusable artefacts | Nothing left over | Generates `generated_rules.yml` — reusable rule against any codebase |

Plus the series spine: *AI augments traditional tools; it doesn't replace them.* Option A breaks that mental model.

## Installation

```bash
# From this directory
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env          # then edit .env with your ANTHROPIC_API_KEY
```

semgrep is a separate binary — install via `pip install semgrep` (in the same venv) or your package manager.

## Quick start

```bash
# Clone WebGoat once (≈100 MB, Java/Spring-Boot):
git clone https://github.com/WebGoat/WebGoat ~/Sources/WebGoat

# Smoke-test the pipeline without any API spend or semgrep install:
python -m tutorial_04 \
    --webgoat-source tests/fixtures/webgoat \
    --concern "Find SQL injection patterns where user input flows into JDBC queries" \
    --mock

# Real run — first concern (SQL injection, the headline demo):
python -m tutorial_04 \
    --webgoat-source ~/Sources/WebGoat \
    --concern "Find SQL injection patterns where user input flows into JDBC queries"

# Second concern (path traversal, the "pipeline isn't sqli-specific" beat):
python -m tutorial_04 \
    --webgoat-source ~/Sources/WebGoat \
    --concern "Find path traversal patterns where filesystem paths are constructed from user input."
```

Both concerns ship in [`concerns.example.txt`](concerns.example.txt). Write your own to point the pipeline at your own codebases.

## What lands on disk

After a real run:

- **`report.json`** — structured report. The canonical artefact; the terminal view is just a summary.
- **`generated_rules.yml`** — the semgrep rule Claude authored. Re-runnable against any codebase: `semgrep --config=generated_rules.yml /path/to/code/`. The reusable take-home.
- **`semgrep_raw.json`** — semgrep's raw output, pre-triage. Useful for diffing against the triaged report.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--webgoat-source PATH` | *(required)* | Path to the cloned WebGoat repo (or any Java source tree to analyse). |
| `--concern TEXT` | *(required)* | The English security concern, in quotes. |
| `--triage-workers N` | 8 | Max concurrent Claude calls during the per-finding map phase. Lower for Anthropic free-tier rate limits. |
| `--max-files N` | 200 | Cap on number of source files semgrep scans. Demo-scoping; raise for engagement-grade runs. |
| `--model NAME` | `claude-haiku-4-5` | Claude model for ALL three calls (rule gen, triage, synth). |
| `--output PATH` | `report.json` | Where to write the structured triaged report. |
| `--rules-out PATH` | `generated_rules.yml` | Where to write the semgrep rule Claude authored. |
| `--dry-run` | off | Run rule generator + semgrep; skip the Claude triage + synthesis. Useful for checking the semgrep step in isolation. |
| `--mock` | off | Skip semgrep AND skip Claude. Uses fixture data — for smoke tests. |

## Three Claude calls — what each is doing

1. **Rule generator** ([rule_generator.py](tutorial_04/rule_generator.py)). *"Translate this English concern into a semgrep YAML rule."* Forced JSON via tool-use; the schema validates the YAML structure semgrep expects. ~500 input tokens, ~150 output.
2. **Per-finding triager** ([triager.py](tutorial_04/triager.py)). One Claude call per raw semgrep match; runs in parallel. *"For this specific finding in this file, is it a real bug? Rank exploitability."* Output: `high / medium / low / false-positive` plus a one-sentence rationale and (for non-false-positives) one-line exploitation guidance. ~1k input tokens each, ~150 output, 8–15 concurrent calls.
3. **Synthesiser** ([synthesiser.py](tutorial_04/synthesiser.py)). Single reduce call. *"Across all triaged findings, produce a one-paragraph executive summary and a prioritised list."* ~3k input, ~500 output.

Total budget: ~20–25k tokens per run, ~$0.03–0.05 at Haiku-4.5 rates.

## Smoke testing

```bash
python -m pytest -q
```

Tests are mock-based — no live API, no semgrep install required. The end-to-end test uses `--mock` to exercise the orchestration without touching either tool.

## Lab honesty

WebGoat is built to be vulnerable. The findings semgrep+Claude produce aren't impressive in themselves — the *pattern* is what matters (translate concern → generate rule → triage findings). Run the same pipeline against your own codebase to find unintentional bugs that no one planted.

For licit use of this pipeline against systems you don't own: lab targets and codebases with documented authorisation only. Always.
