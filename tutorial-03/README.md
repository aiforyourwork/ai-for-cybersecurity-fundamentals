# T3 — AI-Augmented Subdomain Enumeration

Companion code for *AI for Cybersecurity Fundamentals* tutorial 3 on the [AI For Your Work](https://www.youtube.com/@AIForYourWork) channel.

A four-stage pipeline that takes a root domain plus a scope file, runs `subfinder` in passive mode, asks Claude to suggest more candidates from the homepage's business context, resolves everything via DNS, sends one HTTP `GET` per resolved host, and asks Claude to rank the live web hosts by likely value.

The AI does two distinct jobs:

1. **Stage 1c — `generator`** reads the target's homepage and proposes subdomain candidates a generic wordlist would never produce (e.g. `careers.`, `status.`, `support.` based on what the homepage actually advertises).
2. **Stage 4 — `ranker`** reads each live host's status + title + server header and assigns a priority (`high` / `medium` / `low`) with a one-line rationale.

Output: a ranked, scope-filtered, deduplicated subdomain list — the kind of opening-night artefact you'd want from a real engagement.

> **Authorised targets only.** This tool runs against bug-bounty wildcards and other engagements you have explicit written authorisation to test. Running it against any system not in your scope is illegal in most jurisdictions. The channel doesn't provide legal advice.

---

## Prerequisites

Setup is fully covered in the [companion blog post](../../../docs/tutorials/ai-for-cybersecurity-fundamentals/Phase1/tutorial_03_enumerate_subdomains_with_ai.md) — this README is the working-reference once everything's installed. Quick summary:

| Tool | Why | Quick install (Ubuntu 24.04) |
| --- | --- | --- |
| Python 3.12+ with `venv` | This package | `sudo apt install python3-venv python3-pip` |
| `subfinder` | Passive enumeration from ~30 public sources (crt.sh, AlienVault OTX, VirusTotal, etc.) | Prebuilt binary from <https://github.com/projectdiscovery/subfinder/releases> — extract and put on PATH |
| Anthropic API key | Claude does the candidate generation + ranking | <https://console.anthropic.com> — set as `ANTHROPIC_API_KEY` in `.env` |

## Configure the CLI

Copy `.env.example` to `.env` and fill in the API key:

```env
ANTHROPIC_API_KEY=sk-ant-...
```

Create a virtual env and install the Python deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Scope file — the safety hinge

The `--scope <path>` flag is **mandatory**. The scope file lists the wildcard patterns your engagement authorises; everything outside is hard-filtered before any network call.

Copy the example and edit:

```bash
cp scope.example.txt scope.txt
# scope.txt — one pattern per line
*.hackerone.com
```

Patterns use the shell-glob form supported by Python's `fnmatch`:

- `*.example.com` — any subdomain of example.com.
- `*.dev.example.com` — any subdomain of dev.example.com.
- `exact.example.com` — only the exact host.

There is no "default scope = everything" mode. The CLI refuses to run without `--scope`.

**Before recording or publishing:** verify the program's scope page on HackerOne / Bugcrowd / Intigriti still includes the wildcard you've listed. Bug-bounty scopes drift.

## Run it

### Mock (no network, no API spend)

Use the `.test`-TLD demo target shipped with the package — fully offline, useful for development:

```bash
echo "*.demo-target.test" > scope.demo.txt

python -m tutorial_03 \
  --domain demo-target.test \
  --scope scope.demo.txt \
  --mock
```

This produces the same funnel shape the live pipeline does, with deliberately interesting fixture findings (a Swagger-UI hit, an auth-protected admin login, plus the usual marketing/CDN noise).

### Dry-run (real subfinder + DNS + HTTP, no Claude)

Skips both Claude calls but exercises every deterministic stage:

```bash
python -m tutorial_03 \
  --domain hackerone.com \
  --scope scope.txt \
  --dry-run
```

Useful for verifying subfinder works, the homepage fetches, and DNS/HTTP latencies are sensible before paying for the AI calls. Zero LLM cost.

### Live run

```bash
python -m tutorial_03 \
  --domain hackerone.com \
  --scope scope.txt
```

The four-stage funnel:

```
─── Stage 1: candidate generation ───
  subfinder       :   61 candidate(s)
  claude          :   17 candidate(s) (net-new after dedupe)
  total unique    :   78
  (dropped out-of-scope: 0)
─── Stage 2: DNS resolution ────────
  resolved        :   41 / 78
─── Stage 3: HTTP verification ─────
  live web        :   34 / 41
─── Stage 4: AI ranking ────────────
  ranked          :   34 host(s)

  [high]
    api-dev.hackerone.com       200   Swagger UI exposed; non-prod API
    staging.hackerone.com       401   Auth-required non-prod env
  [medium]
    portal.hackerone.com        200   Customer auth surface
    ...
  [low]
    docs.hackerone.com          200   Docs site (CDN)
    ...

Headline: <one-sentence summary from the ranker>
```

The structured JSON form of the same report is saved to `report.json` for later programmatic use.

## CLI flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--domain` | — *(required)* | Root domain to enumerate, e.g. `hackerone.com`. No scheme. |
| `--scope` | — *(required)* | Path to the scope file. Hard-filters out-of-scope candidates before any network call. |
| `--max-from-passive` | `60` | Cap subfinder output. Pass `0` to disable. |
| `--max-from-claude` | `25` | Max candidates the AI generator returns. |
| `--no-verify` | off | Skip Stage 3 (HTTP probes). Resolved hosts go straight to the ranker. True zero-touch passive mode. |
| `--model` | `claude-haiku-4-5` | Claude model for both AI calls. |
| `--api-key` | — | Override `ANTHROPIC_API_KEY` from env. |
| `--output` | `report.json` | Where to write the structured JSON report. |
| `--raw-log` | `subfinder.log` | Where to write the raw subfinder output (audit trail). Pass `""` to skip. |
| `--dry-run` | off | Run subfinder + homepage + DNS + (optional) HTTP, but skip both Claude calls. Zero LLM cost. |
| `--mock` | off | Skip every external dependency. Uses canned fixtures. |

## Cost

| Step | Wall time | Cost |
| --- | --- | --- |
| subfinder (passive) | 5–30 sec | free |
| Homepage fetch + DNS resolution | 5–15 sec | free |
| HTTP verification (~40 hosts, ~6 sec timeout, 12 workers) | 5–20 sec | free |
| Claude generator (Haiku) | 2–4 sec | ~$0.005 |
| Claude ranker (Haiku) | 2–4 sec | ~$0.01 |

Total: ~$0.01–0.03 per run.

## How it works (pointers into the code)

- [`tutorial_03/scope.py`](tutorial_03/scope.py) — pure-function scope parser + `Scope.matches` + `Scope.permits_root`. The safety hinge; refuses files with `*` (would match every host).
- [`tutorial_03/subfinder_runner.py`](tutorial_03/subfinder_runner.py) — subprocess wrapping `subfinder -d <domain> -silent`. Parses stdout into a deduplicated, lower-cased tuple.
- [`tutorial_03/homepage.py`](tutorial_03/homepage.py) — fetches `https://<domain>/`, falls back to HTTP, strips scripts/styles/noscript, truncates the cleaned text to ~6000 chars for the generator prompt.
- [`tutorial_03/generator.py`](tutorial_03/generator.py) — Claude call #1. Forced output via tool-use; `CandidateSubdomain.host` ends with the root domain or it's dropped.
- [`tutorial_03/resolver.py`](tutorial_03/resolver.py) — stdlib `socket.getaddrinfo` in a thread pool. No `dnspython` dep.
- [`tutorial_03/verifier.py`](tutorial_03/verifier.py) — one `GET` per resolved host with a benign UA. Captures status, title, server header. Skipped under `--no-verify`.
- [`tutorial_03/ranker.py`](tutorial_03/ranker.py) — Claude call #2. Priority is a `Literal["high", "medium", "low"]` so the SDK validates the value.
- [`tutorial_03/report.py`](tutorial_03/report.py) — Pydantic `Report` schema + the terminal funnel renderer.
- [`tutorial_03/cli.py`](tutorial_03/cli.py) — argparse + orchestration. The `_run_mock` function at the bottom is the fixture pipeline used by `--mock`.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The shipped tests cover the scope safety hinge (case-folding, trailing-dot handling, wildcard match scope, `*`-refusal), the subfinder output parser, the homepage HTML cleaner, the generator schema + root-filter, the ranker schema + priority sort, the resolver against localhost, the verifier's title regex, and the CLI end-to-end via `--mock`. No tests hit the network or the Claude API.

## License

MIT. See [LICENSE](LICENSE).
