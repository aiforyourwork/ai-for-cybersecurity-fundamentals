# T2 — Find SQL Injection with AI Assistance

Companion code for *AI for Cybersecurity Fundamentals* tutorial 2 on the [AI For Your Work](https://www.youtube.com/@AIForYourWork) channel.

This is a small Python CLI that drives `sqlmap` against one or more deliberately-vulnerable lab targets (OWASP WebGoat), captures the raw output, and asks Claude to turn that wall of text into a structured analyst report — confirmed vulnerabilities, extracted schemas, sample data, and a plain-English business-impact summary across every target.

The AI's job isn't to find the vulnerabilities (sqlmap does that). It's to **read sqlmap's noisy output across a batch of targets and tell you what it means** in 30 seconds instead of 30 minutes of scrolling. The value scales with the noise: scan one target and you could squint through the log yourself; scan four or five and the analyst earns its keep.

> **Lab targets only. Always.** This technique against any system you don't own or have written authorisation to test is illegal in most jurisdictions. The channel doesn't provide legal advice.

---

## Prerequisites

Setup is fully covered in the [companion blog post](../../../docs/tutorials/ai-for-cybersecurity/Phase1/tutorial_02_find_sqli_with_ai.md) — this README is the working-reference once everything's installed. Quick summary of what you need:

| Tool | Why | Quick install (Ubuntu 24.04) |
| --- | --- | --- |
| Python 3.12+ with `venv` | This package | `sudo apt install python3-venv python3-pip` |
| Docker | Run WebGoat in a container (bundles its own JRE — no Java install on the host) | `sudo apt install docker.io && sudo usermod -aG docker $USER` |
| WebGoat | The lab target | `docker pull webgoat/webgoat` then `docker run -d --name webgoat -p 8080:8080 -p 9090:9090 webgoat/webgoat` |
| sqlmap | The SQLi exploitation tool we drive | `sudo apt install sqlmap` (NOT `pip install` — Ubuntu 24.04's PEP 668 blocks system-wide pip) |
| Anthropic API key | Claude does the interpretation | [console.anthropic.com](https://console.anthropic.com) — set as `ANTHROPIC_API_KEY` in `.env` |

## Start the lab

```bash
docker start webgoat        # if container already exists from a previous run
# OR, first time:
docker run -d --name webgoat -p 8080:8080 -p 9090:9090 webgoat/webgoat
```

WebGoat starts on `http://localhost:8080/WebGoat`. Open it in a browser, register a new user, and log in. (The user persists across `docker stop` / `docker start`, but is wiped on `docker rm`.)

In your browser:

1. Navigate to **(A) Injection → SQL Injection (intro) → Lesson 10 — Try It! Numeric SQL injection** (the default target — `assignment5b`).
2. Open DevTools → **Application → Cookies → http://localhost:8080**. Copy the value of the **`JSESSIONID`** cookie. (Re-grab every time the WebGoat container restarts — the Spring Boot session is in-memory.)

## Configure the CLI

Copy `.env.example` to `.env` and fill in the API key:

```env
ANTHROPIC_API_KEY=sk-ant-...
```

The WebGoat session cookie is **not** stored in `.env` — it expires on every WebGoat restart, so persisting it would cause silent stale-cookie bugs. Each time WebGoat restarts (or after a host reboot), grab the fresh `JSESSIONID` from DevTools and paste it directly into the `--cookie` flag on the next run:

```bash
python -m tutorial_02 ... --cookie "JSESSIONID=<paste-value-here>"
```

Your shell's up-arrow recalls the full command, so you only paste the value once per WebGoat lifetime.

Create a virtual env and install the Python deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Run it

You can point the CLI at one URL (`--url`) or a list of URLs in a plain-text file (`--targets-file`). The multi-target form is the headline demo — it stacks several sqlmap sessions into one giant log, which is where the AI analyst actually earns its keep.

### Multi-target (recommended)

Copy the sample target list and run against the lot:

```bash
cp targets.example.txt targets.txt
# Edit targets.txt if you want to add or drop URLs.

python -m tutorial_02 \
  --targets-file targets.txt \
  --cookie "JSESSIONID=<paste-cookie-value-here>"
```

The shipped `targets.example.txt` scans four WebGoat endpoints in one go: a numeric-SQLi lesson (`assignment5b`), a string-SQLi lesson sqlmap struggles to confirm (`assignment5a`), a later lesson with a different parameter shape, and a parameter-less endpoint as a negative control. Total wall time ~1–3 minutes; total captured output ~1,500–3,000 lines of mixed signal and noise; one analyst call.

The target file format is simple:

```
# Comments and blank lines allowed.
URL                    # GET — sqlmap tests query-string params
URL | DATA             # POST — DATA is application/x-www-form-urlencoded
```

The cookie is **not** per-line — it's passed once via `--cookie` because all WebGoat lessons share one JSESSIONID per logged-in session.

### Single target

For a quick one-off, skip the file:

```bash
python -m tutorial_02 \
  --url "http://localhost:8080/WebGoat/SqlInjection/assignment5b" \
  --data 'login_count=1&userid=1' \
  --cookie "JSESSIONID=<paste-cookie-value-here>"
```

### What the tool does

For each target (one or many):

1. Spawn `sqlmap` with `--batch --dbms=hsqldb --dump`.
2. Capture the full stdout (typically 100–500 lines of `[INFO]` chatter, parameter testing, payload attempts, and finally a schema/table dump).
3. Concatenate the per-target outputs with `=== TARGET k/N: <url> ===` banners between them.
4. Send the whole pile to Claude in **one** call with a security-analyst system prompt.
5. Print a structured report: one finding per target plus an overall summary and business-impact line.

### Example output (shape only — your actual run will differ)

```
─── Raw sqlmap output (4 target(s), 2,184 lines, 84,213 chars) ──
  === TARGET 1/4: http://localhost:8080/WebGoat/SqlInjection/assignment5b ===
  --data: login_count=1&userid=1
  sqlmap exit code: 0

  [INFO] testing connection to the target URL
  ...
  ... (2,154 more lines not shown)
────────────────────────────────────────────────────────────

[analyst] sending 84,213-char sqlmap log across 4 target(s) to Claude for interpretation...

─── AI analyst report ───────────────────────────────────────
Scanned 4 target(s); 2 confirmed injectable, 2 not confirmed.

[1/4] ✓ confirmed — http://localhost:8080/WebGoat/SqlInjection/assignment5b
        Parameter        : userid
        Injection type   : UNION query (NULL) - 7 columns, plus HSQLDB time-based blind
        Database engine  : HSQLDB
        Extracted schema :
          - user_data (5 columns, 14 rows)
              101 / Joe / Snow / 0 / passwd1
        Note             : userid was injectable via UNION; login_count clean.

[2/4] ✗ NOT confirmed — http://localhost:8080/WebGoat/SqlInjection/assignment5a
        Note             : Uniform JSON envelope tripped sqlmap's reflective-value filter.

[3/4] ✓ confirmed — http://localhost:8080/WebGoat/SqlInjection/attack8
        Parameter        : name
        Injection type   : boolean-based blind and UNION query (NULL) - 6 columns
        Database engine  : HSQLDB

[4/4] ✗ NOT confirmed — http://localhost:8080/WebGoat/service/lessonmenu.mvc
        Note             : No parameters present — sqlmap correctly reports nothing to test.

─── Overall summary ─────────────────────────────────
  Two of four endpoints permit unauthenticated database reads via SQL injection.
  The asymmetric treatment — some params parameterised, others concatenated — is
  the realistic finding.

─── Overall business impact ─────────────────────────
  Critical — credential extraction confirmed across two endpoints.
```

The structured JSON form of the same report is saved to `report.json` for later programmatic use (e.g. feeding into a bug-tracker integration in a future tutorial).

## CLI flags

Exactly one of `--url` or `--targets-file` is required.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--targets-file` | — | Path to a plain-text file listing many target URLs (one per line; format `URL` or `URL \| DATA`; `#` comments allowed). Mutually exclusive with `--url`. |
| `--url` | — | Single target URL. Mutually exclusive with `--targets-file`. |
| `--data` | none | POST body for single-URL use. Only valid with `--url` — in the file, put data after `\|` on each line. |
| `--param` | none | Specific parameter to target (sqlmap's `-p`). Only valid with `--url`. Omit for black-box discovery. |
| `--cookie` | none — pass per run | Session cookie for authenticated lab targets, e.g. `--cookie "JSESSIONID=ABC...XYZ"`. Applied to every target. Not read from `.env` — the cookie expires every WebGoat restart, so persisting it is a footgun. |
| `--dbms` | `hsqldb` | Sqlmap's `--dbms` hint applied to every target (WebGoat ships HSQLDB; change for other targets). |
| `--model` | `claude-haiku-4-5` | Claude model for the analyst step. |
| `--output` | `report.json` | Where to write the structured report. |
| `--raw-log` | `sqlmap.log` | Where to write the raw concatenated sqlmap stdout across every target. This is the audit-trail artefact, and the input you'd re-feed offline if you wanted to try a different model or prompt without re-running sqlmap. Pass `""` to skip. |
| `--compressed-log` | `sqlmap.compressed.log` | Where to write the compressed sqlmap log — what the LLM actually receives, after stripping `[DEBUG]` lines / timestamps / consecutive duplicates. Useful for diff against `--raw-log` to inspect what the preprocessing step removed. Pass `""` to skip. |
| `--dry-run` | off | Run sqlmap on every target but skip the Claude call (cheap preview). |
| `--mock` | off | Skip both sqlmap and Claude. Uses canned fixture stories keyed off the URLs in your targets file. For development. |
| `--thorough` | off | Bump sqlmap to `--level=3 --risk=2` (engagement-grade settings). Slower (5-10x runtime per target) but defeats WebGoat's false-positive validator and confirms most lessons. Default sqlmap (level=1 risk=1) is conservative and typically only confirms the most distinctively-vulnerable target. |

## Cost

| Step | Wall time | Cost |
| --- | --- | --- |
| sqlmap session (per target) | 10–60 seconds | free |
| Claude analyst call (one call per *run*, regardless of target count) | 2–5 seconds | ~$0.005–0.02 with Haiku 4.5 (scales with concatenated stdout size) |

Total: still well under 5¢ for a four-target scan. Worth running multiple times during development.

## How it works (pointers into the code)

- [`tutorial_02/sqlmap_runner.py`](tutorial_02/sqlmap_runner.py) — subprocess wrapping `sqlmap` with `--batch` for non-interactive runs. Captures stdout + stderr, surfaces non-zero exit codes with sqlmap's reason. One run, one URL.
- [`tutorial_02/targets.py`](tutorial_02/targets.py) — pure-function parser for the multi-target file format (`URL`, `URL | DATA`, comments, blanks).
- [`tutorial_02/analyst.py`](tutorial_02/analyst.py) — Claude integration. The schema (`SqliReport` → `targets: list[TargetFinding]`) is multi-target by design. The system prompt tells Claude to expect `=== TARGET k/N: <url> ===` banners and to produce exactly one `TargetFinding` per banner. Output is forced via Anthropic tool-use.
- [`tutorial_02/cli.py`](tutorial_02/cli.py) — argparse + orchestration. Resolves the target list (from `--url` or `--targets-file`), loops sqlmap per target, concatenates the per-target stdouts under their banners, hands the pile to the analyst, prints + saves the report.

The cleanest separation is intentional: the sqlmap wrapper is dumb (it just runs a process), the targets parser is a pure function, Claude is the interpreter, and the CLI is the conductor. Each component is independently testable.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The included tests cover the Pydantic schema and the sqlmap-output → string-prep helpers. They don't run sqlmap or hit the Claude API — those are validated manually by running the tool against your own WebGoat instance.

## Why WebGoat and not Juice Shop?

Both work. WebGoat is the canonical OWASP teaching platform for SQLi specifically and runs cleanly in one official Docker image. The code is target-agnostic — pass any URL/parameter combination, change `--dbms` if needed, and the same wrapper works against Juice Shop (`--dbms=sqlite`), DVWA (`--dbms=mysql`), or any other intentionally-vulnerable container.

## License

MIT. See [LICENSE](LICENSE).
