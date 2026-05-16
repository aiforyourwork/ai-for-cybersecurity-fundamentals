"""Thin subprocess wrapper around ``sqlmap``.

Design choice: the wrapper is **deliberately dumb**. It does not try to
parse sqlmap's output into structured data — that's exactly what the
analyst step exists for. The wrapper's job is to:

1. Build a sane sqlmap command line from a handful of CLI flags.
2. Run sqlmap non-interactively (``--batch``) so it doesn't prompt.
3. Capture the full stdout + stderr.
4. Surface non-zero exits with a clear error.

Keeping the wrapper dumb means the tutorial reads cleanly: "here's the
raw tool output → here's what the LLM interprets it as", with no
fragile-by-version sqlmap parsing in between.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SqlmapResult:
    """The captured output of one sqlmap run."""

    command: list[str]      # Argv list — useful for the report and for debugging.
    returncode: int
    stdout: str             # Combined stdout (the interesting part).
    stderr: str             # Captured separately. Usually empty on success.

    @property
    def ok(self) -> bool:
        """sqlmap returns 0 on a clean run regardless of whether it found
        a vulnerability. Non-zero means *the tool itself* errored."""
        return self.returncode == 0


class SqlmapMissingError(RuntimeError):
    """Raised when ``sqlmap`` is not on PATH."""


def _require_sqlmap() -> str:
    path = shutil.which("sqlmap")
    if path is None:
        raise SqlmapMissingError(
            "'sqlmap' not found on PATH. On Ubuntu/Debian: `sudo apt install "
            "sqlmap`. Other platforms: `pipx install sqlmap`, or clone from "
            "https://github.com/sqlmapproject/sqlmap and add it to PATH."
        )
    return path


def build_sqlmap_command(
    *,
    url: str,
    parameter: str | None = None,
    data: str | None = None,
    cookie: str | None = None,
    dbms: str = "hsqldb",
    extra_args: list[str] | None = None,
) -> list[str]:
    """Construct the sqlmap argv. Pure function — exported for testability.

    Always-on flags:

    - ``--batch`` — never prompt; assume default answers. Required for
      scripted use.
    - ``--dump`` — extract data after confirming injectability. Without
      ``--dump``, sqlmap would stop after "yes, this is injectable",
      which makes for a less interesting analyst report.

    Optional flags:

    - ``-p <param>`` — narrow to one specific parameter. **Omitting it
      is the right default for black-box discovery**: sqlmap tests every
      parameter in ``--data`` and reports which (if any) are injectable.
      The runtime cost on a 2-parameter form is trivial (~10 seconds);
      the pedagogical payoff is that the AI analyst gets to summarise
      "this field is vulnerable, this one is sanitised" — a real
      pentester finding rather than a contrived "we knew which to attack".
    - ``--data`` for POST bodies in ``application/x-www-form-urlencoded``
      form (the WebGoat lesson endpoints expect this — confirm via
      DevTools Network tab if you're targeting a different endpoint).
    - ``--cookie`` for authenticated sessions. WebGoat lessons require
      a logged-in session, so we pass the user's JSESSIONID through.
    - ``--dbms`` to skip the DBMS-fingerprinting step. WebGoat ships
      HSQLDB; setting this saves about 10 seconds per run.

    For targets that expect JSON bodies (Spring ``@RequestBody`` controllers,
    typically modern SPAs), you'd need to add ``-H "Content-Type:
    application/json"``. The wrapper does NOT auto-add this — sqlmap can't
    reliably detect the right Content-Type from the body alone, and a
    mismatched Content-Type causes silent ``HTTP 400`` on every request.
    Confirm the right Content-Type by capturing the browser's request via
    DevTools (Network → Copy as cURL) before pointing sqlmap at a new
    target.
    """
    sqlmap = _require_sqlmap()
    cmd = [
        sqlmap,
        "-u", url,
        "--batch",
        "--dump",
        "--dbms", dbms,
        # -v 3 — engagement-grade verbosity. Default level 2 lists techniques
        # ("testing 'AND boolean-based blind'...") but hides the actual SQL
        # payload strings. Real pentest audit trails need the payload-level
        # detail: reproducibility (clients' dev teams need the exact string
        # to patch), evidence (findings get challenged weeks later), and
        # false-positive verification (technique name alone can't tell real
        # from noise). The AI analyst happens to be useful at this volume
        # too — but that's not the reason we set it.
        "-v", "3",
        # --flush-session forces sqlmap to discard any cached session state
        # for this URL before probing. Without it, a half-written cache from
        # a previously-interrupted run (Ctrl-C, kill, host reboot) can cause
        # the next run to hang trying to "resume" the broken session — and
        # the hang point is non-deterministic (whichever target's cache got
        # corrupted). Each run starts fresh; loses the speed-up of session
        # resumption, gains predictability. The trade-off is right for a
        # multi-target wrapper where one bad cache stalls the whole batch.
        "--flush-session",
        # --output-dir keeps sqlmap's session/log files out of the cwd
        # so the user's project folder doesn't accumulate sqlmap state.
        # We use a per-target subfolder so repeat runs don't collide.
        "--output-dir", str(_sqlmap_output_dir(url)),
    ]
    if parameter:
        cmd.extend(["-p", parameter])
    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def _sqlmap_output_dir(url: str) -> Path:
    """Where sqlmap writes its session/log files. One subdir per target.

    sqlmap normally writes under ``~/.local/share/sqlmap/output/<host>/``
    on Linux; on Windows it picks ``%APPDATA%\\sqlmap\\output\\<host>\\``.
    Pointing ``--output-dir`` at a project-local directory keeps state
    visible and easy to wipe between runs (delete the folder).
    """
    from urllib.parse import urlparse
    host = urlparse(url).hostname or "unknown-host"
    return Path(".sqlmap-state") / host.replace(":", "_")


def run_sqlmap(
    *,
    url: str,
    parameter: str | None = None,
    data: str | None = None,
    cookie: str | None = None,
    dbms: str = "hsqldb",
    extra_args: list[str] | None = None,
    timeout_seconds: int = 300,
) -> SqlmapResult:
    """Execute sqlmap and capture its output.

    Times out after ``timeout_seconds`` (default 5 min). A SQLi lesson on
    WebGoat typically completes in 10-60 seconds; if sqlmap is still
    running after 5 minutes the target is probably wrong or the cookie
    has expired.
    """
    cmd = build_sqlmap_command(
        url=url,
        parameter=parameter,
        data=data,
        cookie=cookie,
        dbms=dbms,
        extra_args=extra_args,
    )
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
        # Belt-and-braces with --batch: explicitly close stdin so sqlmap
        # can't block on an interactive prompt the --batch defaults didn't
        # cover. Rare edge cases (an unknown target type, a specific WAF
        # response) still trigger Y/N prompts; with stdin closed they
        # error out immediately rather than hanging the whole pipeline.
        stdin=subprocess.DEVNULL,
    )
    return SqlmapResult(
        command=cmd,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


__all__ = [
    "SqlmapMissingError",
    "SqlmapResult",
    "build_sqlmap_command",
    "run_sqlmap",
]
