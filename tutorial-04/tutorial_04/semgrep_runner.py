"""Subprocess wrapper around the ``semgrep`` CLI.

Runs ``semgrep --config=<rule.yml> --json <target>`` and returns the
parsed JSON findings as Python dicts. Deliberately thin — there's no
analytical work here, just a clean error envelope around the binary
and a tiny convenience to chunk findings for the triager.

semgrep itself does ALL the pattern matching. This module just shells
out, captures stdout, and parses the JSON envelope.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ─── Errors ─────────────────────────────────────────────────────────────────

class SemgrepMissingError(RuntimeError):
    """Raised when the ``semgrep`` binary isn't on PATH."""


class SemgrepRunError(RuntimeError):
    """Raised when semgrep exits non-zero with no recoverable output."""


# ─── Result types ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SemgrepFinding:
    """One semgrep match — file + line + matched text + rule metadata.

    Built from semgrep's JSON output (the ``results`` array). Keeps only
    the fields the triager needs; the full raw JSON is preserved on
    disk via ``--semgrep-raw`` so nothing is lost.
    """

    rule_id: str
    file_path: str          # path relative to the scan root
    start_line: int
    end_line: int
    matched_code: str       # the literal text semgrep matched
    message: str            # rule's ``message:`` field
    severity: str           # ERROR / WARNING / INFO

    @classmethod
    def from_semgrep_match(cls, match: dict, *, scan_root: Path) -> "SemgrepFinding":
        """Convert one entry from semgrep's JSON ``results`` array."""
        abs_path = Path(match.get("path", ""))
        try:
            rel = abs_path.relative_to(scan_root)
        except ValueError:
            rel = abs_path
        start = match.get("start", {}) or {}
        end = match.get("end", {}) or {}
        extra = match.get("extra", {}) or {}
        return cls(
            rule_id=str(match.get("check_id") or ""),
            file_path=str(rel).replace("\\", "/"),
            start_line=int(start.get("line") or 0),
            end_line=int(end.get("line") or 0),
            matched_code=str((extra.get("lines") or "")).rstrip("\n"),
            message=str(extra.get("message") or ""),
            severity=str(extra.get("severity") or "INFO"),
        )


@dataclass(frozen=True)
class SemgrepResult:
    """The full outcome of one semgrep run."""

    findings: list[SemgrepFinding]
    raw_json: dict
    returncode: int
    stderr_tail: str        # last ~400 chars of stderr — for error diagnostics

    @property
    def ok(self) -> bool:
        """semgrep returns 0 = no findings, 1 = findings, both fine for us."""
        return self.returncode in (0, 1)


# ─── Runner ─────────────────────────────────────────────────────────────────

def _find_semgrep_binary() -> str:
    """Locate the semgrep binary; raise ``SemgrepMissingError`` if absent."""
    path = shutil.which("semgrep")
    if path is None:
        raise SemgrepMissingError(
            "semgrep not found on PATH. Install with `pip install semgrep` "
            "or your package manager (https://semgrep.dev/docs/getting-started)."
        )
    return path


def run_semgrep(
    *,
    rule_yaml: str,
    target_dir: Path,
    rules_file_path: Path | None = None,
    max_files: int | None = None,
    timeout_s: int = 300,
) -> SemgrepResult:
    """Run semgrep against ``target_dir`` with the supplied YAML rule.

    The rule is written to ``rules_file_path`` (default: a sibling of
    target_dir) so semgrep can ``--config=<file>`` it AND so the user
    has a reusable artefact post-run. semgrep's JSON output is parsed
    and returned alongside the raw envelope.

    ``max_files`` caps how many source files semgrep scans by passing
    ``--max-target-bytes`` — useful for demo runs against a large repo.
    None = no cap.

    Raises ``SemgrepMissingError`` when the binary isn't on PATH;
    ``SemgrepRunError`` when semgrep exits with a code that isn't 0 or
    1 (semgrep exits 0 for no-findings, 1 for findings-present — both
    are healthy outcomes from our perspective).
    """
    binary = _find_semgrep_binary()
    if rules_file_path is None:
        rules_file_path = target_dir.parent / "tutorial_04_generated_rules.yml"
    rules_file_path.write_text(rule_yaml, encoding="utf-8")

    cmd = [
        binary,
        "--config", str(rules_file_path),
        "--json",
        "--no-git-ignore",
        "--metrics=off",
    ]
    if max_files is not None:
        # max-target-bytes is per-file; capping file COUNT in semgrep
        # requires a wrapper. Easier here: pass a generous per-file cap
        # so semgrep skips huge generated files, and rely on chunker.py
        # to scope the targeted path list when --max-files is set.
        cmd.extend(["--max-target-bytes", "2000000"])
    cmd.append(str(target_dir))

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepRunError(
            f"semgrep exceeded the {timeout_s}s timeout. Re-run with "
            f"--max-files set lower, or scope --webgoat-source to a "
            f"subdirectory."
        ) from exc

    if completed.returncode not in (0, 1):
        # Hints for the common non-success exit codes. Semgrep documents
        # these at https://semgrep.dev/docs/cli-reference/#exit-codes.
        hints = {
            2: "argument parsing error — check CLI flags.",
            3: "target-file errors — at least one source file couldn't be read.",
            4: "the target codebase contains invalid syntax semgrep can't parse.",
            5: "semgrep crashed; check stderr below.",
            6: "rule YAML is invalid. Check generated_rules.yml for a structural error.",
            7: "rule has invalid pattern syntax. Most likely the Claude-generated "
               "rule used a pattern semgrep can't parse — re-run (Claude's second draft "
               "tends to be simpler), or rephrase --concern.",
        }
        hint = hints.get(completed.returncode, "see stderr / stdout below.")
        # Errors can show up on either stream depending on the failure mode.
        stderr_tail = (completed.stderr or "").rstrip()[-800:] or "(empty)"
        stdout_tail = (completed.stdout or "").rstrip()[-800:] or "(empty)"
        raise SemgrepRunError(
            f"semgrep exited {completed.returncode}: {hint}\n"
            f"  rule file : {rules_file_path}\n"
            f"  stderr    : {stderr_tail}\n"
            f"  stdout    : {stdout_tail}\n"
            f"To diagnose manually, try:\n"
            f"  semgrep --validate --config={rules_file_path}\n"
            f"  semgrep --config={rules_file_path} {target_dir}"
        )

    try:
        raw = json.loads(completed.stdout) if completed.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        tail = (completed.stdout or "")[-400:]
        raise SemgrepRunError(
            f"semgrep produced unparseable JSON. stdout tail:\n  {tail}"
        ) from exc

    findings = [
        SemgrepFinding.from_semgrep_match(m, scan_root=target_dir)
        for m in (raw.get("results") or [])
    ]
    return SemgrepResult(
        findings=findings,
        raw_json=raw,
        returncode=completed.returncode,
        stderr_tail=(completed.stderr or "")[-400:],
    )


# ─── Display helpers ────────────────────────────────────────────────────────

def render_findings_for_terminal(
    findings: list[SemgrepFinding], *, limit: int = 5
) -> str:
    """Compact one-block-per-finding listing, truncated to ``limit``.

    Used for the post-semgrep / pre-triage print so the user sees what
    semgrep matched before the (more expensive) triage calls run.
    """
    if not findings:
        return "  (no findings)"
    lines = []
    for i, f in enumerate(findings[:limit], start=1):
        lines.append(
            f"  [{i:2d}] {f.severity:<7} {f.file_path}:{f.start_line}"
        )
        preview = f.matched_code.replace("\n", " ⏎ ")
        if len(preview) > 80:
            preview = preview[:77] + "..."
        lines.append(f"       {preview}")
    if len(findings) > limit:
        lines.append(f"  ... and {len(findings) - limit} more.")
    return "\n".join(lines)


__all__ = [
    "SemgrepFinding",
    "SemgrepMissingError",
    "SemgrepResult",
    "SemgrepRunError",
    "render_findings_for_terminal",
    "run_semgrep",
]
