"""Tests for semgrep_runner — subprocess wrapper.

We don't run real semgrep; instead we verify the JSON-parsing layer
and the SemgrepFinding constructor against fixture data shaped like
semgrep's actual output. Real-semgrep coverage happens at the integration
level when developing T4 locally.
"""
from __future__ import annotations

from pathlib import Path

from tutorial_04.semgrep_runner import (
    SemgrepFinding,
    SemgrepResult,
    render_findings_for_terminal,
)


SAMPLE_SEMGREP_MATCH = {
    "check_id": "tutorial-04/sqli-jdbc-user-input",
    "path": "/abs/path/src/main/java/com/Foo.java",
    "start": {"line": 73, "col": 9},
    "end": {"line": 73, "col": 88},
    "extra": {
        "message": "User input concatenated into a JDBC statement.",
        "severity": "ERROR",
        "lines": 'statement.executeQuery("SELECT ... " + accountName)',
    },
}


def test_finding_from_semgrep_match_relativises_path():
    scan_root = Path("/abs/path")
    f = SemgrepFinding.from_semgrep_match(SAMPLE_SEMGREP_MATCH, scan_root=scan_root)
    assert f.file_path == "src/main/java/com/Foo.java"
    assert f.start_line == 73
    assert f.end_line == 73
    assert f.severity == "ERROR"
    assert "executeQuery" in f.matched_code
    assert f.message.startswith("User input concatenated")


def test_finding_from_match_handles_missing_fields():
    f = SemgrepFinding.from_semgrep_match({}, scan_root=Path("/x"))
    # Defaults to zero-line + empty strings rather than raising.
    assert f.rule_id == ""
    assert f.start_line == 0
    assert f.matched_code == ""
    assert f.severity == "INFO"


def test_finding_normalises_windows_path_separators(tmp_path):
    match = {
        "check_id": "x",
        "path": str(tmp_path / "src" / "main" / "java" / "F.java"),
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {"message": "m", "severity": "WARNING", "lines": "x"},
    }
    f = SemgrepFinding.from_semgrep_match(match, scan_root=tmp_path)
    assert "/" in f.file_path
    assert "\\" not in f.file_path


def test_semgrep_result_ok_true_for_0_and_1():
    base = dict(findings=[], raw_json={}, stderr_tail="")
    assert SemgrepResult(returncode=0, **base).ok is True
    assert SemgrepResult(returncode=1, **base).ok is True
    assert SemgrepResult(returncode=2, **base).ok is False


def test_render_findings_truncates_with_limit():
    f = SemgrepFinding.from_semgrep_match(SAMPLE_SEMGREP_MATCH, scan_root=Path("/abs/path"))
    rendered = render_findings_for_terminal([f] * 10, limit=3)
    # 3 rendered + truncation notice
    assert "and 7 more" in rendered
    # First finding's file path appears in output
    assert "Foo.java" in rendered


def test_render_findings_empty():
    assert "no findings" in render_findings_for_terminal([])
