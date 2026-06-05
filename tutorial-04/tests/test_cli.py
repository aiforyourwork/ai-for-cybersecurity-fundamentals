"""End-to-end test for the CLI in --mock mode.

Drives the full orchestration shape without semgrep, without an API key,
without any network call. Verifies:

  - the CLI exits 0
  - report.json is written and has the expected shape
  - generated_rules.yml is written and is valid semgrep YAML
  - the terminal output mentions the confirmed-high count
"""
from __future__ import annotations

import json
from pathlib import Path

from tutorial_04.cli import main
from tutorial_04.rule_generator import validate_rule_yaml


def test_mock_end_to_end_writes_expected_artefacts(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "report.json"
    rules_path = tmp_path / "generated_rules.yml"
    rc = main([
        "--webgoat-source", str(tmp_path),  # ignored in --mock
        "--concern", "Find SQL injection patterns where user input flows into JDBC queries.",
        "--mock",
        "--output", str(report_path),
        "--rules-out", str(rules_path),
        "--semgrep-raw", "",  # skip
    ])
    assert rc == 0

    assert report_path.exists(), "report.json should be written"
    data = json.loads(report_path.read_text(encoding="utf-8"))

    # Shape: top-level keys we depend on downstream.
    for key in (
        "target", "concern", "generated_rule_id", "generated_rule_yaml",
        "counts", "headline", "executive_summary", "findings",
        "confirmed_high", "confirmed_medium", "low_and_false_positives",
    ):
        assert key in data, f"report.json missing top-level key: {key}"

    # Mock fixture: 2 high-confidence + 1 false-positive.
    assert data["counts"]["high"] == 2
    assert data["counts"]["false-positive"] == 1
    assert data["counts"]["raw"] == 3

    # Generated rule lands and is parseable.
    assert rules_path.exists()
    assert validate_rule_yaml(rules_path.read_text(encoding="utf-8")) is True

    # Stdout mentions both Critical verdict + structured report path.
    out = capsys.readouterr().out
    assert "Critical" in out
    assert "report.json" in out


def test_mock_terminal_output_contains_verdict_and_summary(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main([
        "--webgoat-source", str(tmp_path),
        "--concern", "Find path traversal patterns where filesystem paths are constructed from user input.",
        "--mock",
        "--output", str(tmp_path / "r.json"),
        "--rules-out", str(tmp_path / "r.yml"),
        "--semgrep-raw", "",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    # The reduce-phase render includes "Confirmed HIGH:" block on the mock.
    assert "Confirmed HIGH" in out
    # Cross-tutorial callback should appear in the fixture's exploitation_guidance.
    assert "sqlmap" in out or "T2" in out or "SqlInjection" in out
