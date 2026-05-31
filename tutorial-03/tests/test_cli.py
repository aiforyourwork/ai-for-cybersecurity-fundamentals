"""CLI smoke tests against --mock.

The mock mode short-circuits every external dependency (subfinder, DNS,
HTTP, Claude) so these tests run offline with no API key. They also
double as the safety-hinge regression suite — `--scope` is mandatory,
and the mock target's `.test` TLD must hit the scope file or be
rejected, never silently let through."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tutorial_03.cli import main as cli_main


# ─── Helpers ────────────────────────────────────────────────────────────────

def _write_scope(tmp_path: Path, *patterns: str) -> Path:
    p = tmp_path / "scope.txt"
    p.write_text("\n".join(patterns) + "\n", encoding="utf-8")
    return p


# ─── Argument validation ───────────────────────────────────────────────────

def test_cli_requires_domain_flag():
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["--scope", "irrelevant.txt"])
    assert exc_info.value.code == 2


def test_cli_requires_scope_flag():
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["--domain", "example.com"])
    assert exc_info.value.code == 2


def test_cli_rejects_missing_scope_file(tmp_path, capsys):
    rc = cli_main([
        "--domain", "example.com",
        "--scope", str(tmp_path / "no-such-scope.txt"),
        "--mock",
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "scope" in err.lower()


def test_cli_rejects_root_domain_outside_scope(tmp_path, capsys):
    """Critical safety check: even with --mock, the root domain must be
    in scope. We don't want a recording to leak with a misconfigured
    scope file."""
    scope = _write_scope(tmp_path, "*.allowed.com")
    rc = cli_main([
        "--domain", "blocked.com",
        "--scope", str(scope),
        "--mock",
        "--output", str(tmp_path / "report.json"),
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "outside the scope file" in err


# ─── Mock pipeline end-to-end ──────────────────────────────────────────────

def test_cli_mock_produces_funnel_and_json(tmp_path, capsys):
    """Happy path: mock runs end-to-end, prints a funnel, writes a JSON report."""
    scope = _write_scope(tmp_path, "*.demo-target.test")
    report_path = tmp_path / "report.json"
    rc = cli_main([
        "--domain", "demo-target.test",
        "--scope", str(scope),
        "--mock",
        "--output", str(report_path),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "T3 — AI-augmented subdomain enumeration" in out
    assert "Stage 1: candidate generation" in out
    assert "Stage 4: AI ranking" in out
    assert "api-dev.demo-target.test" in out  # high-priority mock hit
    # JSON report shape — three sources tracked separately.
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["root_domain"] == "demo-target.test"
    assert data["scope_patterns"] == ["*.demo-target.test"]
    assert data["counts"]["passive"] > 0
    assert data["counts"]["regex_extracted"] > 0
    assert data["counts"]["ai_inferred"] > 0
    # The inference value-add is the load-bearing number.
    assert data["counts"]["ai_only"] > 0
    # The mock has at least one high-priority host.
    assert any(h["priority"] == "high" for h in data["hosts"])


def test_cli_mock_high_priority_findings_are_ai_only(tmp_path):
    """The pedagogical hinge: in the mock fixture, every high-priority finding
    should come from Claude's inference layer (sources includes 'ai' but
    NOT 'subfinder' or 'regex'). That's the whole tutorial pitch — verify
    the fixtures actually deliver it."""
    scope = _write_scope(tmp_path, "*.demo-target.test")
    report_path = tmp_path / "report.json"
    rc = cli_main([
        "--domain", "demo-target.test",
        "--scope", str(scope),
        "--mock",
        "--output", str(report_path),
    ])
    assert rc == 0
    data = json.loads(report_path.read_text(encoding="utf-8"))
    high_hosts = [h for h in data["hosts"] if h.get("priority") == "high"]
    assert len(high_hosts) >= 2, "mock should have at least 2 high-priority hits"
    for h in high_hosts:
        srcs = set(h["sources"])
        assert "ai" in srcs, f"high host {h['host']} missing 'ai' source"
        assert "subfinder" not in srcs, (
            f"high host {h['host']} also from subfinder — undermines the "
            f"'inference is the value-add' pitch"
        )
        assert "regex" not in srcs, (
            f"high host {h['host']} also from regex extractor — undermines "
            f"the 'inference is the value-add' pitch"
        )


def test_cli_mock_under_a_scope_that_excludes_everything(tmp_path, capsys):
    """If the scope only allows the root domain (not its subs), the mock's
    candidates all drop out. The pipeline should still complete cleanly
    with an empty funnel — not crash."""
    scope = _write_scope(tmp_path, "demo-target.test")
    rc = cli_main([
        "--domain", "demo-target.test",
        "--scope", str(scope),
        "--mock",
        "--output", str(tmp_path / "report.json"),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    # Every passive subdomain (www., mail., etc.) is out of scope under
    # this narrow file.
    assert "dropped" in out


def test_cli_mock_writes_scope_patterns_to_json(tmp_path):
    scope = _write_scope(tmp_path, "*.demo-target.test", "*.also.demo-target.test")
    report_path = tmp_path / "r.json"
    rc = cli_main([
        "--domain", "demo-target.test",
        "--scope", str(scope),
        "--mock",
        "--output", str(report_path),
    ])
    assert rc == 0
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert "*.demo-target.test" in data["scope_patterns"]
    assert "*.also.demo-target.test" in data["scope_patterns"]
