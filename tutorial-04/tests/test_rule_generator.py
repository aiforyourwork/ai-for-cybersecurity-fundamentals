"""Tests for rule_generator — schemas and YAML validator.

No live Claude calls; the API-call paths are exercised via injected
fakes in test_cli.py's end-to-end mock run.
"""
from __future__ import annotations

import pytest

from tutorial_04.rule_generator import (
    GeneratedRule,
    render_rule_for_terminal,
    validate_rule_yaml,
)


VALID_RULE_YAML = """\
rules:
  - id: tutorial-04/sqli-jdbc-user-input
    message: User input concatenated into a JDBC statement.
    languages: [java]
    severity: ERROR
    pattern: |
      $STMT.executeQuery($Q)
"""


def test_validate_accepts_well_formed_rule():
    assert validate_rule_yaml(VALID_RULE_YAML) is True


def test_validate_rejects_unparseable_yaml():
    assert validate_rule_yaml(":\n::not valid::") is False


def test_validate_rejects_missing_top_level_rules():
    assert validate_rule_yaml("not_rules:\n  - id: x\n    pattern: y\n") is False


def test_validate_rejects_empty_rules_list():
    assert validate_rule_yaml("rules: []\n") is False


def test_validate_rejects_rule_missing_id():
    yaml_no_id = """\
rules:
  - message: missing id
    languages: [java]
    pattern: foo
"""
    assert validate_rule_yaml(yaml_no_id) is False


def test_validate_rejects_rule_missing_pattern_directive():
    yaml_no_pattern = """\
rules:
  - id: tutorial-04/x
    message: no pattern directive
    languages: [java]
    severity: ERROR
"""
    assert validate_rule_yaml(yaml_no_pattern) is False


def test_validate_accepts_patterns_compound():
    yaml_patterns = """\
rules:
  - id: tutorial-04/x
    message: ok
    languages: [java]
    severity: ERROR
    patterns:
      - pattern: foo
      - pattern: bar
"""
    assert validate_rule_yaml(yaml_patterns) is True


def test_validate_accepts_pattern_either():
    yaml_either = """\
rules:
  - id: tutorial-04/x
    message: ok
    languages: [java]
    severity: ERROR
    pattern-either:
      - pattern: foo
      - pattern: bar
"""
    assert validate_rule_yaml(yaml_either) is True


def test_generated_rule_model_round_trip():
    rule = GeneratedRule(
        rule_id="tutorial-04/sqli",
        yaml_body=VALID_RULE_YAML,
        rationale="Matches Statement.executeQuery sinks.",
    )
    again = GeneratedRule.model_validate(rule.model_dump())
    assert again == rule


def test_render_rule_for_terminal_includes_id_and_rationale():
    rule = GeneratedRule(
        rule_id="tutorial-04/sqli",
        yaml_body=VALID_RULE_YAML,
        rationale="Matches Statement.executeQuery sinks.",
    )
    out = render_rule_for_terminal(rule)
    assert "tutorial-04/sqli" in out
    assert "Statement.executeQuery sinks" in out
