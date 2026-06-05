"""Tutorial 04 — AI-Augmented Static Code Analysis with semgrep + Claude.

A natural-language security concern goes in. A triaged report listing
every real bug, every false positive, and a one-line executive summary
comes out. semgrep does the deterministic pattern matching; Claude does
the rule authoring and the exploitability triage.

Pipeline shape (three Claude calls, one map-reduce):

  English concern ─▶ rule_generator.py  (Claude #1: NL → semgrep YAML)
                  ▼
                semgrep_runner.py        (subprocess; deterministic)
                  ▼
                raw findings (8-15 typical)
                  ▼
                triager.py               (Claude #2: parallel map,
                                          1 call per finding, exploitability rank)
                  ▼
                synthesiser.py           (Claude #3: reduce, exec summary
                                          + prioritised list)
                  ▼
                report.py                (JSON + terminal renderer)

Companion to AI for Cybersecurity Fundamentals T4. Same lab target
(WebGoat) as T2 — T2 attacked the running app; T4 finds the bug class
in the source. Cross-tutorial callback in slide 14 explicitly maps the
T4 semgrep hit on ``SqlInjectionLesson5a.java`` to the T2 sqlmap
exploitation of the same lesson at runtime.
"""

__version__ = "0.1.0"
