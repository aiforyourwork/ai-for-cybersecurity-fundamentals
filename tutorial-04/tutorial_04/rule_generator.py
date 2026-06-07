"""Claude call #1 — translate an English security concern into a semgrep YAML rule.

This is the first of the three Claude calls in the pipeline. Its whole
job is **rule authorship**: you describe the bug class you care about
in prose; Claude writes the YAML rule that semgrep will execute against
the target source tree.

Design choices worth flagging:

1. **Lazy SDK import.** ``anthropic`` is only imported when we actually
   call the model — schema tests run without the SDK installed.

2. **Tool-use for structured output.** The rule's YAML body comes back
   as a string field on a Pydantic-modelled tool input. Claude can't
   "almost-write-YAML" and trip a parser — the tool-use envelope
   guarantees the response is the right shape; we only need to
   sanity-check the YAML body itself.

3. **Pre-write YAML parse + retry.** Even with tool-use envelope, the
   YAML body might be malformed (mismatched braces, indentation, etc).
   If ``yaml.safe_load`` raises, we retry the Claude call once with the
   error message included, then surface a clear error to the caller.

4. **Single rule per concern.** Each concern produces exactly one
   semgrep rule. Multiple concerns means multiple invocations. Keeps
   the rule small enough that Claude doesn't drift, and keeps the
   output file (``generated_rules.yml``) trivially reusable.
"""
from __future__ import annotations

import os
import re
from typing import Any

import yaml
from pydantic import BaseModel, Field


# ─── Output schema ──────────────────────────────────────────────────────────

class GeneratedRule(BaseModel):
    """The structured rule-generator response."""

    rule_id: str = Field(
        ...,
        description=(
            "Short identifier for the rule. MUST match semgrep's regex "
            "``^[a-zA-Z0-9._-]*$`` — letters, digits, dots, underscores, "
            "and hyphens ONLY. **No forward slashes** (semgrep rejects "
            "them with InvalidRuleSchemaError). Convention: "
            "``tutorial-04.<bug-class>-<context>`` using a dot to "
            "namespace the bug class. Example: "
            "``tutorial-04.sqli-jdbc-user-input`` or "
            "``tutorial-04.path-traversal-file-constructor``. Becomes "
            "the rule's ``id:`` field in the emitted YAML."
        ),
    )
    yaml_body: str = Field(
        ...,
        description=(
            "The complete semgrep rule as a YAML string. MUST be a valid "
            "semgrep ``rules:`` document — top-level key ``rules:`` "
            "followed by a list with ONE rule. Each rule MUST have ``id``, "
            "``message``, ``languages``, ``severity``, plus a pattern "
            "directive (one of ``pattern``, ``patterns``, ``pattern-either``, "
            "``pattern-regex``). See https://semgrep.dev/docs/writing-rules/"
            "rule-syntax for the full grammar."
        ),
    )
    rationale: str = Field(
        ...,
        description=(
            "One short sentence explaining WHY this rule shape was chosen "
            "for the concern. Surfaces in the terminal output so the user "
            "understands what they're about to run. Examples: 'Matches any "
            "Statement.execute* call whose argument concatenates a "
            "getParameter result', 'Matches Path.of / new File where one "
            "argument originates in an HttpServletRequest accessor'."
        ),
    )


# ─── System prompt ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security-tooling assistant whose ONE job is to translate an \
English security concern into a working semgrep YAML rule.

You will receive a concern like *"Find SQL injection patterns where user \
input flows into JDBC queries"* and you return a complete semgrep rule \
document that, when run via ``semgrep --config=<your-yaml>``, will \
surface candidate matches for that concern in a Java codebase.

Rules you must follow:

1. **Output ONE rule per response** — exactly one rule under the \
   top-level ``rules:`` key. Do not bundle multiple rules.
2. **Use semgrep's modern syntax.** Prefer the ``patterns:`` / \
   ``pattern-either:`` style over deprecated ``pattern-not-inside`` \
   combinations when possible. Use ``metavariable-pattern`` for \
   parameter-source tracking when the rule needs it.
3. **Be specific over broad.** A rule that flags everything is useless. \
   Pin the matcher to the actual sink (e.g. ``Statement.executeQuery(...)``, \
   ``Path.of(...)``, ``new File(...)``) AND when feasible the source \
   (e.g. ``request.getParameter(...)``, ``HttpServletRequest`` accessor). \
   False positives cost the analyst time; false negatives cost the \
   organisation money.
4. **Set ``severity`` honestly.** ``ERROR`` for the concern's headline \
   bug class; ``WARNING`` only if the matched shape is a *likely* but not \
   certain instance.
5. **Default to ``languages: [java]`` for WebGoat.** If the concern \
   names a different language (Python, Go, JavaScript), use that — but \
   the demo target is Java/Spring-Boot.
6. **The ``message:`` field is what the analyst reads alongside each \
   finding.** Keep it concrete: name the bug class AND the dataflow shape \
   in one sentence. Bad: *"SQL injection vulnerability."* Good: \
   *"User input from getParameter() concatenated into a JDBC query — \
   classic SQLi sink."*

Validate the YAML you produce by mentally re-reading it: would semgrep \
parse this? Would the patterns actually match the bug class the user \
described? If unsure, prefer a slightly broader pattern (the AI triager \
catches false positives downstream) over a stricter one that misses \
real bugs.

Set ``rule_id`` to a short identifier matching semgrep's regex \
``^[a-zA-Z0-9._-]*$`` — letters, digits, dots, underscores, and hyphens \
only. **No forward slashes** (semgrep rejects rule IDs containing them \
with an InvalidRuleSchemaError). Convention: \
``tutorial-04.<bug-class>-<dataflow-shape>`` using a dot for the \
namespace separator. Example: ``tutorial-04.sqli-jdbc-user-input``.

Set ``rationale`` to one short sentence describing what the rule \
actually matches in concrete terms — surfaces in the terminal so the \
user understands what they're about to run.
"""


# ─── Claude call ────────────────────────────────────────────────────────────

class RuleGenerationError(RuntimeError):
    """Raised when the rule generator fails (missing key, malformed YAML, etc.)."""


def generate_rule(
    *,
    concern: str,
    model: str = "claude-haiku-4-5",
    api_key: str | None = None,
    max_tokens: int = 1024,
    retry_on_yaml_error: bool = True,
) -> GeneratedRule:
    """Translate an English security concern into a semgrep YAML rule.

    Uses tool-use forced output. The Anthropic SDK validates the tool
    input against ``GeneratedRule``'s schema before returning, so a
    malformed RESPONSE is impossible at this boundary. The YAML BODY
    inside ``yaml_body`` is parsed locally with ``yaml.safe_load`` —
    if it fails to parse, we retry the call once with the parse error
    included as feedback, then raise ``RuleGenerationError``.
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuleGenerationError(
            "ANTHROPIC_API_KEY not set. Add it to .env or pass --api-key."
        )

    # Lazy import — schema tests don't need anthropic installed.
    from anthropic import Anthropic

    tool_schema = GeneratedRule.model_json_schema()
    tool = {
        "name": "record_semgrep_rule",
        "description": (
            "Record the semgrep YAML rule synthesised from the user's "
            "natural-language security concern."
        ),
        "input_schema": tool_schema,
    }

    user_message = (
        f"Translate the following security concern into one semgrep "
        f"YAML rule, then call the record_semgrep_rule tool with the "
        f"result.\n\n"
        f"Concern: {concern.strip()}\n"
    )

    client = Anthropic(api_key=api_key)
    rule = _call_and_validate(
        client=client,
        model=model,
        max_tokens=max_tokens,
        system_prompt=SYSTEM_PROMPT,
        user_message=user_message,
        tool=tool,
    )
    if rule is not None:
        return rule

    # First attempt produced unparseable YAML. Retry once with a
    # follow-up message that includes the parser error.
    if not retry_on_yaml_error:
        raise RuleGenerationError(
            "Rule generator produced unparseable YAML and retry was disabled."
        )

    retry_message = user_message + (
        "\n\nYour previous response contained YAML that failed to parse. "
        "Re-emit the rule with valid YAML syntax. Pay attention to "
        "indentation (semgrep YAML is whitespace-sensitive) and quote any "
        "values containing colons, hash marks, or other YAML control "
        "characters. Call the record_semgrep_rule tool again with the "
        "corrected output."
    )
    rule = _call_and_validate(
        client=client,
        model=model,
        max_tokens=max_tokens,
        system_prompt=SYSTEM_PROMPT,
        user_message=retry_message,
        tool=tool,
    )
    if rule is not None:
        return rule

    raise RuleGenerationError(
        "Rule generator produced unparseable YAML on both attempts. "
        "Try rephrasing the --concern or switching --model."
    )


def _call_and_validate(
    *,
    client,
    model: str,
    max_tokens: int,
    system_prompt: str,
    user_message: str,
    tool: dict,
) -> GeneratedRule | None:
    """Invoke Claude with the forced tool; return the rule iff YAML parses."""
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system_prompt,
        tools=[tool],
        tool_choice={"type": "tool", "name": tool["name"]},
        messages=[{"role": "user", "content": user_message}],
    )
    tool_use = _find_tool_use(response.content, tool["name"])
    if tool_use is None:
        raise RuleGenerationError(
            "Claude did not invoke the record_semgrep_rule tool. "
            f"Stop reason: {response.stop_reason}. "
            f"Raw content: {response.content!r}"
        )
    rule = GeneratedRule.model_validate(tool_use["input"])
    rule = _sanitize_rule_id(rule)
    if validate_rule_yaml(rule.yaml_body):
        return rule
    return None


_VALID_RULE_ID_CHARS = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_rule_id(rule: GeneratedRule) -> GeneratedRule:
    """Replace any character not allowed by semgrep's ``^[a-zA-Z0-9._-]*$``
    regex with a dot in BOTH the Pydantic field and the YAML body's ``id:``
    line. Belt-and-braces against the model still emitting slashes despite
    the prompt — forward slash is the historical mistake worth defending.

    Returns a NEW GeneratedRule (Pydantic models are immutable-by-convention
    for our purposes — model_copy preserves type).
    """
    bad_id = rule.rule_id
    clean_id = _VALID_RULE_ID_CHARS.sub(".", bad_id)
    if clean_id == bad_id:
        return rule
    # Also rewrite the YAML body's ``id:`` line. The model usually emits
    # ``id: tutorial-04/sqli-jdbc-user-input`` as the first key under the
    # rule entry — replace the whole-string occurrence to avoid partial
    # matches inside messages or comments.
    new_yaml = rule.yaml_body.replace(bad_id, clean_id)
    return rule.model_copy(update={"rule_id": clean_id, "yaml_body": new_yaml})


def _find_tool_use(content_blocks: list[Any], tool_name: str) -> dict | None:
    """Pick the tool_use block matching ``tool_name`` from a response."""
    for block in content_blocks:
        if getattr(block, "type", None) == "tool_use":
            if getattr(block, "name", None) == tool_name:
                return {"name": block.name, "input": block.input}
    return None


def validate_rule_yaml(yaml_body: str) -> bool:
    """Return True iff ``yaml_body`` parses as a semgrep ``rules:`` document.

    Sanity check only — semgrep itself does the heavy validation when
    it loads the rule. Here we just confirm the YAML is parseable AND
    has the expected top-level shape (``rules:`` key with at least one
    rule that has an ``id`` and a pattern directive).
    """
    try:
        doc = yaml.safe_load(yaml_body)
    except yaml.YAMLError:
        return False
    if not isinstance(doc, dict):
        return False
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        return False
    first = rules[0]
    if not isinstance(first, dict):
        return False
    if "id" not in first:
        return False
    pattern_keys = {
        "pattern", "patterns", "pattern-either", "pattern-regex",
        "pattern-not", "pattern-inside",
    }
    if not (pattern_keys & set(first.keys())):
        return False
    return True


def render_rule_for_terminal(rule: GeneratedRule) -> str:
    """Compact pre-run preview shown before kicking off semgrep.

    Two lines: the rule id and the rationale. The full YAML lands on
    disk via ``--rules-out``; the terminal preview is the "what's about
    to run" headline.
    """
    return (
        f"  rule_id  : {rule.rule_id}\n"
        f"  rationale: {rule.rationale}"
    )


__all__ = [
    "GeneratedRule",
    "RuleGenerationError",
    "SYSTEM_PROMPT",
    "generate_rule",
    "render_rule_for_terminal",
    "validate_rule_yaml",
]
