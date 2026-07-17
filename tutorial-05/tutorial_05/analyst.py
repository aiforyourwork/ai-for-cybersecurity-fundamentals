"""Claude as the report author — reads the evidence pack, returns a structured
Assessment via forced tool-use. One call. Deterministic input, non-deterministic prose.
"""
from __future__ import annotations

import os

from .schemas import Assessment

DEFAULT_MODEL = "claude-haiku-4-5"   # series default (cost). --model claude-opus-4-8 for richer prose.

SYSTEM_PROMPT = """\
You are a senior penetration tester writing a client-facing security assessment report
from the raw output of three automated tools: a dynamic SQL-injection scan (sqlmap), an
attack-surface subdomain enumeration, and a static code analysis (semgrep). Consolidate
them into ONE professional, prioritized assessment.

Rules:
- executive_summary: 3-6 sentences a non-technical stakeholder can read — what was found,
  how bad, what to do.
- overall_severity: the single worst finding (Critical / High / Medium / Low / Informational).
- findings: one entry per DISTINCT issue. **Correlate and de-duplicate**: when the static
  scan and the dynamic scan point at the same SQL-injection weakness, report ONE finding with
  source "Static + Dynamic (corroborated)" and confidence High — do not double-count. Recon
  exposures (reachable admin/SSO/non-prod environments) become their own findings.
- Each finding: assign severity + confidence; map to CWE and OWASP Top 10 (2021) and MITRE
  ATT&CK technique ID(s); give concrete evidence citing the tool detail; give a specific,
  actionable remediation.
- attack_surface_notes: summarize the external exposure with risk framing.
- recommendations: 3-6 prioritized, actionable items.
- Only report what the evidence supports. These are lab targets (OWASP WebGoat / a test
  domain) — note that, but score each issue by the real-world severity of the pattern.
- Be calibrated and specific. No filler, no invented findings.
"""


class AnalystError(RuntimeError):
    pass


def analyse(evidence: str, *, client_name: str, engagement: str,
            model: str = DEFAULT_MODEL, api_key: str | None = None,
            max_tokens: int = 4096) -> Assessment:
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise AnalystError("ANTHROPIC_API_KEY not set (put it in .env or pass --api-key).")

    from anthropic import Anthropic

    tool = {
        "name": "record_assessment",
        "description": "Record the consolidated, prioritized security assessment.",
        "input_schema": Assessment.model_json_schema(),
    }
    user = (
        f"Client: {client_name}\nEngagement: {engagement}\n\n"
        "Consolidated tool evidence (already de-noised):\n\n"
        f"{evidence}\n\n"
        "Call record_assessment. Correlate corroborating findings, prioritize, and map each "
        "to CWE / OWASP / MITRE ATT&CK."
    )

    client = Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model, max_tokens=max_tokens, system=SYSTEM_PROMPT,
        tools=[tool], tool_choice={"type": "tool", "name": "record_assessment"},
        messages=[{"role": "user", "content": user}],
    )
    for block in resp.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "record_assessment":
            return Assessment.model_validate(block.input)
    raise AnalystError(f"Claude did not call the tool (stop_reason={resp.stop_reason}).")


__all__ = ["analyse", "AnalystError", "SYSTEM_PROMPT", "DEFAULT_MODEL"]
