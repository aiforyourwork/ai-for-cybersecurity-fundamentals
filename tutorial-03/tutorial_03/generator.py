"""Claude call #1 — homepage text → candidate subdomain list.

The headline pedagogical move of T3. Subfinder's wordlists are dumb;
Claude can read the homepage and infer business context (sector,
tech-stack signals, hiring activity, partner ecosystem) and propose
subdomain candidates a generic wordlist would never produce.

Forced output via Anthropic tool-use: the schema IS the response
contract, so a malformed response is impossible (the SDK validates
before returning).
"""
from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field


# ─── Output schema ──────────────────────────────────────────────────────────

class CandidateSubdomain(BaseModel):
    """One AI-suggested subdomain candidate."""

    host: str = Field(
        ...,
        description=(
            "The candidate subdomain in fully-qualified form, e.g. "
            "'careers.example.com'. Use only lowercase ASCII letters, "
            "digits, hyphens, and dots. Must end with the supplied root "
            "domain (the caller validates this — invented hosts outside "
            "the root will be dropped)."
        ),
    )
    rationale: str = Field(
        ...,
        description=(
            "One short sentence on what business signal led you to "
            "this guess. Aim for ≤80 chars. Examples: "
            "'careers page links suggest careers. exists'; "
            "'status footer link suggests status.'; "
            "'GitHub repo hints at docs.'."
        ),
    )


class CandidateList(BaseModel):
    """The structured generator output."""

    candidates: list[CandidateSubdomain] = Field(
        default_factory=list,
        description="Up to 25 candidate subdomains, most-likely-first.",
    )


# ─── Generator call ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security analyst doing reconnaissance on a target domain. \
You will be given the cleaned text of the target's homepage, plus a list \
of subdomains that two prior stages have already discovered:

1. A passive-enumeration tool's output (subfinder against Certificate \
Transparency logs).
2. A deterministic regex extractor's output (URL-shaped strings linked \
from the homepage HTML).

Your job is the INFERENCE LAYER on top of those two extraction stages. \
Propose candidate subdomains the homepage SUGGESTS but doesn't directly \
link to — the engineering, internal, non-prod, and pattern-implied surfaces \
that a regex can't surface from the same input.

Two distinct categories to produce
----------------------------------

(A) **Extraction-backed candidates.** Subdomains the homepage clearly \
references — through prose mentions, product names, or footer links. \
These are mostly customer-facing surfaces (``docs``, ``support``, \
``status``, ``api``, ``careers``, ``blog``, ``press``). You're allowed \
to propose these even if they also appear in the regex list (the merge \
step deduplicates). One short rationale per candidate.

(B) **Inference-only candidates.** Subdomains the homepage *implies* \
through business context but does NOT link. This is the load-bearing \
category — the value you add over a regex baseline:

- "Engineering team", "production and staging environments", "API \
versioning", "v2 launch" → ``staging.``, ``dev.``, ``qa.``, \
``api-dev.``, ``api-staging.``, ``api-v2.``.
- Mentions of internal tooling, single-sign-on, employee portals → \
``sso.``, ``okta.``, ``internal.``, ``admin.``, ``portal-admin.``.
- B2B/fintech infrastructure ("payment processing", "webhooks", \
"merchant"): ``payments.``, ``webhook.``, ``merchant.``, ``billing.``.
- DevOps tooling signals (CI/CD, monitoring): ``ci.``, ``jenkins.``, \
``grafana.``, ``kibana.``, ``monitor.``.
- Partner ecosystem ("integration partners", "channel partners"): \
``partners.``, ``partner-portal.``, ``vendors.``.
- Geographic / multi-region signals (London office, EU GDPR copy): \
``uk.``, ``eu.``, ``us.``, country-coded subdomains.

In your rationale field, MAKE THE CATEGORY EXPLICIT: lead with "Linked \
from homepage..." for (A) candidates or "Inferred from..." for (B) \
candidates. The downstream report uses this signal.

Hard rules
----------

- Every ``host`` value must end with the supplied root domain. Inventing \
``careers.other-company.com`` is wrong.
- Use only lowercase ASCII letters, digits, hyphens, and dots. No \
internationalised labels.
- Up to 25 candidates. Aim for a mix of (A) and (B), weighted toward (B) \
since that's where you add value.
- If the homepage is empty / a redirect / a CAPTCHA / JS-only and gives \
no signal, return AT MOST 5 generic-but-defensible candidates \
(``support``, ``api``, ``status``, ``docs``, ``blog``) with rationale \
"no homepage signal; defensible generic guess".
"""


class GeneratorError(RuntimeError):
    """Raised when the generator call fails (missing key, tool refusal, etc.)."""


def generate_candidates(
    *,
    root_domain: str,
    homepage_text: str,
    already_discovered: list[str],
    max_candidates: int = 25,
    model: str = "claude-haiku-4-5",
    api_key: str | None = None,
    max_tokens: int = 4096,
) -> CandidateList:
    """Call Claude to propose extra candidates from the homepage.

    Returns a :py:class:`CandidateList`. Invented-host filtering (host
    not ending in root_domain) happens in the caller — keeps this
    function single-purpose.
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise GeneratorError(
            "ANTHROPIC_API_KEY not set. Add it to .env or pass --api-key."
        )

    # Lazy SDK import — schema-only tests don't need anthropic installed.
    from anthropic import Anthropic

    tool_schema = CandidateList.model_json_schema()
    tool = {
        "name": "record_candidates",
        "description": (
            "Record the proposed subdomain candidates based on the target's "
            "homepage business signals."
        ),
        "input_schema": tool_schema,
    }

    user_message = (
        f"Root domain: {root_domain}\n"
        f"Maximum candidates: {max_candidates}\n\n"
        f"Already discovered ({len(already_discovered)} from passive sources — "
        f"DO NOT REPEAT):\n"
        f"{_format_known_list(already_discovered)}\n\n"
        f"Cleaned homepage text:\n"
        "```\n"
        f"{homepage_text or '(no usable homepage text — page was empty / a redirect / JS-only)'}\n"
        "```\n\n"
        "Call the record_candidates tool with your proposed additional "
        f"subdomains. Return at most {max_candidates} candidates."
    )

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        tools=[tool],
        tool_choice={"type": "tool", "name": "record_candidates"},
        messages=[{"role": "user", "content": user_message}],
    )

    tool_use_block = _find_tool_use(response.content, "record_candidates")
    if tool_use_block is None:
        raise GeneratorError(
            "Claude did not invoke the record_candidates tool. "
            f"Stop reason: {response.stop_reason}. "
            f"Raw content: {response.content!r}"
        )

    return CandidateList.model_validate(tool_use_block["input"])


def filter_to_root(candidates: list[CandidateSubdomain], root: str) -> list[CandidateSubdomain]:
    """Drop any candidate whose host doesn't end with the root domain.

    Claude occasionally invents a hostname under a different domain when
    the homepage mentions a partner brand. We log + drop those rather
    than send them downstream.
    """
    root = root.lower().rstrip(".")
    kept: list[CandidateSubdomain] = []
    for c in candidates:
        host = c.host.lower().rstrip(".")
        if host == root or host.endswith("." + root):
            kept.append(c)
    return kept


def _format_known_list(hosts: list[str]) -> str:
    """Render a list of known hosts as a bullet list, trimmed for token cost."""
    if not hosts:
        return "  (none — passive sources returned no subdomains)"
    # Cap the inline list at 60 to keep token cost predictable; the
    # generator's job is to add NEW candidates, not memorise the full
    # passive list.
    visible = hosts[:60]
    overflow = len(hosts) - len(visible)
    lines = [f"  - {h}" for h in visible]
    if overflow > 0:
        lines.append(f"  - ... ({overflow} more)")
    return "\n".join(lines)


def _find_tool_use(content_blocks: list[Any], tool_name: str) -> dict | None:
    for block in content_blocks:
        if getattr(block, "type", None) == "tool_use":
            if getattr(block, "name", None) == tool_name:
                return {"name": block.name, "input": block.input}
    return None


__all__ = [
    "CandidateList",
    "CandidateSubdomain",
    "GeneratorError",
    "SYSTEM_PROMPT",
    "filter_to_root",
    "generate_candidates",
]
