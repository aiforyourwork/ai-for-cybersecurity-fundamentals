"""Claude call #2 — resolved+verified hosts → priority-ranked list.

The funnel's final stage. After resolution drops dead names and HTTP
verification confirms live web services, the ranker looks at each
survivor's title + status code + server header and assigns a priority:

  - ``high``    engineering / admin / staging / non-prod / API leak signals
  - ``medium``  customer-facing apps with auth
  - ``low``     marketing / static / docs / CDN-served pages

Forced output via Anthropic tool-use, same pattern as the generator.
"""
from __future__ import annotations

import os
from typing import Any, Literal

from pydantic import BaseModel, Field


Priority = Literal["high", "medium", "low"]


# ─── Output schema ──────────────────────────────────────────────────────────

class RankedHost(BaseModel):
    """One host's priority assignment."""

    host: str = Field(
        ...,
        description=(
            "The host being ranked. Must match a host from the input "
            "list verbatim."
        ),
    )
    priority: Priority = Field(
        ...,
        description=(
            "High = engineering / admin / staging / non-prod env / API "
            "or Swagger UI / login portal for internal use. Medium = "
            "customer-facing app with auth, e.g. user portal, account "
            "dashboard. Low = static / marketing / docs / blog / CDN."
        ),
    )
    value: str = Field(
        ...,
        description=(
            "One short sentence on what the host likely is and why "
            "it earned this priority. Aim for ≤100 chars."
        ),
    )


class RankingReport(BaseModel):
    """The structured ranker output."""

    hosts: list[RankedHost] = Field(
        default_factory=list,
        description=(
            "Priority-ranked hosts — one entry per input host. "
            "Caller is responsible for sorting by priority for display."
        ),
    )
    headline: str = Field(
        ...,
        description=(
            "One sentence summarising the most interesting findings "
            "across all ranked hosts. Aim for ≤140 chars."
        ),
    )


# ─── Ranker call ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a security analyst triaging live web hosts discovered during \
reconnaissance on an authorised target. For each host below — with its \
HTTP status code, response title, and server header (where available) \
— assign a priority and a one-line ``value`` explaining what the host \
likely is.

The HTTP status code is the STRONGEST signal for prioritisation. \
Hostname patterns guide interpretation but should NOT override what \
the response actually tells you.

Priority rubric
---------------

**``high``** — actively interesting; investigate first thing tomorrow. \
Specific signals:

- ``200`` with default pages from non-prod tooling (Jenkins login, \
GitLab login, Grafana, Kibana, phpMyAdmin, Swagger UI, Spring Boot \
banner) regardless of hostname.
- ``200`` from a hostname strongly suggesting non-prod / internal \
infra (``admin.``, ``staging.``, ``dev.``, ``qa.``, ``test.``, \
``internal.``, ``api-dev.``, ``api-v2.`` when v2 is signalled as \
non-prod). The 200 means it's actually serving content right now.
- ``401`` or ``403`` from hostnames suggesting non-prod / internal \
(``admin.``, ``staging.``, ``dev.``, ``qa.``, ``internal.``, \
``webhook.`` where the prose implies it's auth-protected). The auth \
challenge tells you something exists behind it.

**``medium``** — real but the path to interesting findings is longer:

- ``200`` with a customer-facing login form on a non-engineering \
hostname (user portal, account dashboard, member area, partner portal).
- ``401`` / ``403`` from customer-facing hostnames (``api.``, \
``support.``, ``partners.``).
- Identity-provider login surfaces (``sso.``, ``okta.``).

**``low``** — OSINT context only; not a near-term exploitation target:

- ``200`` with marketing / static / docs content (``careers.``, \
``blog.``, ``status.``, ``docs.``, ``press.``, CDN-fronted brochure \
pages, status pages).
- **``404`` from ANY hostname — default to low.** A 404 means the \
host name resolves but the server has no content to serve right now. \
That's the OPPOSITE of "interesting" — there's nothing to look at \
today. The hostname might be a placeholder, a misconfigured wildcard, \
a legacy name kept in DNS for historical reasons, or a domain reserved \
for future use. None of those are immediate findings. **Do not let \
the URL pattern (``admin``, ``staging``, etc.) override the 404 — \
the 404 is the signal.** The host might become interesting later; \
make a note, move on.
- ``5xx`` responses from any hostname (the server is broken or \
overloaded; no findable surface today).
- Hosts that did not respond at all (probe failed).

The ONLY 404 case worth upgrading is one with a hostname so specifically \
operational (e.g. a literal ``vpn.``, ``jenkins.``, ``admin-internal.``) \
AND the broader context (multiple sibling subdomains active) gives a \
real reason to suspect "currently dormant but architecturally present." \
Even then, prefer ``medium`` over ``high`` for these.

Hard rules
----------

- Produce EXACTLY ONE entry per input host. Match the ``host`` field \
verbatim — including case — to the input.
- The ``value`` field is at most one sentence, ≤100 chars. This is \
the line the analyst reads at a glance. For 404s, lead with the status: \
"404; no content served — name resolves but nothing to investigate."
- The top-level ``headline`` is one sentence (≤140 chars) summarising \
the most interesting find. Lead with hosts that actually serve \
something (200 / 401) — NOT the 404s.
- Calibration check: if your output has more than 5 ``high`` priorities \
from 404 responses, the rubric isn't being applied — re-rank with the \
status code as the dominant signal.
"""


class RankerError(RuntimeError):
    """Raised when the ranker call fails."""


def rank_hosts(
    *,
    host_records: list[dict[str, Any]],
    root_domain: str,
    model: str = "claude-haiku-4-5",
    api_key: str | None = None,
    max_tokens: int = 4096,
) -> RankingReport:
    """Call Claude to rank the live hosts.

    ``host_records`` is a list of dicts with keys: ``host`` (str),
    ``status_code`` (int|None), ``title`` (str|None), ``server`` (str|None).
    """
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RankerError(
            "ANTHROPIC_API_KEY not set. Add it to .env or pass --api-key."
        )

    from anthropic import Anthropic

    tool_schema = RankingReport.model_json_schema()
    tool = {
        "name": "record_ranking",
        "description": (
            "Record the priority-ranked hosts and a one-line headline "
            "summarising the most interesting findings."
        ),
        "input_schema": tool_schema,
    }

    table = _format_host_table(host_records)
    user_message = (
        f"Root domain: {root_domain}\n"
        f"Live hosts to rank ({len(host_records)} total):\n\n"
        f"{table}\n\n"
        "Call the record_ranking tool. Produce exactly one RankedHost "
        "per row above, then write the top-level headline."
    )

    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        tools=[tool],
        tool_choice={"type": "tool", "name": "record_ranking"},
        messages=[{"role": "user", "content": user_message}],
    )

    tool_use_block = _find_tool_use(response.content, "record_ranking")
    if tool_use_block is None:
        raise RankerError(
            "Claude did not invoke the record_ranking tool. "
            f"Stop reason: {response.stop_reason}. "
            f"Raw content: {response.content!r}"
        )

    return RankingReport.model_validate(tool_use_block["input"])


def _format_host_table(records: list[dict[str, Any]]) -> str:
    """Render the host records as a compact text table for the prompt."""
    lines = []
    for r in records:
        host = r.get("host", "?")
        status = r.get("status_code")
        title = (r.get("title") or "").strip() or "(no title)"
        server = (r.get("server") or "").strip() or "(no server hdr)"
        status_str = str(status) if status is not None else "-"
        lines.append(f"  - {host}  [{status_str}]  {server}  | {title}")
    return "\n".join(lines)


def _find_tool_use(content_blocks: list[Any], tool_name: str) -> dict | None:
    for block in content_blocks:
        if getattr(block, "type", None) == "tool_use":
            if getattr(block, "name", None) == tool_name:
                return {"name": block.name, "input": block.input}
    return None


PRIORITY_ORDER: dict[Priority, int] = {"high": 0, "medium": 1, "low": 2}


def sort_by_priority(hosts: list[RankedHost]) -> list[RankedHost]:
    """Stable sort by priority (high → medium → low)."""
    return sorted(hosts, key=lambda h: PRIORITY_ORDER.get(h.priority, 3))


__all__ = [
    "Priority",
    "PRIORITY_ORDER",
    "RankedHost",
    "RankerError",
    "RankingReport",
    "SYSTEM_PROMPT",
    "rank_hosts",
    "sort_by_priority",
]
