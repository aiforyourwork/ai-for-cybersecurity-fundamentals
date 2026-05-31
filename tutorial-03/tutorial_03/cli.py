"""CLI for the T3 subdomain-enum + AI tool.

Three execution modes:

- **Normal**: run subfinder, fetch the homepage, call Claude for
  candidate generation, resolve everything via DNS, send one HTTP GET
  per live host (unless ``--no-verify``), call Claude again to rank,
  print + save the report.
- **--dry-run**: run subfinder, fetch the homepage, resolve via DNS,
  but skip BOTH Claude calls. Useful for verifying the deterministic
  steps in isolation. Zero LLM cost.
- **--mock**: skip subfinder + the homepage fetch + DNS + HTTP + both
  Claude calls. Uses canned fixtures so the pipeline produces the
  same shaped output without any external dependency. For development
  and smoke tests.

Scope is enforced via ``--scope <path>``. The flag is REQUIRED — there
is no "default scope = everything" mode. Any candidate outside the
scope file is hard-filtered before any network call.

Outputs:

- A human-readable funnel summary to stdout.
- The full structured :class:`Report` as JSON at the path given by
  ``--output`` (default ``report.json``).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .generator import (
    CandidateList,
    CandidateSubdomain,
    GeneratorError,
    filter_to_root,
    generate_candidates,
)
from .homepage import Homepage, HomepageFetchError, fetch_homepage
from .ranker import (
    RankedHost,
    RankerError,
    RankingReport,
    rank_hosts,
)
from .regex_extractor import ExtractedCandidate, extract_subdomain_candidates
from .report import (
    HostState,
    Report,
    build_report,
    render_funnel,
)
from .resolver import resolve_many
from .scope import Scope, ScopeError, parse_scope_file
from .subfinder_runner import (
    SubfinderMissingError,
    SubfinderResult,
    run_subfinder,
)
from .verifier import HostProbe, verify_many


DEFAULT_MODEL = "claude-haiku-4-5"
DEFAULT_OUTPUT = "report.json"
DEFAULT_RAW_LOG = "subfinder.log"
DEFAULT_MAX_FROM_PASSIVE = 60
DEFAULT_MAX_FROM_CLAUDE = 25


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m tutorial_03",
        description=(
            "AI-augmented subdomain enumeration. Pipeline: subfinder "
            "(passive) + Claude (candidate generation) → DNS resolution "
            "→ HTTP verification → Claude (ranking). Authorised targets "
            "only — runs are scope-filtered against a required --scope "
            "file."
        ),
    )
    p.add_argument(
        "--domain", required=True,
        help="Root domain to enumerate, e.g. 'hackerone.com'. No scheme.",
    )
    p.add_argument(
        "--scope", required=True,
        help=(
            "Path to the scope file (one wildcard pattern per line). "
            "MANDATORY — hard-filters everything not matching at least "
            "one pattern, before any network call. See scope.example.txt."
        ),
    )
    p.add_argument(
        "--max-from-passive", type=int, default=DEFAULT_MAX_FROM_PASSIVE,
        help=(
            f"Cap the subfinder output at this many subdomains (default: "
            f"{DEFAULT_MAX_FROM_PASSIVE}). For very large targets, the "
            f"visual story drowns without a cap. Pass 0 to disable the cap."
        ),
    )
    p.add_argument(
        "--max-from-claude", type=int, default=DEFAULT_MAX_FROM_CLAUDE,
        help=(
            f"Max candidates the AI generator returns (default: "
            f"{DEFAULT_MAX_FROM_CLAUDE})."
        ),
    )
    p.add_argument(
        "--no-verify", action="store_true",
        help=(
            "Skip the HTTP verification stage. Resolved hosts go straight "
            "to the ranker with status/title/server fields empty. Useful "
            "for true zero-touch passive runs."
        ),
    )
    p.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Claude model for both AI calls (default: {DEFAULT_MODEL}).",
    )
    p.add_argument(
        "--api-key", default=None,
        help="Anthropic API key. Defaults to ANTHROPIC_API_KEY env var.",
    )
    p.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Where to write the structured JSON report (default: {DEFAULT_OUTPUT}).",
    )
    p.add_argument(
        "--raw-log", default=DEFAULT_RAW_LOG,
        help=(
            f"Where to write the raw subfinder stdout (default: {DEFAULT_RAW_LOG}). "
            "Pass an empty string to skip."
        ),
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help=(
            "Run subfinder + homepage fetch + DNS + (optionally) HTTP "
            "verification, but skip BOTH Claude calls. Zero LLM cost."
        ),
    )
    p.add_argument(
        "--mock", action="store_true",
        help=(
            "Skip every external dependency (subfinder, network, Claude). "
            "Uses canned fixtures. For development and smoke tests."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    load_dotenv(override=True)
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── Load scope (mandatory) ─────────────────────────────────────
    try:
        scope = parse_scope_file(Path(args.scope))
    except ScopeError as exc:
        print(f"[error] scope: {exc}", file=sys.stderr)
        return 1

    if not scope.permits_root(args.domain):
        print(
            f"[error] The root domain '{args.domain}' is itself outside the "
            f"scope file at {args.scope}. To enumerate under it, the scope "
            f"file must contain either '{args.domain}' directly or "
            f"'*.{args.domain}'. Fix the scope file or pass a different "
            f"--domain.",
            file=sys.stderr,
        )
        return 1

    # ── Banner ─────────────────────────────────────────────────────
    mode = "MOCK" if args.mock else ("DRY-RUN" if args.dry_run else "LIVE")
    print("=" * 64)
    print("T3 — AI-augmented subdomain enumeration")
    print("=" * 64)
    print(f"  Root domain      : {args.domain}")
    print(f"  Scope patterns   : {len(scope.patterns)} ({', '.join(scope.patterns[:3])}{'...' if len(scope.patterns) > 3 else ''})")
    print(f"  Mode             : {mode}")
    print(f"  Max passive      : {args.max_from_passive or 'unlimited'}")
    print(f"  Max from Claude  : {args.max_from_claude}")
    print(f"  Verify (HTTP)    : {'no' if args.no_verify else 'yes'}")
    print()

    # ── Mock mode ──────────────────────────────────────────────────
    if args.mock:
        report = _run_mock(args.domain, scope)
        _print_and_save(report, output_path=Path(args.output))
        return 0

    # ── Stage 1a: subfinder ────────────────────────────────────────
    try:
        sub_result = run_subfinder(domain=args.domain)
    except SubfinderMissingError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    if not sub_result.ok:
        print(
            f"[warn] subfinder exited {sub_result.returncode}; continuing "
            f"with whatever output landed. stderr tail:\n  "
            f"{sub_result.stderr[-300:]!r}",
            file=sys.stderr,
        )

    passive_hosts = list(sub_result.subdomains)
    if args.max_from_passive and len(passive_hosts) > args.max_from_passive:
        print(
            f"[info] subfinder returned {len(passive_hosts)} subdomains; "
            f"capping to {args.max_from_passive} via --max-from-passive."
        )
        passive_hosts = passive_hosts[: args.max_from_passive]
    print(f"[stage 1a] subfinder: {len(passive_hosts)} subdomain(s).")

    _save_log_to_disk(
        "\n".join(passive_hosts) + "\n",
        path_str=args.raw_log,
        label="subfinder raw output",
    )

    # ── Stage 1b: homepage fetch ───────────────────────────────────
    try:
        homepage = fetch_homepage(args.domain)
    except HomepageFetchError as exc:
        print(
            f"[warn] {exc}. Continuing with empty homepage text — the AI "
            f"generator will return only generic candidates.",
            file=sys.stderr,
        )
        homepage = Homepage(
            url=f"https://{args.domain}/",
            status_code=0,
            title=None,
            text="",
            raw_html="",
        )
    print(
        f"[stage 1b] homepage: {homepage.url} ({homepage.status_code}) "
        f"→ {len(homepage.text):,} chars cleaned."
    )

    # ── Stage 1c: regex extractor ──────────────────────────────────
    # Pulls subdomains the homepage explicitly references (in <a href> or
    # in URL-shaped text strings). Deterministic; no LLM. The Claude
    # generator's value is what it proposes ON TOP of this extracted set —
    # the inference layer over extraction.
    regex_candidates = extract_subdomain_candidates(
        html=homepage.raw_html,
        root_domain=args.domain,
    )
    print(
        f"[stage 1c] regex extractor: {len(regex_candidates)} candidate(s) "
        f"linked from homepage."
    )

    # ── Stage 1d: AI generator ─────────────────────────────────────
    if args.dry_run:
        print("[stage 1d] dry-run: skipping AI generator (no Claude call).")
        ai_candidates: list[CandidateSubdomain] = []
    else:
        try:
            # Feed Claude the union of what we already have so it focuses
            # on net-new inference rather than re-proposing extracted ones.
            already_discovered = list(
                {*passive_hosts, *(c.host for c in regex_candidates)}
            )
            cand_list = generate_candidates(
                root_domain=args.domain,
                homepage_text=homepage.text,
                already_discovered=already_discovered,
                max_candidates=args.max_from_claude,
                model=args.model,
                api_key=args.api_key,
            )
        except GeneratorError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            return 1
        ai_candidates = filter_to_root(list(cand_list.candidates), args.domain)
        print(
            f"[stage 1d] Claude proposed {len(cand_list.candidates)} "
            f"candidate(s); {len(ai_candidates)} kept after root-domain "
            f"filter."
        )

    # ── Stage 1e: combine, dedupe, scope-filter ────────────────────
    states = _merge_candidates(
        passive_hosts=passive_hosts,
        regex_candidates=regex_candidates,
        ai_candidates=ai_candidates,
        scope=scope,
    )
    n_subfinder_only = sum(1 for s in states if s.sources == ["subfinder"])
    n_regex = sum(1 for s in states if "regex" in s.sources)
    n_ai_only = sum(
        1 for s in states
        if "ai" in s.sources
        and "regex" not in s.sources
        and "subfinder" not in s.sources
    )
    print(
        f"[stage 1e] candidates: {len(states)} unique in scope "
        f"({n_subfinder_only} subfinder-only, {n_regex} regex, "
        f"{n_ai_only} AI-only / inferred)."
    )

    # ── Stage 2: DNS resolution ────────────────────────────────────
    resolution_targets = [s.host for s in states]
    resolutions = resolve_many(resolution_targets)
    for state, r in zip(states, resolutions):
        state.resolved = r.resolved
        state.addresses = list(r.addresses)
    print(
        f"[stage 2] DNS: {sum(1 for s in states if s.resolved)} / "
        f"{len(states)} resolved."
    )

    # ── Stage 3: HTTP verification (optional) ──────────────────────
    if args.no_verify:
        print("[stage 3] HTTP verification: skipped (--no-verify).")
    else:
        live_targets = [s.host for s in states if s.resolved]
        probes = verify_many(live_targets) if live_targets else []
        by_host = {p.host: p for p in probes}
        for s in states:
            p = by_host.get(s.host)
            if p is None:
                continue
            s.live_web = p.live
            s.status_code = p.status_code
            s.title = p.title
            s.server = p.server
        print(
            f"[stage 3] HTTP: {sum(1 for s in states if s.live_web)} / "
            f"{sum(1 for s in states if s.resolved)} live."
        )

    # ── Stage 4: ranker ────────────────────────────────────────────
    if args.dry_run:
        print("[stage 4] dry-run: skipping AI ranker (no Claude call).")
        headline = (
            "Dry-run complete; ranker skipped. "
            f"{sum(1 for s in states if s.resolved)} resolved, "
            f"{sum(1 for s in states if s.live_web)} live web."
        )
    else:
        rankable_states = [s for s in states if s.live_web or s.resolved]
        rankable_records: list[dict[str, Any]] = [
            {
                "host": s.host,
                "status_code": s.status_code,
                "title": s.title,
                "server": s.server,
            }
            for s in rankable_states
        ]
        if not rankable_records:
            print(
                "[stage 4] nothing to rank — no hosts resolved. Skipping "
                "Claude call."
            )
            headline = "Nothing resolved; ranker skipped."
        else:
            try:
                ranking = rank_hosts(
                    host_records=rankable_records,
                    root_domain=args.domain,
                    model=args.model,
                    api_key=args.api_key,
                )
            except RankerError as exc:
                print(f"[error] {exc}", file=sys.stderr)
                return 1
            _attach_ranking_to_states(states, ranking)
            headline = ranking.headline
            print(
                f"[stage 4] ranker: {len(ranking.hosts)} host(s) ranked. "
                f"Headline: {headline}"
            )

    # ── Build + emit report ────────────────────────────────────────
    report = build_report(
        root_domain=args.domain,
        scope_patterns=list(scope.patterns),
        states=states,
        headline=headline,
    )
    _print_and_save(report, output_path=Path(args.output))
    return 0


# ─── Orchestration helpers ──────────────────────────────────────────────────

def _merge_candidates(
    *,
    passive_hosts: list[str],
    regex_candidates: list[ExtractedCandidate],
    ai_candidates: list[CandidateSubdomain],
    scope: Scope,
) -> list[HostState]:
    """Combine subfinder + regex + Claude outputs into a deduplicated,
    scope-filtered list of :class:`HostState`.

    Order: subfinder hits first, then regex extractions, then net-new AI.
    Each ``HostState.sources`` records every source that surfaced the host
    so the report can show the regex-vs-AI split.
    """
    by_host: dict[str, HostState] = {}
    out_of_scope_dropped = 0

    for h in passive_hosts:
        h_norm = h.lower().rstrip(".")
        if not scope.matches(h_norm):
            out_of_scope_dropped += 1
            continue
        by_host.setdefault(h_norm, HostState(host=h_norm)).sources.append("subfinder")

    for ext in regex_candidates:
        h_norm = ext.host.lower().rstrip(".")
        if not scope.matches(h_norm):
            out_of_scope_dropped += 1
            continue
        state = by_host.setdefault(h_norm, HostState(host=h_norm))
        if "regex" not in state.sources:
            state.sources.append("regex")

    for cand in ai_candidates:
        h_norm = cand.host.lower().rstrip(".")
        if not scope.matches(h_norm):
            out_of_scope_dropped += 1
            continue
        state = by_host.setdefault(h_norm, HostState(host=h_norm))
        if "ai" not in state.sources:
            state.sources.append("ai")
        state.ai_rationale = cand.rationale

    if out_of_scope_dropped:
        print(
            f"[scope] dropped {out_of_scope_dropped} candidate(s) outside "
            f"the scope file."
        )

    # De-duplicate sources for each state, preserving first-occurrence order.
    for state in by_host.values():
        seen: set[str] = set()
        deduped: list[str] = []
        for src in state.sources:
            if src not in seen:
                seen.add(src)
                deduped.append(src)
        state.sources = deduped

    return list(by_host.values())


def _attach_ranking_to_states(
    states: list[HostState],
    ranking: RankingReport,
) -> None:
    """Apply the ranker's priority + value to each matching host state."""
    by_host = {h.host.lower().rstrip("."): h for h in ranking.hosts}
    for state in states:
        match = by_host.get(state.host)
        if match is not None:
            state.priority = match.priority
            state.value = match.value


# ─── Output helpers ─────────────────────────────────────────────────────────

def _save_log_to_disk(content: str, *, path_str: str | None, label: str) -> None:
    if not path_str:
        return
    path = Path(path_str)
    path.write_text(content, encoding="utf-8")
    print(f"[ok] {label} saved to {path} ({len(content):,} chars)")


def _print_and_save(report: Report, *, output_path: Path) -> None:
    print()
    print("─── Pipeline funnel " + "─" * 40)
    print(render_funnel(report))
    print("─" * 60)
    output_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(f"\n[ok] Structured report saved to {output_path}")


# ─── Fixtures for --mock ────────────────────────────────────────────────────
#
# The mock pretends to be a passive enum of a fictional fintech-y target
# called "demo-target.test". It produces the same Report shape the real
# pipeline does, with deliberately interesting findings so the funnel
# visual lands without needing network access.

_MOCK_PASSIVE = [
    # Subfinder simulates CT-log historicals: a small set including
    # one half-stale name (`marketing.`) that DNS won't resolve.
    "www.demo-target.test",
    "mail.demo-target.test",
    "blog.demo-target.test",
    "cdn.demo-target.test",
    "marketing.demo-target.test",
    "shop.demo-target.test",
]

# Regex extractor — subdomains the (fictional) homepage links directly
# via <a href="https://...">. Customer-facing marketing surfaces, mostly low
# priority once the ranker sees them. These overlap with Claude's output.
_MOCK_REGEX_EXTRACTED = [
    "careers.demo-target.test",
    "status.demo-target.test",
    "support.demo-target.test",
    "blog.demo-target.test",          # also from subfinder; double-source
    "shop.demo-target.test",           # also from subfinder; double-source
]

# Claude generator — proposes the regex-extracted set PLUS inferred candidates
# from prose signals (engineering team, API versions, internal infra). The
# inferred-only candidates are the load-bearing high-priority findings — the
# whole pedagogical pitch.
_MOCK_AI_GENERATED = [
    # Overlap with regex (low value-add — Claude could read these off the page)
    ("careers.demo-target.test", "Careers page linked from footer."),
    ("status.demo-target.test", "Status page linked from footer."),
    ("support.demo-target.test", "Support portal linked from footer."),
    # Inference-only (the actual value-add — regex can't find these)
    ("api-dev.demo-target.test", "Homepage mentions API + 'developer' env; non-prod API likely."),
    ("admin.demo-target.test", "B2B SaaS; admin portal for staff is the standard pattern."),
    ("staging.demo-target.test", "Homepage mentions production/staging envs; staging surface likely."),
    ("sso.demo-target.test", "Homepage mentions SSO; identity-provider surface inferable."),
    ("internal.demo-target.test", "Generic-but-defensible: internal-tools subdomain."),
]

# Per-host fixtures: address, http status, title, server, priority, value.
# `live_web` derives from status_code being not None.
_MOCK_HOST_FIXTURES: dict[str, dict[str, Any]] = {
    "www.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.10"],
        "status_code": 200, "title": "Demo Target — pay your bills",
        "server": "cloudflare",
        "priority": "low",
        "value": "Marketing homepage; CDN-served; low-interest for offence.",
    },
    "mail.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.11"],
        "status_code": None, "title": None, "server": None,
        "priority": None, "value": None,    # MX, not web
    },
    "blog.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.12"],
        "status_code": 200, "title": "Demo Target blog",
        "server": "nginx",
        "priority": "low",
        "value": "Marketing blog; nginx default; low-interest.",
    },
    "cdn.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.13"],
        "status_code": 403, "title": None, "server": "cloudfront",
        "priority": "low",
        "value": "CDN apex; expected 403 on bare GET; low-interest.",
    },
    "marketing.demo-target.test": {
        "resolved": False, "addresses": [],
        "status_code": None, "title": None, "server": None,
        "priority": None, "value": None,
    },
    "shop.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.14"],
        "status_code": 200, "title": "Demo Target shop — sign in",
        "server": "nginx",
        "priority": "medium",
        "value": "Customer-facing storefront with auth; real but not opening-night.",
    },
    "careers.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.15"],
        "status_code": 200, "title": "Careers at Demo Target",
        "server": "nginx",
        "priority": "low",
        "value": "Public careers page; low-interest for offence.",
    },
    "status.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.16"],
        "status_code": 200, "title": "Demo Target status",
        "server": "Statuspage",
        "priority": "low",
        "value": "Statuspage.io tenant; no admin surface; low-interest.",
    },
    "support.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.17"],
        "status_code": 200, "title": "Help — Demo Target",
        "server": "Zendesk",
        "priority": "medium",
        "value": "Zendesk help centre; customer login surface.",
    },
    "api-dev.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.18"],
        "status_code": 200, "title": "Swagger UI",
        "server": "nginx",
        "priority": "high",
        "value": "Swagger UI exposed — non-prod API surface; high-interest.",
    },
    "admin.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.19"],
        "status_code": 401, "title": None, "server": "nginx",
        "priority": "high",
        "value": "Auth-required admin login; non-prod env suspected.",
    },
    "staging.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.20"],
        "status_code": 401, "title": None, "server": "nginx",
        "priority": "high",
        "value": "Non-prod env behind basic auth; high-interest.",
    },
    "sso.demo-target.test": {
        "resolved": True, "addresses": ["203.0.113.21"],
        "status_code": 200, "title": "Sign in",
        "server": "nginx",
        "priority": "medium",
        "value": "Identity-provider login surface; medium-interest.",
    },
    "internal.demo-target.test": {
        "resolved": False, "addresses": [],
        "status_code": None, "title": None, "server": None,
        "priority": None, "value": None,    # internal-only; no public DNS
    },
}


def _run_mock(domain: str, scope: Scope) -> Report:
    """Build a Report from canned fixtures, applying the same scope filter
    the real pipeline would. Lets readers see the pipeline's output shape
    without a network, an API key, or subfinder being installed.

    Note: the mock target is `demo-target.test` — `.test` is a reserved
    TLD per RFC 2606, so no real hostname will ever collide with the
    fixture. If the user's scope file allows `*.demo-target.test`, the
    mock displays its full funnel; otherwise it shows just the scope-
    filtering step. Either way the pipeline's structure is visible.
    """
    print(f"[mock] Pretending to enumerate '{domain}' using fixture data.")
    print("[mock] (No network calls; no API spend; no subfinder.)")
    print()

    states = _merge_candidates(
        passive_hosts=list(_MOCK_PASSIVE),
        regex_candidates=[
            ExtractedCandidate(host=h, source_type="link")
            for h in _MOCK_REGEX_EXTRACTED
        ],
        ai_candidates=[
            CandidateSubdomain(host=h, rationale=r) for h, r in _MOCK_AI_GENERATED
        ],
        scope=scope,
    )

    for s in states:
        fx = _MOCK_HOST_FIXTURES.get(s.host)
        if fx is None:
            continue
        s.resolved = fx["resolved"]
        s.addresses = list(fx["addresses"])
        s.live_web = fx["status_code"] is not None
        s.status_code = fx["status_code"]
        s.title = fx["title"]
        s.server = fx["server"]
        s.priority = fx["priority"]
        s.value = fx["value"]

    headline = (
        "3 high-priority findings ALL from Claude's inference layer: "
        "api-dev. (Swagger UI), admin. (401), staging. (401) — none of these "
        "were extracted from the homepage or found by subfinder."
        if any(s.priority == "high" for s in states)
        else "No high-priority findings under the supplied scope."
    )

    return build_report(
        root_domain=domain,
        scope_patterns=list(scope.patterns),
        states=states,
        headline=headline,
    )


__all__ = ["build_parser", "main"]
