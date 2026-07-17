"""Structured schema for the consolidated assessment (forced via Claude tool-use)."""
from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    title: str
    asset: str = Field(..., description="Affected asset: a URL, host, or file:line.")
    source: str = Field(
        ...,
        description='Origin of the finding, e.g. "Dynamic (sqlmap)", "Static (semgrep)", '
                    '"Recon", or "Static + Dynamic (corroborated)" when signals agree.',
    )
    severity: str = Field(..., description="Critical | High | Medium | Low | Informational")
    confidence: str = Field(..., description="High | Medium | Low")
    cwe: str | None = Field(None, description='e.g. "CWE-89"')
    owasp: str | None = Field(None, description='OWASP Top 10 2021, e.g. "A03:2021 – Injection"')
    mitre_attack: list[str] = Field(
        default_factory=list, description='MITRE ATT&CK technique IDs, e.g. ["T1190"]'
    )
    evidence: str = Field(..., description="Concrete evidence, citing the tool output.")
    remediation: str = Field(..., description="Specific, actionable fix.")


class Assessment(BaseModel):
    executive_summary: str = Field(..., description="3-6 sentences for a non-technical reader.")
    overall_severity: str = Field(..., description="Worst finding: Critical/High/Medium/Low/Informational")
    findings: list[Finding] = Field(default_factory=list)
    attack_surface_notes: str = Field("", description="Exposure summary from recon, with risk framing.")
    recommendations: list[str] = Field(default_factory=list, description="3-6 prioritized actions.")


__all__ = ["Finding", "Assessment"]
