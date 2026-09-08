"""
Layer 2.7 — Content / NLP Extractor.

Thin wrapper that turns the advisory LLM output into normalized findings.
Every finding here is explicitly `fact_level=Inferred`, `reliability=Medium`
— this analyzer must never be allowed to produce a final PHISHING/MALWARE
label; that happens only in classifier/threat_classifier.py, using this
plus deterministic evidence.
"""
from __future__ import annotations

from app.schemas.evidence import (
    AnalyzerFinding,
    AnalyzerResult,
    AnalyzerStatus,
    FactLevel,
    Reliability,
    Severity,
)
from app.services.llm_service import analyze_content

_SCORE_LABELS = {
    "urgency": "Urgency",
    "phishing_intent": "Phishing intent",
    "impersonation_style": "Impersonation style",
    "social_engineering": "Social engineering",
    "credential_request": "Credential request",
    "financial_request": "Financial request",
    "account_threat": "Account threat language",
}

HIGH_THRESHOLD = 0.7
MEDIUM_THRESHOLD = 0.4


def _severity_for_score(score: float) -> Severity:
    if score >= HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.INFO


def analyze_nlp(email_id: str, subject: str | None, body: str | None) -> AnalyzerResult:
    result = analyze_content(subject, body)

    if result["status"] != "success":
        return AnalyzerResult(
            analyzer="content_nlp",
            status=AnalyzerStatus.UNAVAILABLE,
            findings=[
                AnalyzerFinding(
                    type="NLP_ANALYSIS",
                    value="unavailable",
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.OBSERVED,
                    description=(
                        f"LLM-based content analysis was unavailable "
                        f"({result.get('reason', 'no reason given')}). Threat "
                        f"classification will proceed on deterministic evidence only."
                    ),
                )
            ],
            error=result.get("reason"),
        )

    scores = result["scores"]
    findings: list[AnalyzerFinding] = []

    for key, label in _SCORE_LABELS.items():
        value = scores.get(key, 0.0)
        findings.append(
            AnalyzerFinding(
                type=key.upper(),
                value=round(value, 2),
                reliability=Reliability.MEDIUM,
                fact_level=FactLevel.INFERRED,
                severity=_severity_for_score(value),
                description=(
                    f"LLM-derived / inferred evidence: {label} score is "
                    f"{value:.2f} (0-1 scale). This is a semantic interpretation, "
                    f"not proof of intent."
                ),
            )
        )

    brand = scores.get("brand_mention")
    if brand:
        findings.append(
            AnalyzerFinding(
                type="BRAND_MENTION",
                value=brand,
                reliability=Reliability.MEDIUM,
                fact_level=FactLevel.INFERRED,
                description=f"LLM-derived / inferred evidence: content appears to reference the brand '{brand}'.",
            )
        )

    return AnalyzerResult(analyzer="content_nlp", status=AnalyzerStatus.SUCCESS, findings=findings)
