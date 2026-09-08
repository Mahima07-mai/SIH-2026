"""
Layer 4.3 — Deterministic Scoring.

Explainable, additive scoring. Weights are configurable constants (not
learned, not black-box) so the report can always show exactly why a score
is what it is. Final score is clamped to 0-100.
"""
from __future__ import annotations

from app.schemas.evidence import RuleHit

# Example weights — tune freely. Kept in one place so the whole scoring
# policy is auditable at a glance.
RULE_WEIGHTS: dict[str, int] = {
    "DMARC_FAILURE": 15,
    "FROM_REPLYTO_MISMATCH": 12,
    "FROM_RETURNPATH_MISMATCH": 8,
    "DISPLAY_NAME_BRAND_MISMATCH": 12,
    "SUSPICIOUS_DOMAIN_AGE": 15,
    "PUNYCODE_DOMAIN_OR_URL": 12,
    "BRAND_SIMILARITY_MATCH": 10,
    "IP_BASED_URL": 8,
    "MIME_MISMATCH": 20,
    "EXECUTABLE_ATTACHMENT": 20,
    "MACRO_DETECTED": 15,
    "YARA_MATCH": 25,
    "HIGH_PHISHING_INTENT": 15,
    "HIGH_CREDENTIAL_REQUEST": 12,
    "HIGH_URGENCY": 6,
    "HIGH_SOCIAL_ENGINEERING": 10,
    "MULTIPLE_REDIRECTS": 6,
}


def compute_risk_score(rule_hits: list[RuleHit]) -> tuple[int, list[dict]]:
    """Sum rule contributions, clamp to 0-100, and return the breakdown."""
    total = sum(hit.score_contribution for hit in rule_hits)
    risk_score = max(0, min(100, total))
    contributions = [
        {"rule": hit.rule_id, "score": hit.score_contribution, "description": hit.description}
        for hit in rule_hits
    ]
    return risk_score, contributions


def confidence_for_score(risk_score: int, evidence_count: int) -> str:
    """A simple, explainable confidence heuristic — more corroborating
    evidence at a given score level => higher confidence."""
    if risk_score >= 70 and evidence_count >= 5:
        return "HIGH"
    if risk_score >= 40 or evidence_count >= 3:
        return "MEDIUM"
    return "LOW"
