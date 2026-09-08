"""
Layer 6 — Threat Classifier.

THIS IS NOT GPT. This is a deterministic, rule-based decision layer that
consumes correlated evidence + rule hits (which already incorporate the
LLM's advisory scores as ordinary weighted inputs) and assigns a final
category. Every decision is traceable to specific rule IDs.
"""
from __future__ import annotations

from app.schemas.evidence import Evidence, RuleHit, Severity, ThreatResult
from app.correlation.scoring import compute_risk_score, confidence_for_score

CATEGORY_TREE = {
    "PHISHING": ["Credential phishing", "Account takeover", "Brand impersonation"],
    "BEC": ["Executive impersonation", "Payment request", "Invoice fraud"],
    "MALWARE": ["Malicious attachment", "Malicious payload"],
    "SPOOFING": [],
    "SCAM": [],
    "SPAM": [],
    "BENIGN": [],
}


def _has(evidence: list[Evidence], type_: str, min_value: float | None = None) -> bool:
    for ev in evidence:
        if ev.type == type_:
            if min_value is None:
                return bool(ev.value)
            try:
                return float(ev.value) >= min_value
            except (TypeError, ValueError):
                return False
    return False


def _rule_ids(hits: list[RuleHit]) -> set[str]:
    return {h.rule_id for h in hits}


def classify_threat(
    evidence: list[Evidence],
    rule_hits: list[RuleHit],
) -> ThreatResult:
    fired = _rule_ids(rule_hits)
    risk_score, contributions = compute_risk_score(rule_hits)
    reasoning: list[str] = [h.description for h in rule_hits]

    credential_request = _has(evidence, "CREDENTIAL_REQUEST", 0.6)
    phishing_intent = _has(evidence, "PHISHING_INTENT", 0.6)
    impersonation = _has(evidence, "IMPERSONATION_STYLE", 0.6)
    financial_request = _has(evidence, "FINANCIAL_REQUEST", 0.6)
    identity_mismatch = bool(
        fired & {"FROM_REPLYTO_MISMATCH", "FROM_RETURNPATH_MISMATCH", "AUTH_FAILURE_PLUS_SENDER_MISMATCH"}
    )
    suspicious_domain = bool(
        fired & {"SUSPICIOUS_DOMAIN_AGE", "PUNYCODE_DOMAIN_OR_URL", "BRAND_SIMILARITY_MATCH", "PUNYCODE_PLUS_BRAND_SIMILARITY"}
    )
    malicious_attachment = bool(fired & {"YARA_MATCH", "MACRO_DETECTED", "MIME_MISMATCH", "EXECUTABLE_ATTACHMENT"})
    auth_failure = "DMARC_FAILURE" in fired
    suspicious_url = bool(fired & {"IP_BASED_URL", "SUSPICIOUS_URL_PLUS_HIGH_PHISHING_INTENT", "MULTIPLE_REDIRECTS"})
    brand_mismatch = "DISPLAY_NAME_BRAND_MISMATCH" in fired

    category = "BENIGN"
    subcategory = None

    # Ordered decision logic — first strong match wins. Kept simple and
    # explainable rather than a black-box weighted vote, per spec.
    if malicious_attachment and ("YARA_MATCH" in fired or "MACRO_DETECTED" in fired or "MIME_MISMATCH" in fired):
        category = "MALWARE"
        subcategory = "Malicious attachment"
    elif credential_request and (suspicious_url or suspicious_domain) and (phishing_intent or impersonation):
        category = "PHISHING"
        subcategory = "Brand impersonation" if brand_mismatch else "Credential phishing"
    elif financial_request and identity_mismatch and impersonation:
        category = "BEC"
        subcategory = "Payment request"
    elif identity_mismatch and auth_failure and not (phishing_intent or credential_request):
        category = "SPOOFING"
    elif phishing_intent and not credential_request and not malicious_attachment:
        category = "SCAM"
        subcategory = None
    elif risk_score >= 15 and risk_score < 35 and not (malicious_attachment or credential_request):
        category = "SPAM"
    else:
        category = "BENIGN"

    if risk_score == 0 and not rule_hits:
        reasoning.append("No deterministic rules fired and no significant evidence was found.")

    confidence = confidence_for_score(risk_score, len(evidence))

    if not reasoning:
        reasoning = ["Insufficient evidence to support a stronger classification than BENIGN."]

    return ThreatResult(
        category=category,
        subcategory=subcategory,
        risk_score=risk_score,
        confidence=confidence,
        reasoning=reasoning,
    )
