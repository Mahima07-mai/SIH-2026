"""
Layer 6 — Threat Classifier.

THIS IS NOT GPT. This is a deterministic, rule-based decision layer that
consumes correlated evidence + rule hits (which already incorporate the
model-derived advisory evidence as ordinary weighted inputs) and assigns a final
category. Every decision is traceable to specific rule IDs.
"""
from __future__ import annotations

from app.config import get_settings
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
    rule_risk_score, contributions = compute_risk_score(rule_hits)
    reasoning: list[str] = [h.description for h in rule_hits]

    credential_request = _has(evidence, "CREDENTIAL_REQUEST", 0.6)
    phishing_intent = _has(evidence, "PHISHING_INTENT", 0.6)
    impersonation = _has(evidence, "IMPERSONATION_STYLE", 0.6)
    financial_request = _has(evidence, "FINANCIAL_REQUEST", 0.6)
    bec_intent = _has(evidence, "BEC_INTENT", 0.5)
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
    spam_probability = next(
        (float(ev.value) for ev in evidence if ev.type == "SPAM_PROBABILITY"), 0.0
    )
    model_category = next(
        (str(ev.value) for ev in evidence if ev.type == "MODEL_CATEGORY"), ""
    )
    model_category_probability = next(
        (
            float(ev.value.get(model_category, 0.0))
            for ev in evidence
            if ev.type == "MODEL_CATEGORY_PROBABILITIES" and isinstance(ev.value, dict)
        ),
        0.0,
    )
    model_risk_score = next(
        (int(ev.value) for ev in evidence if ev.type == "MODEL_RISK_SCORE"),
        rule_risk_score,
    )
    category = "BENIGN"
    subcategory = None

    # The trained multiclass model selects the category. Rule hits explain
    # corroborating evidence but do not map numeric score bands to labels.
    if model_category:
        category = model_category
        subcategory = {
            "PHISHING": "Brand impersonation" if brand_mismatch else "Credential phishing",
            "BEC": "Payment request" if financial_request or bec_intent else "Executive impersonation",
            "MALWARE": "Malicious attachment",
        }.get(category)
    else:
        category = "BENIGN"
        subcategory = None

    auth_pass = all(
        any(ev.type == f"{mechanism}_RESULT" and str(ev.value).upper() == "PASS" for ev in evidence)
        for mechanism in ("SPF", "DKIM", "DMARC")
    )
    if category == "BENIGN" and auth_pass:
        model_risk_score = round(model_risk_score * 0.25)

    if model_risk_score == 0 and not rule_hits:
        reasoning.append("No deterministic rules fired and no significant evidence was found.")

    confidence = confidence_for_score(model_risk_score, len(evidence))
    if category == "BENIGN":
        confidence = "LOW"

    if not reasoning:
        reasoning = ["Insufficient evidence to support a stronger classification than BENIGN."]

    return ThreatResult(
        category=category,
        subcategory=subcategory,
        risk_score=model_risk_score,
        confidence=confidence,
        reasoning=reasoning,
    )
