"""
Layer 4.2 — Contradiction / Rule Engine.

Ten deterministic rules operating over normalized Evidence. Each rule that
fires produces a RuleHit referencing the specific evidence items that
triggered it, so the proof chain and PDF report can show exactly why.

This is where GPT's advisory NLP scores are combined with hard technical
evidence — but note GPT scores only ever contribute via the same weighted,
explainable mechanism as everything else; they never short-circuit to a
verdict on their own.
"""
from __future__ import annotations

from app.config import get_settings
from app.correlation.scoring import RULE_WEIGHTS
from app.schemas.evidence import Evidence, RuleHit, Severity


def _find(evidence: list[Evidence], type_: str) -> Evidence | None:
    for ev in evidence:
        if ev.type == type_:
            return ev
    return None


def _find_all(evidence: list[Evidence], types: set[str]) -> list[Evidence]:
    return [ev for ev in evidence if ev.type in types]


def run_rules(evidence: list[Evidence]) -> list[RuleHit]:
    hits: list[RuleHit] = []

    def add(rule_id: str, description: str, matched: list[Evidence], severity: Severity):
        hits.append(
            RuleHit(
                rule_id=rule_id,
                description=description,
                matched_evidence=[e.evidence_id for e in matched],
                severity=severity,
                score_contribution=RULE_WEIGHTS.get(rule_id, 5),
            )
        )

    # RULE 1: From domain != Reply-To domain
    e = _find(evidence, "FROM_REPLYTO_MISMATCH")
    if e and e.value:
        add(
            "FROM_REPLYTO_MISMATCH",
            "From domain and Reply-To domain differ — replies are silently redirected.",
            [e],
            Severity.HIGH,
        )

    # RULE 2: From domain != Return-Path domain
    e = _find(evidence, "FROM_RETURNPATH_MISMATCH")
    if e and e.value:
        add(
            "FROM_RETURNPATH_MISMATCH",
            "From domain and Return-Path domain differ.",
            [e],
            Severity.MEDIUM,
        )

    # RULE 3: Visible claimed brand != URL/sending domain
    e = _find(evidence, "DISPLAY_NAME_BRAND_MISMATCH")
    if e:
        add(
            "DISPLAY_NAME_BRAND_MISMATCH",
            "Display name references a known brand not matched by the sending domain.",
            [e],
            Severity.MEDIUM,
        )

    # RULE 4: Attachment extension / declared MIME != actual MIME
    e = _find(evidence, "MIME_MISMATCH")
    if e:
        add(
            "MIME_MISMATCH",
            "Attachment's declared type does not match its actual detected content type.",
            [e],
            Severity.HIGH,
        )

    exe = _find(evidence, "EXECUTABLE_EXTENSION")
    if exe:
        add(
            "EXECUTABLE_ATTACHMENT",
            "Attachment carries an executable/script extension.",
            [exe],
            Severity.HIGH,
        )

    # RULE 5: DMARC FAIL + identity mismatch
    dmarc = _find(evidence, "DMARC_FAILURE")
    mismatch = _find(evidence, "FROM_REPLYTO_MISMATCH") or _find(evidence, "FROM_RETURNPATH_MISMATCH")
    if dmarc:
        add(
            "DMARC_FAILURE",
            "DMARC authentication failed for the sending domain.",
            [dmarc],
            Severity.HIGH,
        )
    if dmarc and mismatch:
        add(
            "AUTH_FAILURE_PLUS_IDENTITY_MISMATCH",
            "DMARC failure combined with a From/Reply-To or From/Return-Path mismatch — "
            "authentication anomaly and identity inconsistency corroborate each other.",
            [dmarc, mismatch],
            Severity.CRITICAL,
        )

    # RULE 6: Punycode domain + brand similarity
    puny = _find(evidence, "PUNYCODE_DOMAIN") or _find(evidence, "PUNYCODE_URL")
    brand_sim = _find(evidence, "BRAND_SIMILARITY")
    if puny:
        add(
            "PUNYCODE_DOMAIN_OR_URL",
            "A domain or URL uses Punycode encoding, often used to visually mimic a brand.",
            [puny],
            Severity.MEDIUM,
        )
    if puny and brand_sim:
        add(
            "PUNYCODE_PLUS_BRAND_SIMILARITY",
            "Punycode domain combined with textual similarity to a known brand.",
            [puny, brand_sim],
            Severity.HIGH,
        )
    elif brand_sim:
        add(
            "BRAND_SIMILARITY_MATCH",
            "Domain is textually similar to a known brand name.",
            [brand_sim],
            Severity.MEDIUM,
        )

    # RULE 7: Newly registered domain + credential request
    age = _find(evidence, "DOMAIN_AGE")
    cred_request = _find(evidence, "CREDENTIAL_REQUEST")
    is_new_domain = age and isinstance(age.value, int) and age.value < 30
    if is_new_domain:
        add(
            "SUSPICIOUS_DOMAIN_AGE",
            f"Domain was registered only {age.value} day(s) ago.",
            [age],
            Severity.HIGH,
        )
    if is_new_domain and cred_request and cred_request.value and cred_request.value >= 0.6:
        add(
            "NEW_DOMAIN_PLUS_CREDENTIAL_REQUEST",
            "Newly registered domain combined with content that requests credentials.",
            [age, cred_request],
            Severity.CRITICAL,
        )

    # RULE 8: Suspicious URL + high phishing intent
    ip_url = _find(evidence, "IP_BASED_URL")
    phishing = _find(evidence, "PHISHING_INTENT")
    if ip_url:
        add("IP_BASED_URL", "A URL uses a raw IP address instead of a domain name.", [ip_url], Severity.MEDIUM)
    if phishing and phishing.value and phishing.value >= 0.7:
        add(
            "HIGH_PHISHING_INTENT",
            f"Model-derived phishing intent score is high ({phishing.value:.2f}).",
            [phishing],
            Severity.HIGH,
        )
    if (ip_url or puny) and phishing and phishing.value and phishing.value >= 0.6:
        add(
            "SUSPICIOUS_URL_PLUS_HIGH_PHISHING_INTENT",
            "A structurally suspicious URL correlates with high model-derived phishing intent.",
            [ev for ev in (ip_url, puny, phishing) if ev],
            Severity.CRITICAL,
        )

    # Local content features used for explainable BEC/social-engineering scoring.
    urgency = _find(evidence, "URGENCY")
    financial = _find(evidence, "FINANCIAL_REQUEST")
    impersonation = _find(evidence, "IMPERSONATION_STYLE")
    bec_intent = _find(evidence, "BEC_INTENT")
    if urgency and urgency.value and urgency.value >= 0.7:
        add(
            "HIGH_URGENCY",
            f"Urgency language score is high ({urgency.value:.2f}).",
            [urgency],
            Severity.MEDIUM,
        )
    if financial and financial.value and financial.value >= 0.7:
        add(
            "HIGH_FINANCIAL_REQUEST",
            f"Financial-request language score is high ({financial.value:.2f}).",
            [financial],
            Severity.HIGH,
        )
    if impersonation and impersonation.value and impersonation.value >= 0.7:
        add(
            "HIGH_IMPERSONATION_STYLE",
            f"Impersonation-style language score is high ({impersonation.value:.2f}).",
            [impersonation],
            Severity.HIGH,
        )
    if financial and impersonation and financial.value >= 0.7 and impersonation.value >= 0.7:
        add(
            "BEC_PAYMENT_REQUEST",
            "Financial request combined with executive or confidential impersonation language.",
            [financial, impersonation],
            Severity.CRITICAL,
        )
    if bec_intent and bec_intent.value and bec_intent.value >= 0.5:
        add(
            "HIGH_BEC_INTENT",
            f"Combined BEC intent score is high ({bec_intent.value:.2f}).",
            [bec_intent],
            Severity.HIGH,
        )

    model_category = _find(evidence, "MODEL_CATEGORY")
    model_probability = _find(evidence, "MODEL_CATEGORY_PROBABILITIES")
    if model_category and model_probability and isinstance(model_probability.value, dict):
        category = str(model_category.value)
        probability = float(model_probability.value.get(category, 0.0))
        model_rules = {
            "BEC": ("MODEL_BEC_HIGH", "Multiclass model predicts BEC", Severity.HIGH),
            "PHISHING": ("MODEL_PHISHING_HIGH", "Multiclass model predicts phishing", Severity.HIGH),
            "MALWARE": ("MODEL_MALWARE_HIGH", "Multiclass model predicts malware", Severity.CRITICAL),
            "SPOOFING": ("MODEL_SPOOFING_HIGH", "Multiclass model predicts spoofing", Severity.HIGH),
            "SPAM": ("MODEL_SPAM_HIGH", "Multiclass model predicts spam", Severity.LOW),
        }
        rule = model_rules.get(category)
        if rule and probability >= 0.65:
            add(rule[0], f"{rule[1]} with probability {probability:.2f}.", [model_category, model_probability], rule[2])
        elif category == "BEC" and probability >= 0.35:
            add(
                "MODEL_BEC_MEDIUM",
                f"Multiclass model finds meaningful BEC probability ({probability:.2f}).",
                [model_category, model_probability],
                Severity.MEDIUM,
            )

    # RULE 9: Authentication failure + identity mismatch (broader form)
    e = _find(evidence, "FROM_SENDER_MISMATCH")
    if dmarc and e:
        add(
            "AUTH_FAILURE_PLUS_SENDER_MISMATCH",
            "DMARC failure combined with From/Sender header mismatch.",
            [dmarc, e],
            Severity.HIGH,
        )

    # RULE 10: Known malicious attachment hash (placeholder — no threat-intel
    # feed wired in for the prototype; only fires on local YARA hits).
    yara = _find(evidence, "YARA_MATCHES")
    if yara and isinstance(yara.value, list) and yara.value:
        add(
            "YARA_MATCH",
            f"Attachment matched local YARA rule(s): {', '.join(yara.value)}.",
            [yara],
            Severity.CRITICAL,
        )

    macro = _find(evidence, "MACRO_DETECTED")
    if macro and macro.value is True:
        add(
            "MACRO_DETECTED",
            "Attachment contains VBA macros — a common malware delivery mechanism.",
            [macro],
            Severity.HIGH,
        )

    # Local ML contribution remains advisory and cannot override stronger rules.
    spam_probability = _find(evidence, "SPAM_PROBABILITY")
    if (
        spam_probability
        and spam_probability.value
        and spam_probability.value >= get_settings().spam_threshold
    ):
        add(
            "SPAM_MODEL_HIGH",
            f"Local ML spam probability is high ({spam_probability.value:.2f}).",
            [spam_probability],
            Severity.LOW,
        )

    redirects = [ev for ev in evidence if ev.type == "REDIRECT_CHAIN" and isinstance(ev.value, dict)]
    for r in redirects:
        if r.value.get("redirect_count", 0) >= 2:
            add(
                "MULTIPLE_REDIRECTS",
                f"URL redirected {r.value['redirect_count']} times before resolving.",
                [r],
                Severity.LOW,
            )

    return hits
