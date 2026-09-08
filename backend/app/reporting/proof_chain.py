"""
Layer 8 (part) — Proof Chain.

Generates a human-readable evidence -> rule -> correlation -> threat chain
FROM THE ACTUAL MATCHED RULES, never hard-coded. If a scenario doesn't
trigger a given rule, that step simply doesn't appear.
"""
from __future__ import annotations

from app.schemas.evidence import Evidence, ProofChainStep, RuleHit, ThreatResult

# Ordering hint only — steps are included solely based on what actually fired.
_STEP_ORDER = [
    "FROM_REPLYTO_MISMATCH",
    "FROM_RETURNPATH_MISMATCH",
    "DISPLAY_NAME_BRAND_MISMATCH",
    "DMARC_FAILURE",
    "AUTH_FAILURE_PLUS_IDENTITY_MISMATCH",
    "AUTH_FAILURE_PLUS_SENDER_MISMATCH",
    "SUSPICIOUS_DOMAIN_AGE",
    "PUNYCODE_DOMAIN_OR_URL",
    "PUNYCODE_PLUS_BRAND_SIMILARITY",
    "BRAND_SIMILARITY_MATCH",
    "NEW_DOMAIN_PLUS_CREDENTIAL_REQUEST",
    "IP_BASED_URL",
    "MULTIPLE_REDIRECTS",
    "HIGH_URGENCY",
    "HIGH_CREDENTIAL_REQUEST",
    "HIGH_SOCIAL_ENGINEERING",
    "HIGH_PHISHING_INTENT",
    "SUSPICIOUS_URL_PLUS_HIGH_PHISHING_INTENT",
    "MIME_MISMATCH",
    "EXECUTABLE_ATTACHMENT",
    "MACRO_DETECTED",
    "YARA_MATCH",
]


def build_proof_chain(
    evidence: list[Evidence],
    rule_hits: list[RuleHit],
    threat_result: ThreatResult,
) -> list[ProofChainStep]:
    evidence_by_id = {ev.evidence_id: ev for ev in evidence}
    hits_by_id = {h.rule_id: h for h in rule_hits}

    steps: list[ProofChainStep] = []
    step_num = 1

    for rule_id in _STEP_ORDER:
        hit = hits_by_id.get(rule_id)
        if not hit:
            continue
        matched_evidence = [evidence_by_id[eid] for eid in hit.matched_evidence if eid in evidence_by_id]
        # A step's fact_level is the "weakest link" among its evidence —
        # Inferred if any matched evidence is Inferred, else Derived if any
        # is Derived, else Observed.
        fact_levels = {ev.fact_level for ev in matched_evidence}
        if any(fl.value == "Inferred" for fl in fact_levels):
            from app.schemas.evidence import FactLevel
            step_fact_level = FactLevel.INFERRED
        elif any(fl.value == "Derived" for fl in fact_levels):
            from app.schemas.evidence import FactLevel
            step_fact_level = FactLevel.DERIVED
        else:
            from app.schemas.evidence import FactLevel
            step_fact_level = FactLevel.OBSERVED

        steps.append(
            ProofChainStep(
                step=step_num,
                label=hit.description,
                fact_level=step_fact_level,
                evidence_ids=hit.matched_evidence,
            )
        )
        step_num += 1

    # Any rule hits not in the ordering list still get appended at the end
    for hit in rule_hits:
        if hit.rule_id not in _STEP_ORDER:
            matched_evidence = [evidence_by_id[eid] for eid in hit.matched_evidence if eid in evidence_by_id]
            from app.schemas.evidence import FactLevel
            fact_levels = {ev.fact_level for ev in matched_evidence}
            step_fact_level = (
                FactLevel.INFERRED if any(fl.value == "Inferred" for fl in fact_levels)
                else FactLevel.DERIVED if any(fl.value == "Derived" for fl in fact_levels)
                else FactLevel.OBSERVED
            )
            steps.append(
                ProofChainStep(step=step_num, label=hit.description, fact_level=step_fact_level, evidence_ids=hit.matched_evidence)
            )
            step_num += 1

    # Final step: the classification itself
    conclusion = f"Correlated evidence leads to classification: {threat_result.category}"
    if threat_result.subcategory:
        conclusion += f" ({threat_result.subcategory})"
    steps.append(
        ProofChainStep(step=step_num, label=conclusion, fact_level=None, evidence_ids=[])  # type: ignore[arg-type]
    )

    return steps
