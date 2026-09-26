"""Layer 2.7 - local ML content analyzer."""
from __future__ import annotations

from app.schemas.evidence import (
    AnalyzerFinding,
    AnalyzerResult,
    AnalyzerStatus,
    FactLevel,
    Reliability,
    Severity,
)
from app.services.ml_service import analyze_content


def analyze_nlp(
    email_id: str,
    subject: str | None,
    body: str | None,
    context: str = "",
) -> AnalyzerResult:
    result = analyze_content(subject, body, context)

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
                        f"Local ML content analysis was unavailable "
                        f"({result.get('reason', 'no reason given')}). Threat "
                        "classification will proceed on deterministic evidence only."
                    ),
                )
            ],
            error=result.get("reason"),
        )

    probability = result["spam_probability"]
    severity = Severity.HIGH if probability >= result["threshold"] else Severity.INFO
    score_labels = {
        "urgency": "urgency",
        "phishing_intent": "phishing intent",
        "impersonation_style": "impersonation style",
        "social_engineering": "social engineering",
        "credential_request": "credential request",
        "financial_request": "financial request",
        "account_threat": "account threat language",
        "payment_action": "payment action",
        "bec_intent": "BEC intent",
    }
    findings = [
        AnalyzerFinding(
            type="SPAM_PROBABILITY",
            value=probability,
            reliability=Reliability.MEDIUM,
            fact_level=FactLevel.INFERRED,
            severity=severity,
            description=(
                "Local TF-IDF/logistic-regression model estimates spam "
                f"probability at {probability:.2f}; threshold is "
                f"{result['threshold']:.2f}."
            ),
        )
    ]
    findings.extend(
        [
            AnalyzerFinding(
                type="MODEL_CATEGORY",
                value=result["predicted_category"],
                reliability=Reliability.MEDIUM,
                fact_level=FactLevel.INFERRED,
                severity=Severity.HIGH if result["predicted_probability"] >= 0.7 else Severity.MEDIUM,
                description=(
                    f"Multiclass text model predicts {result['predicted_category']} "
                    f"with probability {result['predicted_probability']:.2f}."
                ),
            ),
            AnalyzerFinding(
                type="MODEL_CATEGORY_PROBABILITIES",
                value=result["category_probabilities"],
                reliability=Reliability.MEDIUM,
                fact_level=FactLevel.INFERRED,
                description="Multiclass model probability distribution across learned threat categories.",
            ),
            AnalyzerFinding(
                type="MODEL_RISK_SCORE",
                value=result["model_risk_score"],
                reliability=Reliability.MEDIUM,
                fact_level=FactLevel.INFERRED,
                severity=Severity.HIGH if result["model_risk_score"] >= 70 else Severity.MEDIUM,
                description=(
                    "Model risk is derived from the strongest learned threat "
                    "probability, not from a category score range."
                ),
            ),
        ]
    )
    for key, label in score_labels.items():
        value = result["scores"][key]
        if value:
            findings.append(
                AnalyzerFinding(
                    type=key.upper(),
                    value=value,
                    reliability=Reliability.MEDIUM,
                    fact_level=FactLevel.INFERRED,
                    severity=Severity.HIGH if value >= 0.7 else Severity.MEDIUM,
                    description=f"Local content feature detected {label} ({value:.2f}).",
                )
            )
    return AnalyzerResult(
        analyzer="content_nlp",
        status=AnalyzerStatus.SUCCESS,
        findings=findings,
    )
