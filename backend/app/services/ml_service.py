"""Local machine-learning content analysis for email spam detection."""
from __future__ import annotations

import csv
import os
import re
from functools import lru_cache
from pathlib import Path
from collections import defaultdict

from app.config import get_settings

PROJECT_ARCHIVE_DATASET_PATH = Path(__file__).resolve().parents[3] / "archive" / "email_spam.csv"
PARENT_ARCHIVE_DATASET_PATH = Path(__file__).resolve().parents[4] / "archive" / "email_spam.csv"
BUNDLED_DATASET_PATH = Path(__file__).resolve().parents[2] / "data" / "spam_training.csv"
NORMALIZED_DATASET_PATH = Path(__file__).resolve().parents[2] / "data" / "threat_training.csv"
configured_dataset_path = os.getenv("SPAM_DATASET_PATH", "").strip()
DATASET_PATH = Path(configured_dataset_path) if configured_dataset_path else PROJECT_ARCHIVE_DATASET_PATH
if not DATASET_PATH.exists() and PARENT_ARCHIVE_DATASET_PATH.exists():
    DATASET_PATH = PARENT_ARCHIVE_DATASET_PATH
if not DATASET_PATH.exists() and BUNDLED_DATASET_PATH.exists():
    DATASET_PATH = BUNDLED_DATASET_PATH

LABELS = {
    "spam": "SPAM",
    "not spam": "BENIGN",
    "ham": "BENIGN",
    "benign": "BENIGN",
    "phishing": "PHISHING",
    "bec": "BEC",
    "spoofing": "SPOOFING",
    "malware": "MALWARE",
}


def _contains_any(text: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in text for phrase in phrases)


def _model_text(subject: str, body: str) -> str:
    """Add learned feature tokens while retaining the original email text."""
    text = f"{subject}\n{body}".strip()
    lowered = text.lower()
    tags: list[str] = []
    if re.search(r"\.(exe|scr|bat|cmd|js|vbs|ps1|apk)\b", lowered):
        tags.extend(["FEATURE_EXECUTABLE_ATTACHMENT"] * 6)
    if "macro" in lowered or "enable editing" in lowered:
        tags.extend(["FEATURE_MACRO_ATTACHMENT"] * 6)
    if "attachment" in lowered or "attached" in lowered:
        tags.extend(["FEATURE_ATTACHMENT"] * 2)
    if _contains_any(lowered, ("wire transfer", "bank details", "beneficiary", "vendor payment", "payment redirection")):
        tags.append("FEATURE_PAYMENT_REQUEST")
    if _contains_any(lowered, ("password", "login credentials", "verify your account", "sign in")):
        tags.append("FEATURE_CREDENTIAL_REQUEST")
    if _contains_any(lowered, ("urgent", "immediately", "today", "asap", "before end of day")):
        tags.append("FEATURE_URGENCY")
    if _contains_any(lowered, ("feature_authentication_failure", "authentication failed", "dmarc failed", "spf failed", "sender domain")):
        tags.extend(["FEATURE_AUTHENTICATION_FAILURE"] * 4)
    if _contains_any(lowered, ("feature_identity_mismatch", "reply-to", "return path", "from domain", "sender domain are different")):
        tags.extend(["FEATURE_IDENTITY_MISMATCH"] * 4)
    return f"{text}\n{' '.join(tags)}"


def _signal_score(text: str, phrases: tuple[str, ...], cap: int = 3) -> float:
    matches = sum(1 for phrase in phrases if phrase in text)
    return round(min(matches, cap) / cap, 2)


def _semantic_scores(subject: str | None, body: str | None) -> dict[str, float]:
    """Extract graded, transparent content signals for threat categories."""
    text = f"{subject or ''}\n{body or ''}".lower()
    urgency = _signal_score(text, ("urgent", "asap", "immediately", "today", "time sensitive", "before 2pm"))
    financial = _signal_score(text, ("wire transfer", "bank details", "payment", "invoice", "vendor", "money", "pay"))
    credential = _signal_score(text, ("password", "verify your account", "login", "credentials", "sign in"))
    account_threat = _signal_score(text, ("account will be suspended", "account is blocked", "final warning", "avoid a fee"))
    impersonation = _signal_score(
        text,
        ("ceo", "chief executive", "executive", "i'm in a meeting", "confidential", "don't discuss", "do not discuss", "boss", "on behalf of"),
    )
    payment_action = _signal_score(text, ("process", "send", "transfer", "pay", "settle", "deposit", "purchase"))
    phishing = min(1.0, credential + _signal_score(text, ("click", "link", "verify", "suspended", "immediately"))) / 2
    social_engineering = min(1.0, urgency + impersonation + account_threat)
    bec_intent = round(min(1.0, financial * 0.45 + payment_action * 0.25 + urgency * 0.15 + impersonation * 0.15), 2)
    return {
        "urgency": urgency,
        "phishing_intent": round(phishing, 2),
        "impersonation_style": impersonation,
        "social_engineering": round(social_engineering, 2),
        "credential_request": credential,
        "financial_request": financial,
        "account_threat": account_threat,
        "payment_action": payment_action,
        "bec_intent": bec_intent,
    }


@lru_cache(maxsize=1)
def _get_model():
    """Train the local model once per process and reuse it."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    texts: list[str] = []
    labels: list[str] = []
    dataset_path = NORMALIZED_DATASET_PATH if NORMALIZED_DATASET_PATH.exists() else DATASET_PATH
    with dataset_path.open(newline="", encoding="utf-8-sig") as dataset:
        for row in csv.DictReader(dataset):
            raw_label = row.get("label", row.get("type", "")).strip().lower()
            if raw_label not in LABELS:
                raise ValueError(
                    f"unsupported threat dataset label {raw_label!r}; "
                    f"expected one of {sorted(LABELS)}"
                )
            title = row.get("subject", row.get("title", "")).strip()
            body = row.get("body", row.get("text", "")).strip()
            if not title and not body:
                continue
            texts.append(_model_text(f"SUBJECT: {title}", f"BODY: {body}"))
            labels.append(LABELS[raw_label])

    if len(set(labels)) < 2:
        raise ValueError("threat dataset must contain at least two labels")

    # Give rare, safety-critical classes enough representation to learn their
    # vocabulary without discarding the larger public corpora.
    grouped: dict[str, list[str]] = defaultdict(list)
    for text, label in zip(texts, labels):
        grouped[label].append(text)
    balanced_texts: list[str] = []
    balanced_labels: list[str] = []
    for label, samples in grouped.items():
        target_size = max(len(samples), 300)
        expanded = [samples[index % len(samples)] for index in range(target_size)]
        balanced_texts.extend(expanded)
        balanced_labels.extend([label] * target_size)

    model = Pipeline(
        [
            ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), sublinear_tf=True)),
            ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ]
    )
    model.fit(balanced_texts, balanced_labels)
    return model


def analyze_content(subject: str | None, body: str | None, context: str = "") -> dict:
    """Return local multiclass threat probabilities and semantic signals."""
    text = _model_text(
        f"SUBJECT: {subject or '(none)'}",
        f"BODY: {body or '(none)'} {context}",
    )[:8000]
    try:
        model = _get_model()
        probabilities = model.predict_proba([text])[0]
        classes = list(model.classes_)
        probability_map = {
            str(label): round(float(probabilities[index]), 4)
            for index, label in enumerate(classes)
        }
        spam_probability = probability_map.get("SPAM", 0.0)
        predicted_category = max(probability_map, key=probability_map.get)
        predicted_probability = probability_map[predicted_category]
        threat_probabilities = {
            label: probability for label, probability in probability_map.items()
            if label != "BENIGN"
        }
        model_risk_score = round(max(threat_probabilities.values(), default=0.0) * 100)
        threshold = get_settings().spam_threshold
        return {
            "status": "success",
            "spam_probability": spam_probability,
            "threshold": threshold,
            "predicted_category": predicted_category,
            "predicted_probability": predicted_probability,
            "model_risk_score": model_risk_score,
            "category_probabilities": probability_map,
            "scores": _semantic_scores(subject, body),
        }
    except Exception as exc:
        return {"status": "error", "reason": f"ML spam model unavailable: {exc}"}
