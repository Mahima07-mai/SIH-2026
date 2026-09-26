"""
Layer 12.12 — "What We Cannot Know".

Only surfaces limitations relevant to evidence actually present in this
analysis, per the forensic principles in the spec (never overclaim).
"""
from __future__ import annotations

from app.schemas.evidence import Evidence


def build_limitations(evidence: list[Evidence]) -> list[str]:
    types = {ev.type for ev in evidence}
    limitations: list[str] = []

    if "IP_GEOLOCATION" in types:
        limitations.append(
            "IP geolocation identifies where observed network infrastructure appears "
            "to be, not the physical location of the person who sent the email."
        )
    if "LIKELY_CLOUD_OR_RELAY" in types:
        limitations.append(
            "The sending IP belongs to shared cloud/relay infrastructure, which can "
            "obscure the true originating host entirely."
        )
    if "SPAM_PROBABILITY" in types:
        limitations.append(
            "The local spam model produces a statistical inference from its training "
            "corpus; it is not proof of the sender's intent."
        )
    if "DMARC_FAILURE" in types or "SPF_RESULT" in types or "DKIM_RESULT" in types:
        limitations.append(
            "An authentication failure (SPF/DKIM/DMARC) is an anomaly, not by itself "
            "proof of spoofing or malicious intent — misconfiguration can also cause it."
        )
    if "DOMAIN_AGE" in types:
        limitations.append(
            "A newly registered domain is a risk indicator, not proof of malicious intent "
            "on its own — many legitimate domains are also new."
        )
    if any(t in types for t in ("URL_STRUCTURE", "IP_BASED_URL", "PUNYCODE_URL")):
        limitations.append(
            "A suspicious-looking URL alone does not prove that a system was compromised "
            "or that a link was clicked."
        )
    if any(t.startswith("YARA") or t == "MACRO_DETECTED" or t == "MIME_MISMATCH" for t in types):
        limitations.append(
            "Static attachment analysis (hashing, MIME checks, macro/YARA scanning) can "
            "miss malware that uses obfuscation or novel techniques; no dynamic sandbox "
            "detonation was performed in this prototype."
        )
    if "URL_REPUTATION" in types:
        limitations.append(
            "No live URL reputation feed was queried in this prototype; findings rely on "
            "structural analysis only."
        )

    if not limitations:
        limitations.append(
            "Limited evidence was available for this email; conclusions should be treated "
            "as preliminary."
        )

    return limitations
