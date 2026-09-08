"""
Layer 2.4 — Domain Extractor.

Collects every domain referenced by the email (From, Reply-To, Return-Path,
Message-ID, DKIM d=, URL hostnames), and for each: DNS records, WHOIS age,
punycode/homograph checks, and a lightweight brand-similarity heuristic.

Brand impersonation is only ever FLAGGED, never asserted as fact.
"""
from __future__ import annotations

import difflib
import re

from app.schemas.evidence import (
    AnalyzerFinding,
    AnalyzerResult,
    AnalyzerStatus,
    FactLevel,
    Reliability,
    Severity,
)
from app.services.whois_service import lookup_whois

KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "irs", "dhl", "fedex",
    "facebook", "instagram", "linkedin", "dropbox", "adobe",
]


def _is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def _brand_similarity(domain: str) -> tuple[str, float] | None:
    """Very lightweight, explainable similarity heuristic (NOT a security
    product's brand-protection engine — purely for the prototype)."""
    root = domain.split(".")[0].lower()
    best: tuple[str, float] | None = None
    for brand in KNOWN_BRANDS:
        if brand == root:
            continue  # exact match to the brand's own domain root isn't "similarity"
        ratio = difflib.SequenceMatcher(None, root, brand).ratio()
        if ratio >= 0.72 or (brand in root and len(root) - len(brand) <= 4):
            if not best or ratio > best[1]:
                best = (brand, ratio)
    return best


def _resolve_dns(domain: str) -> dict:
    try:
        import dns.resolver  # dnspython
    except ImportError:
        return {"status": "unavailable", "reason": "dnspython not installed"}

    records: dict[str, list[str]] = {}
    any_success = False
    for rtype in ("A", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=4.0)
            records[rtype] = [str(r) for r in answers]
            any_success = True
        except Exception:
            records[rtype] = []
    if not any_success:
        return {"status": "unavailable", "reason": "no DNS records resolved", "records": records}
    return {"status": "success", "records": records}


def analyze_domain(email_id: str, domain: str, context: str) -> AnalyzerResult:
    """`context` is a short label like 'from', 'reply_to', 'url:example.com/x'."""
    try:
        findings: list[AnalyzerFinding] = []
        domain = domain.lower().strip().rstrip(".")

        punycode = _is_punycode(domain)
        if punycode:
            findings.append(
                AnalyzerFinding(
                    type="PUNYCODE_DOMAIN",
                    value=domain,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Domain '{domain}' ({context}) uses Punycode (xn--) encoding, "
                        f"often used to visually mimic ASCII brand names."
                    ),
                    entity_refs=[f"domain:{domain}"],
                )
            )

        similarity = _brand_similarity(domain)
        if similarity:
            brand, ratio = similarity
            findings.append(
                AnalyzerFinding(
                    type="BRAND_SIMILARITY",
                    value={"domain": domain, "possible_brand": brand, "similarity": round(ratio, 2)},
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.DERIVED,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Domain '{domain}' ({context}) is textually similar to the "
                        f"brand '{brand}' (similarity {ratio:.2f}). This is a heuristic "
                        f"flag, not confirmation of impersonation."
                    ),
                    entity_refs=[f"domain:{domain}"],
                )
            )

        dns_result = _resolve_dns(domain)
        if dns_result["status"] == "success":
            findings.append(
                AnalyzerFinding(
                    type="DNS_RECORDS",
                    value=dns_result["records"],
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    description=f"DNS records resolved for '{domain}' ({context}).",
                    entity_refs=[f"domain:{domain}"],
                )
            )
        else:
            findings.append(
                AnalyzerFinding(
                    type="DNS_RECORDS",
                    value="unavailable",
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.OBSERVED,
                    description=f"DNS lookup unavailable for '{domain}': {dns_result.get('reason')}.",
                )
            )

        whois_result = lookup_whois(domain)
        if whois_result["status"] == "success":
            age_days = whois_result["age_days"]
            findings.append(
                AnalyzerFinding(
                    type="DOMAIN_AGE",
                    value=age_days,
                    unit="days",
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    severity=Severity.HIGH if age_days < 30 else (
                        Severity.MEDIUM if age_days < 180 else Severity.INFO
                    ),
                    description=(
                        f"Domain '{domain}' ({context}) was registered {age_days} day(s) "
                        f"ago" + (f" via {whois_result['registrar']}." if whois_result.get("registrar") else ".")
                    ),
                    entity_refs=[f"domain:{domain}"],
                )
            )
        else:
            findings.append(
                AnalyzerFinding(
                    type="DOMAIN_AGE",
                    value="unavailable",
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.OBSERVED,
                    description=f"WHOIS lookup unavailable for '{domain}': {whois_result.get('reason')}.",
                )
            )

        return AnalyzerResult(
            analyzer="domain_intelligence",
            status=AnalyzerStatus.SUCCESS,
            findings=findings,
        )
    except Exception as exc:  # pragma: no cover
        return AnalyzerResult(
            analyzer="domain_intelligence",
            status=AnalyzerStatus.ERROR,
            findings=[],
            error=str(exc),
        )
