"""
Layer 2.3 — Infrastructure Extractor.

Extracts IP addresses from Received headers and geolocates the most
plausible originating relay. Deliberately conservative in its wording:
this reports where SENDING INFRASTRUCTURE geolocates, never where a person
is physically located.
"""
from __future__ import annotations

import ipaddress
import re

from app.schemas.evidence import (
    AnalyzerFinding,
    AnalyzerResult,
    AnalyzerStatus,
    FactLevel,
    Reliability,
    Severity,
)
from app.services.geo_service import lookup_ip

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def _is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def extract_ips_from_received(received_raw: str | None) -> list[str]:
    if not received_raw:
        return []
    candidates = _IP_RE.findall(received_raw)
    # Preserve order, dedupe, keep only public IPs (private hops are internal
    # relays and rarely useful for external geolocation).
    seen: list[str] = []
    for ip in candidates:
        if ip not in seen and _is_public(ip):
            seen.append(ip)
    return seen


def analyze_infrastructure(email_id: str, received_raw: str | None) -> AnalyzerResult:
    try:
        ips = extract_ips_from_received(received_raw)
        findings: list[AnalyzerFinding] = []

        if not ips:
            findings.append(
                AnalyzerFinding(
                    type="SENDING_IP",
                    value=None,
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.OBSERVED,
                    description=(
                        "No usable public IP address could be extracted from the "
                        "supplied Received headers."
                    ),
                )
            )
            return AnalyzerResult(
                analyzer="infrastructure",
                status=AnalyzerStatus.SUCCESS,
                findings=findings,
            )

        # The LAST public IP in the Received chain (as typically written,
        # top-to-bottom = newest-to-oldest) is usually closest to the
        # original sender, but this is a heuristic, not a certainty.
        candidate_ip = ips[-1]

        findings.append(
            AnalyzerFinding(
                type="SENDING_IP",
                value=candidate_ip,
                reliability=Reliability.MEDIUM,
                fact_level=FactLevel.OBSERVED,
                description=(
                    f"Extracted candidate originating IP {candidate_ip} from the "
                    f"Received header chain ({len(ips)} public IP(s) observed total). "
                    f"Received-header order is a convention, not a guarantee."
                ),
                entity_refs=[f"ip:{candidate_ip}"],
            )
        )

        geo = lookup_ip(candidate_ip)

        if geo.get("status") == "success":
            location_bits = [b for b in (geo.get("city"), geo.get("region"), geo.get("country")) if b]
            location_str = ", ".join(location_bits) if location_bits else "unknown location"
            findings.append(
                AnalyzerFinding(
                    type="IP_GEOLOCATION",
                    value=geo,
                    reliability=Reliability.MEDIUM,
                    fact_level=FactLevel.OBSERVED,
                    description=(
                        f"Observed sending infrastructure ({candidate_ip}) geolocates to "
                        f"{location_str}. This describes network infrastructure only and "
                        f"does not establish the physical location of a human sender."
                    ),
                    entity_refs=[f"ip:{candidate_ip}"],
                )
            )
            if geo.get("org"):
                findings.append(
                    AnalyzerFinding(
                        type="IP_ORGANIZATION",
                        value=geo["org"],
                        reliability=Reliability.MEDIUM,
                        fact_level=FactLevel.OBSERVED,
                        description=f"IP {candidate_ip} is registered to/announced by '{geo['org']}'.",
                        entity_refs=[f"ip:{candidate_ip}"],
                    )
                )
            if geo.get("is_likely_cloud_or_relay"):
                findings.append(
                    AnalyzerFinding(
                        type="LIKELY_CLOUD_OR_RELAY",
                        value=True,
                        reliability=Reliability.MEDIUM,
                        fact_level=FactLevel.DERIVED,
                        severity=Severity.INFO,
                        description=(
                            "This IP belongs to a large cloud/email provider network. "
                            "The true originating host may be obscured behind this "
                            "infrastructure; treat geolocation as provider location, "
                            "not attacker location."
                        ),
                    )
                )
        else:
            findings.append(
                AnalyzerFinding(
                    type="IP_GEOLOCATION",
                    value="unavailable",
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.OBSERVED,
                    description=(
                        f"Geolocation for {candidate_ip} is unavailable "
                        f"({geo.get('reason', 'no reason given')})."
                    ),
                )
            )

        return AnalyzerResult(
            analyzer="infrastructure",
            status=AnalyzerStatus.SUCCESS,
            findings=findings,
        )
    except Exception as exc:  # pragma: no cover
        return AnalyzerResult(
            analyzer="infrastructure",
            status=AnalyzerStatus.ERROR,
            findings=[],
            error=str(exc),
        )
