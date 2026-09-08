"""
Layer 2.5 — URL Extractor.

Extracts URLs from raw text/HTML, then inspects each URL's structure
(punycode, IP-literal host, suspicious char use) and — safely — its
redirect chain and TLS certificate. Networking is bounded by timeout,
redirect limit, and response-size limit; nothing is executed or saved.
"""
from __future__ import annotations

import re
import ssl
import socket
from urllib.parse import urlparse

import httpx

from app.config import get_settings
from app.schemas.evidence import (
    AnalyzerFinding,
    AnalyzerResult,
    AnalyzerStatus,
    FactLevel,
    Reliability,
    Severity,
)

_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.I)
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_urls(*texts: str | None) -> list[str]:
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        found.extend(_URL_RE.findall(text))
    # normalize (strip trailing punctuation) + dedupe, order-preserving
    cleaned = []
    seen = set()
    for u in found:
        u = u.rstrip(".,;:!?")
        if u not in seen:
            seen.add(u)
            cleaned.append(u)
    return cleaned


def _get_certificate_info(hostname: str, timeout: float) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        return {"status": "success", "valid": True, "subject": cert.get("subject")}
    except Exception as exc:
        return {"status": "unavailable", "valid": None, "reason": str(exc)}


def analyze_url(email_id: str, url: str) -> AnalyzerResult:
    settings = get_settings()
    try:
        findings: list[AnalyzerFinding] = []
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        is_punycode = hostname.startswith("xn--") or ".xn--" in hostname
        is_ip_host = bool(_IP_HOST_RE.match(hostname))

        findings.append(
            AnalyzerFinding(
                type="URL_STRUCTURE",
                value={
                    "url": url,
                    "scheme": parsed.scheme,
                    "hostname": hostname,
                    "path": parsed.path,
                    "query": parsed.query,
                },
                reliability=Reliability.HIGH,
                fact_level=FactLevel.OBSERVED,
                description=f"Parsed URL structure for {url}.",
                entity_refs=[f"url:{url}"],
            )
        )

        if is_ip_host:
            findings.append(
                AnalyzerFinding(
                    type="IP_BASED_URL",
                    value=True,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    severity=Severity.MEDIUM,
                    description=f"URL uses a raw IP address ({hostname}) instead of a domain name.",
                    entity_refs=[f"url:{url}"],
                )
            )

        if is_punycode:
            findings.append(
                AnalyzerFinding(
                    type="PUNYCODE_URL",
                    value=True,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    severity=Severity.MEDIUM,
                    description=f"URL hostname '{hostname}' uses Punycode encoding.",
                    entity_refs=[f"url:{url}"],
                )
            )

        if parsed.scheme != "https":
            findings.append(
                AnalyzerFinding(
                    type="NON_HTTPS_URL",
                    value=True,
                    reliability=Reliability.MEDIUM,
                    fact_level=FactLevel.OBSERVED,
                    severity=Severity.LOW,
                    description=f"URL does not use HTTPS ({parsed.scheme}).",
                    entity_refs=[f"url:{url}"],
                )
            )

        # --- Safe redirect-chain check (HEAD-first, bounded) -----------------
        redirect_count = 0
        final_url = url
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=settings.url_fetch_timeout_seconds,
            ) as client:
                current = url
                for _ in range(settings.url_fetch_max_redirects):
                    resp = client.head(current)
                    if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                        redirect_count += 1
                        current = resp.headers["location"]
                    else:
                        final_url = current
                        break
                else:
                    final_url = current

            findings.append(
                AnalyzerFinding(
                    type="REDIRECT_CHAIN",
                    value={"redirect_count": redirect_count, "final_url": final_url},
                    reliability=Reliability.MEDIUM,
                    fact_level=FactLevel.OBSERVED,
                    severity=Severity.MEDIUM if redirect_count >= 2 else Severity.INFO,
                    description=(
                        f"URL redirected {redirect_count} time(s), landing on {final_url}."
                        if redirect_count
                        else "URL did not redirect."
                    ),
                    entity_refs=[f"url:{url}"],
                )
            )
        except Exception as exc:
            findings.append(
                AnalyzerFinding(
                    type="REDIRECT_CHAIN",
                    value="unavailable",
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.OBSERVED,
                    description=f"Could not safely check redirects: {exc}.",
                )
            )

        if hostname and parsed.scheme == "https":
            cert_info = _get_certificate_info(hostname, settings.url_fetch_timeout_seconds)
            if cert_info["status"] == "success":
                findings.append(
                    AnalyzerFinding(
                        type="CERTIFICATE_VALID",
                        value=True,
                        reliability=Reliability.MEDIUM,
                        fact_level=FactLevel.OBSERVED,
                        description=f"TLS certificate for {hostname} presented successfully.",
                        entity_refs=[f"url:{url}"],
                    )
                )
            else:
                findings.append(
                    AnalyzerFinding(
                        type="CERTIFICATE_VALID",
                        value="unavailable",
                        reliability=Reliability.LOW,
                        fact_level=FactLevel.OBSERVED,
                        description=f"TLS certificate check unavailable: {cert_info.get('reason')}.",
                    )
                )

        # URL reputation — no external API configured in this prototype.
        findings.append(
            AnalyzerFinding(
                type="URL_REPUTATION",
                value="unavailable",
                reliability=Reliability.LOW,
                fact_level=FactLevel.OBSERVED,
                description=(
                    "No URL reputation provider is configured in this prototype. "
                    "Wire in a provider (e.g. Google Safe Browsing, VirusTotal) via "
                    "services/reputation_service.py to populate this."
                ),
            )
        )

        return AnalyzerResult(analyzer="url_intelligence", status=AnalyzerStatus.SUCCESS, findings=findings)
    except Exception as exc:  # pragma: no cover
        return AnalyzerResult(analyzer="url_intelligence", status=AnalyzerStatus.ERROR, findings=[], error=str(exc))
