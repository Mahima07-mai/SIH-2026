"""
Layer 2.1 — Header / Identity Extractor.

Parses From / Reply-To / Return-Path / Sender / Message-ID and flags
mismatches between them. Pure stdlib (`email.utils`), fully deterministic.
"""
from __future__ import annotations

from email.utils import getaddresses

from app.schemas.evidence import (
    AnalyzerFinding,
    AnalyzerResult,
    AnalyzerStatus,
    FactLevel,
    Reliability,
    Severity,
)


def _extract_address(raw: str | None) -> str | None:
    if not raw:
        return None
    parsed = getaddresses([raw])
    if not parsed or not parsed[0][1]:
        return None
    return parsed[0][1].strip().lower()


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(">")


def _domain_of_message_id(message_id: str | None) -> str | None:
    if not message_id:
        return None
    mid = message_id.strip().strip("<>")
    if "@" in mid:
        return mid.rsplit("@", 1)[-1].lower()
    return None


def analyze_headers(
    email_id: str,
    from_raw: str | None,
    reply_to_raw: str | None,
    return_path_raw: str | None,
    sender_raw: str | None,
    message_id_raw: str | None,
) -> AnalyzerResult:
    try:
        from_addr = _extract_address(from_raw)
        reply_to_addr = _extract_address(reply_to_raw)
        return_path_addr = _extract_address(return_path_raw)
        sender_addr = _extract_address(sender_raw)

        from_domain = _domain_of(from_addr)
        reply_to_domain = _domain_of(reply_to_addr)
        return_path_domain = _domain_of(return_path_addr)
        sender_domain = _domain_of(sender_addr)
        message_id_domain = _domain_of_message_id(message_id_raw)

        findings: list[AnalyzerFinding] = []

        if from_addr:
            findings.append(
                AnalyzerFinding(
                    type="FROM_ADDRESS",
                    value=from_addr,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    description=f"Claimed From address is {from_addr}",
                    entity_refs=[f"sender:{from_addr}"],
                )
            )
        if reply_to_addr:
            findings.append(
                AnalyzerFinding(
                    type="REPLY_TO_ADDRESS",
                    value=reply_to_addr,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    description=f"Reply-To address is {reply_to_addr}",
                )
            )
        if return_path_addr:
            findings.append(
                AnalyzerFinding(
                    type="RETURN_PATH_ADDRESS",
                    value=return_path_addr,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    description=f"Return-Path address is {return_path_addr}",
                )
            )

        # --- Comparisons (Derived evidence) ---------------------------------
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            findings.append(
                AnalyzerFinding(
                    type="FROM_REPLYTO_MISMATCH",
                    value=True,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.DERIVED,
                    severity=Severity.HIGH,
                    description=(
                        f"From domain '{from_domain}' differs from Reply-To domain "
                        f"'{reply_to_domain}'. Replies would be routed away from the "
                        f"claimed sending organization."
                    ),
                )
            )

        if from_domain and return_path_domain and from_domain != return_path_domain:
            findings.append(
                AnalyzerFinding(
                    type="FROM_RETURNPATH_MISMATCH",
                    value=True,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.DERIVED,
                    severity=Severity.MEDIUM,
                    description=(
                        f"From domain '{from_domain}' differs from Return-Path domain "
                        f"'{return_path_domain}'. This can be legitimate (mailing "
                        f"infrastructure) but is also common in spoofing."
                    ),
                )
            )

        if from_domain and sender_domain and from_domain != sender_domain:
            findings.append(
                AnalyzerFinding(
                    type="FROM_SENDER_MISMATCH",
                    value=True,
                    reliability=Reliability.MEDIUM,
                    fact_level=FactLevel.DERIVED,
                    severity=Severity.LOW,
                    description=(
                        f"From domain '{from_domain}' differs from Sender header "
                        f"domain '{sender_domain}'."
                    ),
                )
            )

        if from_domain and message_id_domain and from_domain != message_id_domain:
            findings.append(
                AnalyzerFinding(
                    type="FROM_MESSAGEID_MISMATCH",
                    value=True,
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.DERIVED,
                    severity=Severity.LOW,
                    description=(
                        f"From domain '{from_domain}' differs from the domain embedded "
                        f"in Message-ID '{message_id_domain}'. Weak signal on its own — "
                        f"many legitimate mail systems generate Message-ID on a "
                        f"different host than the From domain."
                    ),
                )
            )

        # Suspicious display-name-vs-domain relationship (e.g. "PayPal Support"
        # <security@totally-not-paypal.xyz>) — only checked if we have a raw
        # From header with a display name.
        if from_raw and from_addr:
            display_part = from_raw.split("<")[0].strip().strip('"').lower()
            known_brands = [
                "paypal", "microsoft", "apple", "google", "amazon", "bank",
                "netflix", "irs", "dhl", "fedex", "visa", "mastercard",
            ]
            for brand in known_brands:
                if brand in display_part and from_domain and brand not in from_domain:
                    findings.append(
                        AnalyzerFinding(
                            type="DISPLAY_NAME_BRAND_MISMATCH",
                            value={"display_name": display_part, "brand": brand, "domain": from_domain},
                            reliability=Reliability.MEDIUM,
                            fact_level=FactLevel.DERIVED,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Display name references '{brand}' but the sending "
                                f"domain '{from_domain}' does not belong to that brand."
                            ),
                        )
                    )
                    break

        return AnalyzerResult(
            analyzer="header_identity",
            status=AnalyzerStatus.SUCCESS,
            findings=findings,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return AnalyzerResult(
            analyzer="header_identity",
            status=AnalyzerStatus.ERROR,
            findings=[],
            error=str(exc),
        )
