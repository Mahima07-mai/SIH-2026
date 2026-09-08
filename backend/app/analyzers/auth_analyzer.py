"""
Layer 2.2 — Authentication Extractor.

Parses the `Authentication-Results` header (and presence of DKIM-Signature /
ARC headers) for SPF / DKIM / DMARC verdicts and coarse alignment signals.

IMPORTANT: results here are evidence, not a verdict. A DMARC failure alone
does not mean "malicious" — the correlation/classifier layers decide that.
"""
from __future__ import annotations

import re

from app.schemas.evidence import (
    AnalyzerFinding,
    AnalyzerResult,
    AnalyzerStatus,
    FactLevel,
    Reliability,
    Severity,
)

_RESULT_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", re.I)


def _parse_auth_results(auth_header: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for mech, verdict in _RESULT_RE.findall(auth_header or ""):
        # Keep the first occurrence per mechanism (outermost / most relevant hop)
        key = mech.lower()
        if key not in results:
            results[key] = verdict.lower()
    return results


def analyze_authentication(
    email_id: str,
    authentication_results_raw: str | None,
    dkim_signature_raw: str | None,
    arc_headers_raw: str | None,
    from_domain: str | None,
) -> AnalyzerResult:
    try:
        findings: list[AnalyzerFinding] = []

        if not authentication_results_raw:
            findings.append(
                AnalyzerFinding(
                    type="AUTHENTICATION_RESULTS",
                    value="not_present",
                    reliability=Reliability.MEDIUM,
                    fact_level=FactLevel.OBSERVED,
                    severity=Severity.LOW,
                    description=(
                        "No Authentication-Results header was supplied. SPF/DKIM/DMARC "
                        "verdicts are unknown, not necessarily failing."
                    ),
                )
            )
        else:
            parsed = _parse_auth_results(authentication_results_raw)

            for mech in ("spf", "dkim", "dmarc"):
                verdict = parsed.get(mech)
                if not verdict:
                    continue
                is_fail = verdict in ("fail", "softfail", "permerror")
                findings.append(
                    AnalyzerFinding(
                        type=f"{mech.upper()}_RESULT",
                        value=verdict.upper(),
                        reliability=Reliability.HIGH,
                        fact_level=FactLevel.OBSERVED,
                        severity=Severity.HIGH if (mech == "dmarc" and is_fail) else (
                            Severity.MEDIUM if is_fail else Severity.INFO
                        ),
                        description=f"{mech.upper()} authentication result: {verdict.upper()}.",
                    )
                )

            if parsed.get("dmarc") in ("fail", "permerror"):
                findings.append(
                    AnalyzerFinding(
                        type="DMARC_FAILURE",
                        value=True,
                        reliability=Reliability.HIGH,
                        fact_level=FactLevel.OBSERVED,
                        severity=Severity.HIGH,
                        description=(
                            "DMARC failed. This is an authentication anomaly that "
                            "contributes to — but does not by itself prove — spoofing."
                        ),
                    )
                )

        findings.append(
            AnalyzerFinding(
                type="DKIM_SIGNATURE_PRESENT",
                value=bool(dkim_signature_raw),
                reliability=Reliability.HIGH,
                fact_level=FactLevel.OBSERVED,
                description=(
                    "A DKIM-Signature header is present." if dkim_signature_raw
                    else "No DKIM-Signature header was supplied."
                ),
            )
        )

        findings.append(
            AnalyzerFinding(
                type="ARC_HEADERS_PRESENT",
                value=bool(arc_headers_raw),
                reliability=Reliability.MEDIUM,
                fact_level=FactLevel.OBSERVED,
                description=(
                    "ARC headers present (message passed through an intermediary that "
                    "re-attested authentication)." if arc_headers_raw
                    else "No ARC headers were supplied."
                ),
            )
        )

        return AnalyzerResult(
            analyzer="authentication",
            status=AnalyzerStatus.SUCCESS,
            findings=findings,
        )
    except Exception as exc:  # pragma: no cover
        return AnalyzerResult(
            analyzer="authentication",
            status=AnalyzerStatus.ERROR,
            findings=[],
            error=str(exc),
        )
