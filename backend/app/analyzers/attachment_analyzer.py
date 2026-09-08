"""
Layer 2.6 — Attachment Extractor.

Hashes and inspects attachments WITHOUT ever executing them. MIME detection
via python-magic is best-effort — if libmagic isn't installed on the host,
this degrades to declared-MIME-only rather than crashing.
"""
from __future__ import annotations

import hashlib
import io
import zipfile

from app.schemas.evidence import (
    AnalyzerFinding,
    AnalyzerResult,
    AnalyzerStatus,
    FactLevel,
    Reliability,
    Severity,
)

MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
EXECUTABLE_LOOKALIKE_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".ps1"}


def _detect_mime(content: bytes) -> tuple[str | None, str]:
    try:
        import magic  # python-magic
        return magic.from_buffer(content, mime=True), "python-magic"
    except Exception:
        # Minimal built-in magic-byte fallback so the analyzer still says
        # *something* useful without libmagic installed.
        sigs = [
            (b"%PDF-", "application/pdf"),
            (b"PK\x03\x04", "application/zip"),
            (b"\xd0\xcf\x11\xe0", "application/x-ole-storage"),
            (b"MZ", "application/x-dosexec"),
            (b"\x89PNG", "image/png"),
            (b"\xff\xd8\xff", "image/jpeg"),
        ]
        for magic_bytes, mime in sigs:
            if content.startswith(magic_bytes):
                return mime, "signature-fallback"
        return None, "unavailable"


def _has_office_macro(content: bytes) -> bool | str:
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
    except Exception:
        return "unavailable"
    try:
        vba = VBA_Parser(filename="attachment", data=content)
        has_macro = vba.detect_vba_macros()
        vba.close()
        return bool(has_macro)
    except Exception:
        return "unavailable"


def _run_yara(content: bytes) -> list[str] | str:
    try:
        import yara  # yara-python
    except Exception:
        return "unavailable"
    # A tiny illustrative ruleset — production deployments should load a
    # maintained ruleset (e.g. from a threat-intel feed).
    rules_src = r"""
    rule Suspicious_PowerShell_Encoded {
        strings:
            $a = "-enc" nocase
            $b = "-EncodedCommand" nocase
            $c = "FromBase64String" nocase
        condition:
            any of them
    }
    rule Suspicious_Office_AutoOpen {
        strings:
            $a = "AutoOpen" nocase
            $b = "Auto_Open" nocase
            $c = "Shell(" nocase
        condition:
            any of them
    }
    """
    try:
        compiled = yara.compile(source=rules_src)
        matches = compiled.match(data=content)
        return [m.rule for m in matches]
    except Exception:
        return "unavailable"


def analyze_attachment(
    email_id: str,
    filename: str,
    declared_mime: str | None,
    content: bytes,
) -> AnalyzerResult:
    try:
        findings: list[AnalyzerFinding] = []
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""

        sha256 = hashlib.sha256(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        size = len(content)

        findings.append(
            AnalyzerFinding(
                type="FILE_HASH_SHA256",
                value=sha256,
                reliability=Reliability.HIGH,
                fact_level=FactLevel.OBSERVED,
                description=f"SHA-256 of '{filename}' is {sha256}.",
                entity_refs=[f"attachment:{filename}", f"hash:{sha256}"],
            )
        )
        findings.append(
            AnalyzerFinding(
                type="FILE_HASH_SHA1",
                value=sha1,
                reliability=Reliability.HIGH,
                fact_level=FactLevel.OBSERVED,
                description=f"SHA-1 of '{filename}' is {sha1}.",
            )
        )
        findings.append(
            AnalyzerFinding(
                type="FILE_SIZE",
                value=size,
                unit="bytes",
                reliability=Reliability.HIGH,
                fact_level=FactLevel.OBSERVED,
                description=f"'{filename}' is {size} bytes.",
            )
        )

        detected_mime, detection_method = _detect_mime(content)
        findings.append(
            AnalyzerFinding(
                type="DETECTED_MIME",
                value=detected_mime or "unavailable",
                reliability=Reliability.HIGH if detected_mime else Reliability.LOW,
                fact_level=FactLevel.OBSERVED,
                description=(
                    f"Detected MIME type via {detection_method}: {detected_mime}."
                    if detected_mime else "MIME detection unavailable (libmagic not installed)."
                ),
            )
        )

        if declared_mime and detected_mime and declared_mime.lower() != detected_mime.lower():
            findings.append(
                AnalyzerFinding(
                    type="MIME_MISMATCH",
                    value={"declared": declared_mime, "detected": detected_mime},
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.DERIVED,
                    severity=Severity.HIGH,
                    description=(
                        f"Declared MIME '{declared_mime}' does not match detected MIME "
                        f"'{detected_mime}' for '{filename}'. This is a classic disguise "
                        f"technique (e.g. an executable renamed to look like a document)."
                    ),
                )
            )

        if ext in EXECUTABLE_LOOKALIKE_EXTENSIONS:
            findings.append(
                AnalyzerFinding(
                    type="EXECUTABLE_EXTENSION",
                    value=ext,
                    reliability=Reliability.HIGH,
                    fact_level=FactLevel.OBSERVED,
                    severity=Severity.HIGH,
                    description=f"'{filename}' has an executable/script extension ({ext}).",
                )
            )

        if ext in MACRO_ENABLED_EXTENSIONS or (detected_mime == "application/x-ole-storage"):
            macro_result = _has_office_macro(content)
            if macro_result == "unavailable":
                findings.append(
                    AnalyzerFinding(
                        type="MACRO_DETECTED",
                        value="unavailable",
                        reliability=Reliability.LOW,
                        fact_level=FactLevel.OBSERVED,
                        description="Macro analysis unavailable (oletools not installed).",
                    )
                )
            else:
                findings.append(
                    AnalyzerFinding(
                        type="MACRO_DETECTED",
                        value=bool(macro_result),
                        reliability=Reliability.HIGH,
                        fact_level=FactLevel.OBSERVED,
                        severity=Severity.HIGH if macro_result else Severity.INFO,
                        description=(
                            f"VBA macros were detected in '{filename}'." if macro_result
                            else f"No VBA macros were detected in '{filename}'."
                        ),
                    )
                )

        if detected_mime == "application/zip" or ext == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    names = zf.namelist()[:50]
                    findings.append(
                        AnalyzerFinding(
                            type="ARCHIVE_CONTENTS",
                            value=names,
                            reliability=Reliability.HIGH,
                            fact_level=FactLevel.OBSERVED,
                            description=f"Archive '{filename}' contains {len(zf.namelist())} entries (listed without extraction).",
                        )
                    )
            except Exception:
                findings.append(
                    AnalyzerFinding(
                        type="ARCHIVE_CONTENTS",
                        value="unavailable",
                        reliability=Reliability.LOW,
                        fact_level=FactLevel.OBSERVED,
                        description=f"Could not safely list contents of archive '{filename}'.",
                    )
                )

        yara_result = _run_yara(content)
        if yara_result == "unavailable":
            findings.append(
                AnalyzerFinding(
                    type="YARA_MATCHES",
                    value="unavailable",
                    reliability=Reliability.LOW,
                    fact_level=FactLevel.OBSERVED,
                    description="YARA scanning unavailable (yara-python not installed).",
                )
            )
        else:
            findings.append(
                AnalyzerFinding(
                    type="YARA_MATCHES",
                    value=yara_result,
                    reliability=Reliability.MEDIUM,
                    fact_level=FactLevel.DERIVED,
                    severity=Severity.HIGH if yara_result else Severity.INFO,
                    description=(
                        f"YARA rule(s) matched: {', '.join(yara_result)}." if yara_result
                        else "No YARA rule matches (illustrative ruleset only)."
                    ),
                )
            )

        findings.append(
            AnalyzerFinding(
                type="SANDBOX_STATUS",
                value="NOT_AVAILABLE",
                reliability=Reliability.LOW,
                fact_level=FactLevel.OBSERVED,
                description=(
                    "Dynamic sandbox detonation is not implemented in this prototype. "
                    "Uploaded files are never executed on this host."
                ),
            )
        )

        return AnalyzerResult(analyzer="attachment_intelligence", status=AnalyzerStatus.SUCCESS, findings=findings)
    except Exception as exc:  # pragma: no cover
        return AnalyzerResult(analyzer="attachment_intelligence", status=AnalyzerStatus.ERROR, findings=[], error=str(exc))
