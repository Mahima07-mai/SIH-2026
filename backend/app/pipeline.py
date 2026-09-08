"""
The main pipeline orchestrator: Ingestion -> Parallel Extraction ->
Normalization -> Correlation -> NLP -> Classification -> Campaign -> Report.

This is intentionally synchronous/sequential in the prototype (analyzers
are cheap enough, and it keeps the logic easy to follow end-to-end for a
demo/judge). The FastAPI layer wraps this in a BackgroundTask so the HTTP
request returns immediately with a progress-pollable email_id.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

import tldextract

from app.analyzers.attachment_analyzer import analyze_attachment
from app.analyzers.auth_analyzer import analyze_authentication
from app.analyzers.domain_analyzer import analyze_domain
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.infra_analyzer import analyze_infrastructure, extract_ips_from_received
from app.analyzers.nlp_analyzer import analyze_nlp
from app.analyzers.url_analyzer import analyze_url, extract_urls
from app.correlation.campaign import find_campaign_relationships
from app.correlation.graph import build_entity_graph
from app.correlation.rules import run_rules
from app.classifier.threat_classifier import classify_threat
from app.reporting.limitations import build_limitations
from app.reporting.proof_chain import build_proof_chain
from app.schemas.evidence import AnalyzerFinding, AnalyzerResult, Evidence
from app.schemas.input import AnalyzeRequest
from app.storage import STORE, StoredAnalysis
from app.utils.header_parser import merge_headers, parse_raw_headers
from email.utils import getaddresses


def _registered_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    return ".".join(p for p in (ext.domain, ext.suffix) if p) or hostname


def _findings_to_evidence(email_id: str, result: AnalyzerResult) -> list[Evidence]:
    evidence: list[Evidence] = []
    for f in result.findings:
        evidence.append(
            Evidence(
                email_id=email_id,
                type=f.type,
                value=f.value,
                source=result.analyzer,
                reliability=f.reliability,
                fact_level=f.fact_level,
                description=f.description,
                severity=f.severity,
                entity_refs=f.entity_refs,
            )
        )
    return evidence


def run_analysis(request: AnalyzeRequest) -> dict:
    email_id = f"EMAIL-{uuid.uuid4().hex[:8].upper()}"
    started_at = datetime.now(timezone.utc).isoformat()

    # ---------------------------------------------------------------
    # LAYER 1: INGESTION & PARSING
    # ---------------------------------------------------------------
    structured = {
        "from": request.headers.from_address,
        "to": request.headers.to,
        "cc": request.headers.cc,
        "reply_to": request.headers.reply_to,
        "return_path": request.headers.return_path,
        "sender": request.headers.sender,
        "subject": request.headers.subject,
        "message_id": request.headers.message_id,
        "date": request.headers.date,
        "received": request.headers.received,
        "authentication_results": request.headers.authentication_results,
        "dkim_signature": request.headers.dkim_signature,
        "arc_headers": request.headers.arc_headers,
    }
    parsed_from_raw = parse_raw_headers(request.headers.raw_headers or "")
    headers = merge_headers(structured, parsed_from_raw)

    subject = headers.get("subject")
    body_text = request.body.plain_text or ""
    body_html = request.body.html or ""

    manual_urls = extract_urls("\n".join(request.urls))
    body_urls = extract_urls(body_text, body_html)
    all_urls = list(dict.fromkeys(manual_urls + body_urls))  # dedupe, order-preserving

    analyzer_statuses: dict[str, str] = {}
    all_evidence: list[Evidence] = []

    # ---------------------------------------------------------------
    # LAYER 2.1: HEADER / IDENTITY
    # ---------------------------------------------------------------
    header_result = analyze_headers(
        email_id,
        headers.get("from"),
        headers.get("reply_to"),
        headers.get("return_path"),
        headers.get("sender"),
        headers.get("message_id"),
    )
    all_evidence += _findings_to_evidence(email_id, header_result)
    analyzer_statuses["header_identity"] = header_result.status.value

    from_addr = None
    parsed_from = getaddresses([headers.get("from") or ""])
    if parsed_from and parsed_from[0][1]:
        from_addr = parsed_from[0][1].strip().lower()
    from_domain = from_addr.rsplit("@", 1)[-1] if from_addr and "@" in from_addr else None

    reply_to_addr = None
    parsed_reply = getaddresses([headers.get("reply_to") or ""])
    if parsed_reply and parsed_reply[0][1]:
        reply_to_addr = parsed_reply[0][1].strip().lower()

    # ---------------------------------------------------------------
    # LAYER 2.2: AUTHENTICATION
    # ---------------------------------------------------------------
    auth_result = analyze_authentication(
        email_id,
        headers.get("authentication_results"),
        headers.get("dkim_signature"),
        headers.get("arc_headers"),
        from_domain,
    )
    all_evidence += _findings_to_evidence(email_id, auth_result)
    analyzer_statuses["authentication"] = auth_result.status.value

    # ---------------------------------------------------------------
    # LAYER 2.3: INFRASTRUCTURE
    # ---------------------------------------------------------------
    infra_result = analyze_infrastructure(email_id, headers.get("received"))
    all_evidence += _findings_to_evidence(email_id, infra_result)
    analyzer_statuses["infrastructure"] = infra_result.status.value

    sending_ip = None
    for f in infra_result.findings:
        if f.type == "SENDING_IP" and f.value:
            sending_ip = f.value

    # ---------------------------------------------------------------
    # LAYER 2.4: DOMAIN INTELLIGENCE (From domain + URL domains, deduped)
    # ---------------------------------------------------------------
    domains_to_check: dict[str, str] = {}
    if from_domain:
        domains_to_check[from_domain] = "from"
    url_domains: dict[str, str] = {}
    for url in all_urls:
        try:
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname or ""
        except Exception:
            hostname = ""
        if hostname:
            reg_domain = _registered_domain(hostname)
            url_domains[url] = reg_domain
            domains_to_check.setdefault(reg_domain, f"url:{url}")

    domain_statuses = []
    for domain, context in domains_to_check.items():
        d_result = analyze_domain(email_id, domain, context)
        all_evidence += _findings_to_evidence(email_id, d_result)
        domain_statuses.append(d_result.status.value)
    analyzer_statuses["domain_intelligence"] = (
        "success" if any(s == "success" for s in domain_statuses) else "not_applicable"
    ) if domain_statuses else "not_applicable"

    # ---------------------------------------------------------------
    # LAYER 2.5: URL INTELLIGENCE
    # ---------------------------------------------------------------
    url_statuses = []
    for url in all_urls:
        u_result = analyze_url(email_id, url)
        all_evidence += _findings_to_evidence(email_id, u_result)
        url_statuses.append(u_result.status.value)
    analyzer_statuses["url_intelligence"] = (
        "success" if any(s == "success" for s in url_statuses) else "not_applicable"
    ) if url_statuses else "not_applicable"

    # ---------------------------------------------------------------
    # LAYER 2.6: ATTACHMENT INTELLIGENCE
    # ---------------------------------------------------------------
    attachment_summaries: list[dict] = []
    attachment_statuses = []
    for att in request.attachments:
        try:
            content = base64.b64decode(att.content_base64)
        except Exception:
            content = b""
        a_result = analyze_attachment(email_id, att.filename, att.mime_type, content)
        all_evidence += _findings_to_evidence(email_id, a_result)
        attachment_statuses.append(a_result.status.value)

        sha256 = next((f.value for f in a_result.findings if f.type == "FILE_HASH_SHA256"), None)
        attachment_summaries.append({"filename": att.filename, "sha256": sha256})
    analyzer_statuses["attachment_intelligence"] = (
        "success" if any(s == "success" for s in attachment_statuses) else "not_applicable"
    ) if attachment_statuses else "not_applicable"

    # ---------------------------------------------------------------
    # LAYER 2.7 / LAYER 5: CONTENT / NLP (advisory only)
    # ---------------------------------------------------------------
    nlp_result = analyze_nlp(email_id, subject, body_text or body_html)
    all_evidence += _findings_to_evidence(email_id, nlp_result)
    analyzer_statuses["content_nlp"] = nlp_result.status.value

    # ---------------------------------------------------------------
    # LAYER 4: CORRELATION — rules + scoring
    # ---------------------------------------------------------------
    rule_hits = run_rules(all_evidence)

    # ---------------------------------------------------------------
    # LAYER 6: THREAT CLASSIFICATION (deterministic, not the LLM)
    # ---------------------------------------------------------------
    threat_result = classify_threat(all_evidence, rule_hits)

    # ---------------------------------------------------------------
    # LAYER 7: CROSS-EMAIL CAMPAIGN ENGINE
    # ---------------------------------------------------------------
    attachment_hashes = [a["sha256"] for a in attachment_summaries if a.get("sha256")]
    campaign_relationships = find_campaign_relationships(
        email_id, from_addr, sending_ip, list(url_domains.values()), attachment_hashes
    )

    # ---------------------------------------------------------------
    # LAYER 4.1 / 8: ENTITY GRAPH
    # ---------------------------------------------------------------
    entity_graph = build_entity_graph(
        email_id,
        from_addr,
        from_domain,
        reply_to_addr,
        sending_ip,
        all_urls,
        url_domains,
        attachment_summaries,
        all_evidence,
    )

    # ---------------------------------------------------------------
    # LAYER 8: PROOF CHAIN + LIMITATIONS
    # ---------------------------------------------------------------
    proof_chain = build_proof_chain(all_evidence, rule_hits, threat_result)
    limitations = build_limitations(all_evidence)

    # ---------------------------------------------------------------
    # TIMELINE (only real timestamps — never invented)
    # ---------------------------------------------------------------
    timeline = []
    domain_age_ev = next((e for e in all_evidence if e.type == "DOMAIN_AGE" and isinstance(e.value, int)), None)
    if domain_age_ev:
        timeline.append({"label": "Domain registered", "detail": f"{domain_age_ev.value} days before analysis"})
    if headers.get("date"):
        timeline.append({"label": "Email Date header", "detail": headers["date"]})
    timeline.append({"label": "Analysis performed", "detail": started_at})

    result = {
        "email_id": email_id,
        "label": request.label,
        "analyzed_at": started_at,
        "analyzer_statuses": analyzer_statuses,
        "headers": headers,
        "body": {"plain_text": body_text, "html": body_html},
        "urls": all_urls,
        "attachments": attachment_summaries,
        "evidence": [e.model_dump() for e in all_evidence],
        "rule_hits": [h.model_dump() for h in rule_hits],
        "threat_result": threat_result.model_dump(),
        "entity_graph": entity_graph.model_dump(),
        "proof_chain": [s.model_dump() for s in proof_chain],
        "campaign_relationships": [c.model_dump() for c in campaign_relationships],
        "limitations": limitations,
        "timeline": timeline,
    }

    STORE.save(
        StoredAnalysis(
            email_id=email_id,
            label=request.label,
            from_address=from_addr,
            from_domain=from_domain,
            sending_ip=sending_ip,
            url_domains=list(url_domains.values()),
            attachment_hashes=attachment_hashes,
            category=threat_result.category,
            risk_score=threat_result.risk_score,
            full_result=result,
        )
    )

    return result
