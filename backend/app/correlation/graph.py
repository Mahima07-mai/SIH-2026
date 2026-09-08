"""
Layer 4.1 — Entity Graph.

Builds a NetworkX graph from normalized evidence + the raw parsed email,
then exports it as the plain node/edge JSON shape the frontend (React Flow)
consumes. Kept intentionally simple for the prototype; swapping to Neo4j
later just means writing these same nodes/edges to Cypher instead.
"""
from __future__ import annotations

import networkx as nx

from app.schemas.evidence import Evidence, GraphEdge, GraphNode, EntityGraph


def _node_id(entity_ref: str) -> str:
    return entity_ref


def build_entity_graph(
    email_id: str,
    from_address: str | None,
    from_domain: str | None,
    reply_to_address: str | None,
    sending_ip: str | None,
    urls: list[str],
    url_domains: dict[str, str],
    attachments: list[dict],
    evidence: list[Evidence],
) -> EntityGraph:
    g = nx.DiGraph()

    email_node = f"email:{email_id}"
    g.add_node(email_node, type="EMAIL", label=f"Email {email_id}")

    if from_address:
        sender_node = f"sender:{from_address}"
        g.add_node(sender_node, type="SENDER", label=from_address)
        g.add_edge(email_node, sender_node, relationship="sent_by")

        if from_domain:
            domain_node = f"domain:{from_domain}"
            g.add_node(domain_node, type="DOMAIN", label=from_domain)
            g.add_edge(sender_node, domain_node, relationship="uses")

    if reply_to_address and reply_to_address != from_address:
        reply_node = f"replyto:{reply_to_address}"
        g.add_node(reply_node, type="REPLY_TO", label=reply_to_address)
        g.add_edge(email_node, reply_node, relationship="reply_directed_to")

    if sending_ip:
        ip_node = f"ip:{sending_ip}"
        g.add_node(ip_node, type="IP", label=sending_ip)
        g.add_edge(email_node, ip_node, relationship="sent_from_infra")

    for url in urls:
        url_node = f"url:{url}"
        short_label = url if len(url) <= 40 else url[:37] + "..."
        g.add_node(url_node, type="URL", label=short_label)
        g.add_edge(email_node, url_node, relationship="contains")

        domain = url_domains.get(url)
        if domain:
            domain_node = f"domain:{domain}"
            g.add_node(domain_node, type="DOMAIN", label=domain)
            g.add_edge(url_node, domain_node, relationship="belongs_to")

    for att in attachments:
        att_node = f"attachment:{att['filename']}"
        g.add_node(att_node, type="ATTACHMENT", label=att["filename"])
        g.add_edge(email_node, att_node, relationship="contains")
        if att.get("sha256"):
            hash_node = f"hash:{att['sha256']}"
            g.add_node(hash_node, type="HASH", label=att["sha256"][:12] + "...")
            g.add_edge(att_node, hash_node, relationship="has_hash")

    content_node = f"content:{email_id}"
    g.add_node(content_node, type="CONTENT", label="Email content")
    g.add_edge(email_node, content_node, relationship="contains")

    # Authentication (SPF/DKIM/DMARC) as its own node — these are directly
    # observed from the Authentication-Results header, so they get a
    # "Direct Evidence" edge back to the email like sender/IP/reply-to do.
    auth_evidence = [e for e in evidence if e.type in ("SPF_RESULT", "DKIM_RESULT", "DMARC_RESULT")]
    if auth_evidence:
        auth_node = f"auth:{email_id}"
        auth_summary = {e.type.replace("_RESULT", ""): e.value for e in auth_evidence}
        g.add_node(auth_node, type="AUTHENTICATION", label="Authentication", summary=auth_summary)
        g.add_edge(email_node, auth_node, relationship="authenticated_by")

    # Redirect chains: link the URL to where it actually lands, if that
    # differs from the URL itself, so a reviewer can see the true destination.
    for ev in evidence:
        if ev.type != "REDIRECT_CHAIN" or not isinstance(ev.value, dict):
            continue
        final_url = ev.value.get("final_url")
        redirect_count = ev.value.get("redirect_count", 0)
        src_node = next((ref for ref in ev.entity_refs if ref.startswith("url:")), None)
        if not (final_url and src_node and redirect_count and src_node in g):
            continue
        src_url = src_node.removeprefix("url:")
        if final_url == src_url:
            continue
        dest_node = f"url:{final_url}"
        short_label = final_url if len(final_url) <= 40 else final_url[:37] + "..."
        g.add_node(dest_node, type="URL", label=short_label)
        g.add_edge(src_node, dest_node, relationship="redirects_to")

    # Attach evidence counts to nodes for the "click a node -> see evidence" UI
    evidence_by_ref: dict[str, list[str]] = {}
    for ev in evidence:
        for ref in ev.entity_refs:
            evidence_by_ref.setdefault(ref, []).append(ev.evidence_id)

    def _evidence_ids_for(node_id: str, node_data: dict) -> list[str]:
        if node_data.get("type") == "AUTHENTICATION":
            return [e.evidence_id for e in auth_evidence]
        return evidence_by_ref.get(node_id, [])

    nodes = [
        GraphNode(
            id=node_id,
            type=data.get("type", "UNKNOWN"),
            label=data.get("label", node_id),
            data={
                "evidence_ids": _evidence_ids_for(node_id, data),
                **({"summary": data["summary"]} if "summary" in data else {}),
            },
        )
        for node_id, data in g.nodes(data=True)
    ]
    edges = [
        GraphEdge(source=u, target=v, relationship=data.get("relationship", "related_to"))
        for u, v, data in g.edges(data=True)
    ]

    return EntityGraph(nodes=nodes, edges=edges)
