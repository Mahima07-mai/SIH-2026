"""
Layer 7 — Cross-Email Campaign Engine.

Compares the current email's indicators against previously analyzed emails
in the store, looking for shared infrastructure. Deliberately conservative
in language: shared indicators suggest a possible campaign relationship,
never a confirmed common-attacker claim.
"""
from __future__ import annotations

from app.schemas.evidence import CampaignRelationship
from app.storage import STORE, StoredAnalysis


def find_campaign_relationships(
    email_id: str,
    from_address: str | None,
    sending_ip: str | None,
    url_domains: list[str],
    attachment_hashes: list[str],
) -> list[CampaignRelationship]:
    relationships: list[CampaignRelationship] = []

    for other in STORE.all_except(email_id):
        if sending_ip and other.sending_ip and sending_ip == other.sending_ip:
            relationships.append(
                CampaignRelationship(
                    related_email_id=other.email_id,
                    shared_indicator_type="IP",
                    shared_value=sending_ip,
                    note=(
                        f"Shared infrastructure observed: both emails were sent from IP "
                        f"{sending_ip}. This suggests — but does not confirm — a campaign "
                        f"relationship."
                    ),
                )
            )

        shared_domains = set(url_domains) & set(other.url_domains)
        for domain in shared_domains:
            relationships.append(
                CampaignRelationship(
                    related_email_id=other.email_id,
                    shared_indicator_type="DOMAIN",
                    shared_value=domain,
                    note=f"Shared URL domain observed: '{domain}' appears in both emails.",
                )
            )

        shared_hashes = set(attachment_hashes) & set(other.attachment_hashes)
        for h in shared_hashes:
            relationships.append(
                CampaignRelationship(
                    related_email_id=other.email_id,
                    shared_indicator_type="ATTACHMENT_HASH",
                    shared_value=h,
                    note=f"Identical attachment hash observed: {h[:16]}... appears in both emails.",
                )
            )

        if from_address and other.from_address and from_address == other.from_address:
            relationships.append(
                CampaignRelationship(
                    related_email_id=other.email_id,
                    shared_indicator_type="SENDER",
                    shared_value=from_address,
                    note=f"Shared sender address observed: {from_address}.",
                )
            )

    return relationships
