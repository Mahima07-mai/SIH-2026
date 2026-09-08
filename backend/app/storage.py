"""
Storage layer for the prototype.

Uses a simple in-process store (a dict of dataclasses) so the whole thing
runs with zero external services for a hackathon demo. The shape mirrors
the DB tables described in the spec (EMAIL, EVIDENCE, RULE_HIT,
THREAT_RESULT, GRAPH_EDGE, CAMPAIGN...) closely enough that swapping this
module for a real SQLAlchemy/Postgres-backed implementation later is a
drop-in replacement — nothing above this layer needs to change.

For anything beyond a single demo session, replace `_STORE` with real
SQLAlchemy models bound to `settings.database_url`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StoredAnalysis:
    email_id: str
    label: str | None
    from_address: str | None
    from_domain: str | None
    sending_ip: str | None
    url_domains: list[str]
    attachment_hashes: list[str]
    category: str
    risk_score: int
    full_result: dict[str, Any] = field(default_factory=dict)


class _Store:
    def __init__(self) -> None:
        self.analyses: dict[str, StoredAnalysis] = {}

    def save(self, analysis: StoredAnalysis) -> None:
        self.analyses[analysis.email_id] = analysis

    def get(self, email_id: str) -> StoredAnalysis | None:
        return self.analyses.get(email_id)

    def all_except(self, email_id: str) -> list[StoredAnalysis]:
        return [a for eid, a in self.analyses.items() if eid != email_id]

    def all(self) -> list[StoredAnalysis]:
        return list(self.analyses.values())


STORE = _Store()
