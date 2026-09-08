"""
Canonical data contracts shared by every layer of the pipeline.

The single most important rule encoded here: `fact_level` (how the value was
obtained) and `reliability` (how much we trust it) are independent axes.
A GPT inference is `fact_level=Inferred` / `reliability=Medium`. A DMARC
result is `fact_level=Observed` / `reliability=High`. They must never be
conflated.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FactLevel(str, Enum):
    OBSERVED = "Observed"   # directly obtained (DMARC=FAIL, IP=1.2.3.4)
    DERIVED = "Derived"     # computed from observations (domain mismatch)
    INFERRED = "Inferred"   # model / heuristic interpretation (phishing_intent=0.9)


class Reliability(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AnalyzerStatus(str, Enum):
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class Evidence(BaseModel):
    """The single canonical unit every analyzer finding is normalized into."""

    evidence_id: str = Field(default_factory=lambda: f"EV-{uuid4().hex[:10]}")
    email_id: str
    type: str
    value: Any
    source: str
    reliability: Reliability
    fact_level: FactLevel
    description: str
    severity: Severity = Severity.INFO
    timestamp: str = Field(default_factory=now_iso)
    entity_refs: list[str] = Field(default_factory=list)


class AnalyzerFinding(BaseModel):
    """Raw finding shape returned by an analyzer before normalization."""

    type: str
    value: Any
    unit: Optional[str] = None
    reliability: Reliability = Reliability.MEDIUM
    fact_level: FactLevel = FactLevel.DERIVED
    description: str = ""
    severity: Severity = Severity.INFO
    entity_refs: list[str] = Field(default_factory=list)


class AnalyzerResult(BaseModel):
    """Uniform envelope every analyzer must return, success or failure."""

    analyzer: str
    status: AnalyzerStatus
    findings: list[AnalyzerFinding] = Field(default_factory=list)
    error: Optional[str] = None


class RuleHit(BaseModel):
    rule_id: str
    description: str
    matched_evidence: list[str]
    severity: Severity
    score_contribution: int


class ThreatSubcategory(BaseModel):
    category: str
    subcategory: Optional[str] = None


class ThreatResult(BaseModel):
    category: str
    subcategory: Optional[str] = None
    risk_score: int
    confidence: str
    reasoning: list[str]


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    data: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str


class EntityGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class ProofChainStep(BaseModel):
    step: int
    label: str
    fact_level: Optional[FactLevel] = None
    evidence_ids: list[str] = Field(default_factory=list)


class CampaignRelationship(BaseModel):
    related_email_id: str
    shared_indicator_type: str
    shared_value: str
    note: str
