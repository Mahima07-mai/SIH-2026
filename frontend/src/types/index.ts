export type FactLevel = "Observed" | "Derived" | "Inferred";
export type Reliability = "High" | "Medium" | "Low";
export type Severity = "Info" | "Low" | "Medium" | "High" | "Critical";

export interface Evidence {
  evidence_id: string;
  email_id: string;
  type: string;
  value: unknown;
  source: string;
  reliability: Reliability;
  fact_level: FactLevel;
  description: string;
  severity: Severity;
  timestamp: string;
  entity_refs: string[];
}

export interface RuleHit {
  rule_id: string;
  description: string;
  matched_evidence: string[];
  severity: Severity;
  score_contribution: number;
}

export interface ThreatResult {
  category: string;
  subcategory: string | null;
  risk_score: number;
  confidence: string;
  reasoning: string[];
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  data: { evidence_ids: string[]; summary?: Record<string, string> };
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
}

export interface EntityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ProofChainStep {
  step: number;
  label: string;
  fact_level: FactLevel | null;
  evidence_ids: string[];
}

export interface CampaignRelationship {
  related_email_id: string;
  shared_indicator_type: string;
  shared_value: string;
  note: string;
}

export interface TimelineItem {
  label: string;
  detail: string;
}

export interface AnalysisResult {
  email_id: string;
  label: string | null;
  analyzed_at: string;
  analyzer_statuses: Record<string, string>;
  headers: Record<string, string | null>;
  body: { plain_text: string; html: string };
  urls: string[];
  attachments: { filename: string; sha256: string | null }[];
  evidence: Evidence[];
  rule_hits: RuleHit[];
  threat_result: ThreatResult;
  entity_graph: EntityGraph;
  proof_chain: ProofChainStep[];
  campaign_relationships: CampaignRelationship[];
  limitations: string[];
  timeline: TimelineItem[];
}

export interface AttachmentDraft {
  filename: string;
  mime_type: string;
  size: number;
  content_base64: string;
}
