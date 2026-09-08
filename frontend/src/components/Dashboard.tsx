import { useState } from "react";
import {
  Download,
  ArrowLeft,
  AlertTriangle,
  LayoutDashboard,
  User,
  ShieldCheck,
  Server,
  Globe,
  Link2,
  Paperclip,
  Brain,
  Table2,
  Workflow,
  Share2,
  Users,
  Ban,
  type LucideIcon,
} from "lucide-react";
import type { AnalysisResult, Evidence } from "../types";
import { CategoryBadge, ConfidenceBadge, RiskGauge, SeverityBadge } from "./Badges";
import EvidenceTable from "./EvidenceTable";
import ProofChainView from "./ProofChainView";
import EntityGraphView from "./EntityGraphView";
import { downloadPdfReport } from "../services/api";

const TABS = [
  "Overview", "Sender", "Authentication", "Infrastructure", "Domains", "URLs",
  "Attachments", "NLP", "Evidence", "Proof Chain", "Entity Graph", "Campaigns", "Limitations",
] as const;
type Tab = (typeof TABS)[number];

// Icon + accent per tab, echoing the color language used in the entity graph
// and evidence table so the same category reads the same way everywhere.
const TAB_META: Record<Tab, { icon: LucideIcon; color: string }> = {
  "Overview": { icon: LayoutDashboard, color: "#f0a43a" },
  "Sender": { icon: User, color: "#fbbf24" },
  "Authentication": { icon: ShieldCheck, color: "#34d399" },
  "Infrastructure": { icon: Server, color: "#2dd4bf" },
  "Domains": { icon: Globe, color: "#fb923c" },
  "URLs": { icon: Link2, color: "#f87171" },
  "Attachments": { icon: Paperclip, color: "#60a5fa" },
  "NLP": { icon: Brain, color: "#e879f9" },
  "Evidence": { icon: Table2, color: "#94a3b8" },
  "Proof Chain": { icon: Workflow, color: "#94a3b8" },
  "Entity Graph": { icon: Share2, color: "#94a3b8" },
  "Campaigns": { icon: Users, color: "#94a3b8" },
  "Limitations": { icon: Ban, color: "#94a3b8" },
};

function evOfType(evidence: Evidence[], type: string) {
  return evidence.filter((e) => e.type === type);
}

export default function Dashboard({ result, onReset }: { result: AnalysisResult; onReset: () => void }) {
  const [tab, setTab] = useState<Tab>("Overview");
  const [downloading, setDownloading] = useState(false);
  const { threat_result, evidence, rule_hits } = result;

  const topRules = [...rule_hits].sort((a, b) => b.score_contribution - a.score_contribution).slice(0, 5);
  const topEvidence = [...evidence]
    .filter((e) => e.severity === "High" || e.severity === "Critical")
    .slice(0, 5);

  const handleExport = async () => {
    setDownloading(true);
    try {
      await downloadPdfReport(result.email_id);
    } catch (e) {
      alert("Failed to generate PDF report. Is the backend running?");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto pb-24 grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-6">
      {/* LEFT RAIL: verdict summary + navigation */}
      <aside className="lg:sticky lg:top-20 lg:self-start space-y-4">
        <button onClick={onReset} className="flex items-center gap-1 text-sm text-slate-400 hover:text-white">
          <ArrowLeft size={16} /> New analysis
        </button>

        <div className="card p-5 flex flex-col items-center text-center gap-3">
          <RiskGauge score={threat_result.risk_score} />
          <CategoryBadge category={threat_result.category} />
          {threat_result.subcategory && (
            <span className="text-slate-400 text-xs -mt-2">{threat_result.subcategory}</span>
          )}
          <div className="text-slate-400 text-xs flex items-center gap-1.5">
            Confidence:
            <ConfidenceBadge
              confidence={threat_result.confidence}
              riskScore={threat_result.risk_score}
              evidenceCount={evidence.length}
            />
          </div>
          <div className="text-slate-600 text-[11px] pt-2 border-t border-soc-border w-full">
            {result.email_id}
            <br />
            {new Date(result.analyzed_at).toLocaleString()}
          </div>
          <button
            onClick={handleExport}
            disabled={downloading}
            className="flex items-center justify-center gap-2 text-sm bg-soc-accent text-black font-semibold px-4 py-2 rounded-lg disabled:opacity-50 w-full"
          >
            <Download size={16} /> {downloading ? "Generating…" : "Export PDF"}
          </button>
        </div>

        <nav className="card p-2">
          {TABS.map((t) => {
            const meta = TAB_META[t];
            const Icon = meta.icon;
            const active = tab === t;
            return (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`w-full flex items-center gap-2.5 text-left text-sm px-3 py-2 rounded-md transition-colors ${
                  active ? "bg-white/5 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]"
                }`}
              >
                <Icon size={15} style={{ color: active ? meta.color : undefined }} className={active ? "" : "text-slate-600"} />
                {t}
              </button>
            );
          })}
        </nav>
      </aside>

      {/* MAIN CONTENT */}
      <div className="min-w-0">
      {tab === "Overview" && (
        <div className="grid md:grid-cols-2 gap-6">
          <div className="card p-5">
            <h3 className="font-semibold text-white mb-3">Top Evidence</h3>
            <ul className="space-y-2">
              {topEvidence.length === 0 && <li className="text-sm text-slate-500">No high/critical severity evidence found.</li>}
              {topEvidence.map((e) => (
                <li key={e.evidence_id} className="flex items-start gap-2 text-sm">
                  <SeverityBadge severity={e.severity} />
                  <span className="text-slate-300">{e.description}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="card p-5">
            <h3 className="font-semibold text-white mb-3">Top Rule Hits</h3>
            <ul className="space-y-2">
              {topRules.length === 0 && <li className="text-sm text-slate-500">No deterministic rules fired.</li>}
              {topRules.map((r) => (
                <li key={r.rule_id} className="flex items-start justify-between gap-2 text-sm">
                  <span className="text-slate-300">{r.description}</span>
                  <span className="text-soc-accent font-mono shrink-0">+{r.score_contribution}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="card p-5 md:col-span-2">
            <h3 className="font-semibold text-white mb-3">Analyzer Status</h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(result.analyzer_statuses).map(([k, v]) => (
                <span
                  key={k}
                  className={`text-xs px-3 py-1 rounded-full border ${
                    v === "success" ? "border-emerald-700 text-emerald-300" : "border-slate-600 text-slate-400"
                  }`}
                >
                  {k.replace(/_/g, " ")}: {v}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === "Sender" && (
        <div className="card p-5 space-y-2">
          {["from", "to", "cc", "reply_to", "return_path", "sender", "message_id"].map((k) => (
            <div key={k} className="flex gap-4 text-sm">
              <span className="w-32 text-slate-500 capitalize">{k.replace(/_/g, " ")}</span>
              <span className="text-slate-200">{result.headers[k] || "(not supplied)"}</span>
            </div>
          ))}
          <div className="pt-4 border-t border-soc-border mt-4">
            <h4 className="text-sm font-semibold text-white mb-2">Identity findings</h4>
            <ul className="space-y-1">
              {evidence
                .filter((e) => e.source === "header_identity")
                .map((e) => (
                  <li key={e.evidence_id} className="text-sm text-slate-300 flex gap-2">
                    <SeverityBadge severity={e.severity} /> {e.description}
                  </li>
                ))}
            </ul>
          </div>
        </div>
      )}

      {tab === "Authentication" && (
        <div className="card p-5">
          <ul className="space-y-2">
            {evidence
              .filter((e) => e.source === "authentication")
              .map((e) => (
                <li key={e.evidence_id} className="flex items-center gap-2 text-sm">
                  <SeverityBadge severity={e.severity} />
                  <span className="font-mono text-xs text-slate-500">{e.type}</span>
                  <span className="text-slate-300">{e.description}</span>
                </li>
              ))}
          </ul>
        </div>
      )}

      {tab === "Infrastructure" && (
        <div className="card p-5 space-y-3">
          <div className="flex items-start gap-2 text-xs text-amber-300 bg-amber-950/30 border border-amber-800 rounded-lg p-3">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            This represents observed network infrastructure and does not establish the physical
            location or identity of the sender.
          </div>
          <ul className="space-y-2">
            {evidence
              .filter((e) => e.source === "infrastructure")
              .map((e) => (
                <li key={e.evidence_id} className="text-sm text-slate-300">
                  <span className="font-mono text-xs text-slate-500 mr-2">{e.type}</span>
                  {e.description}
                </li>
              ))}
          </ul>
        </div>
      )}

      {tab === "Domains" && (
        <div className="card p-5">
          <ul className="space-y-2">
            {evidence
              .filter((e) => e.source === "domain_intelligence")
              .map((e) => (
                <li key={e.evidence_id} className="flex items-start gap-2 text-sm">
                  <SeverityBadge severity={e.severity} />
                  <span className="text-slate-300">{e.description}</span>
                </li>
              ))}
            {evOfType(evidence, "DOMAIN_AGE").length === 0 && (
              <li className="text-sm text-slate-500">No domains were analyzed.</li>
            )}
          </ul>
        </div>
      )}

      {tab === "URLs" && (
        <div className="space-y-4">
          {result.urls.length === 0 && <p className="text-sm text-slate-500">No URLs were supplied or found.</p>}
          {result.urls.map((url) => (
            <div key={url} className="card p-5">
              <div className="font-mono text-sm text-soc-accent break-all mb-2">{url}</div>
              <ul className="space-y-1">
                {evidence
                  .filter((e) => e.entity_refs.includes(`url:${url}`) || (e.source === "url_intelligence" && JSON.stringify(e.value).includes(url)))
                  .map((e) => (
                    <li key={e.evidence_id} className="text-sm text-slate-300 flex gap-2 items-start">
                      <SeverityBadge severity={e.severity} /> {e.description}
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </div>
      )}

      {tab === "Attachments" && (
        <div className="space-y-4">
          {result.attachments.length === 0 && <p className="text-sm text-slate-500">No attachments were supplied.</p>}
          {result.attachments.map((att) => (
            <div key={att.filename} className="card p-5">
              <div className="text-sm text-white font-medium mb-2">{att.filename}</div>
              <ul className="space-y-1">
                {evidence
                  .filter((e) => e.entity_refs.includes(`attachment:${att.filename}`) || e.source === "attachment_intelligence")
                  .map((e) => (
                    <li key={e.evidence_id} className="text-sm text-slate-300 flex gap-2 items-start">
                      <SeverityBadge severity={e.severity} /> {e.description}
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </div>
      )}

      {tab === "NLP" && (
        <div className="card p-5 space-y-3">
          <div className="text-xs text-fuchsia-300 bg-fuchsia-950/30 border border-fuchsia-800 rounded-lg p-3 inline-block">
            LLM-derived / inferred evidence — advisory only, never the final verdict.
          </div>
          <ul className="space-y-2">
            {evidence
              .filter((e) => e.source === "content_nlp")
              .map((e) => (
                <li key={e.evidence_id} className="flex items-center gap-2 text-sm">
                  <SeverityBadge severity={e.severity} />
                  <span className="text-slate-300">{e.description}</span>
                </li>
              ))}
          </ul>
        </div>
      )}

      {tab === "Evidence" && <EvidenceTable evidence={evidence} />}

      {tab === "Proof Chain" && (
        <div className="card p-5">
          <ProofChainView steps={result.proof_chain} />
        </div>
      )}

      {tab === "Entity Graph" && (
        <EntityGraphView
          graph={result.entity_graph}
          evidence={evidence}
          subject={result.headers.subject}
          date={result.headers.date}
        />
      )}

      {tab === "Campaigns" && (
        <div className="card p-5">
          {result.campaign_relationships.length === 0 ? (
            <p className="text-sm text-slate-500">
              No shared infrastructure found against previously analyzed emails in this session.
            </p>
          ) : (
            <ul className="space-y-2">
              {result.campaign_relationships.map((c, i) => (
                <li key={i} className="text-sm text-slate-300">
                  <span className="text-soc-accent font-mono text-xs mr-2">{c.shared_indicator_type}</span>
                  {c.note}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {tab === "Limitations" && (
        <div className="card p-5">
          <h3 className="font-semibold text-white mb-3">What We Cannot Know</h3>
          <ul className="space-y-2 list-disc list-inside">
            {result.limitations.map((l, i) => (
              <li key={i} className="text-sm text-slate-300">{l}</li>
            ))}
          </ul>
        </div>
      )}
      </div>
    </div>
  );
}
