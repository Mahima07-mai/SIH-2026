import { useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Handle,
  Position,
  type Edge,
  type Node,
  type NodeProps,
  MarkerType,
} from "reactflow";
import "reactflow/dist/style.css";
import {
  AlertTriangle,
  AtSign,
  FileText,
  Globe,
  Info,
  Link2,
  Mail,
  Paperclip,
  Server,
  ShieldCheck,
  User,
  type LucideIcon,
} from "lucide-react";
import { SeverityBadge } from "./Badges";
import type { EntityGraph, Evidence, GraphNode as EntityNode } from "../types";

/* ------------------------------------------------------------------ */
/* Type -> display metadata                                            */
/* ------------------------------------------------------------------ */

const TYPE_META: Record<
  string,
  { label: string; icon: LucideIcon; color: string; plural: boolean }
> = {
  SENDER: { label: "Sender", icon: User, color: "#fbbf24", plural: false },
  REPLY_TO: { label: "Reply-To", icon: AtSign, color: "#a78bfa", plural: false },
  IP: { label: "Mail Server / IP", icon: Server, color: "#2dd4bf", plural: false },
  DOMAIN: { label: "Domains", icon: Globe, color: "#fb923c", plural: true },
  URL: { label: "URLs", icon: Link2, color: "#f87171", plural: true },
  ATTACHMENT: { label: "Attachments", icon: Paperclip, color: "#60a5fa", plural: true },
  CONTENT: { label: "Content", icon: FileText, color: "#34d399", plural: false },
  AUTHENTICATION: { label: "Authentication", icon: ShieldCheck, color: "#34d399", plural: false },
};

// How each cluster's link back to EMAIL is categorized — drives the edge's
// color/style, which the legend explains. "Direct" = asserted straight from
// the email's own headers. "Contains" = the email is composed of this part.
// "Related" = derived by following a hop away from the email itself.
const EDGE_CATEGORY: Record<string, "direct" | "contains" | "related"> = {
  SENDER: "direct",
  REPLY_TO: "direct",
  IP: "direct",
  AUTHENTICATION: "direct",
  URL: "contains",
  ATTACHMENT: "contains",
  CONTENT: "contains",
  DOMAIN: "related",
};

const EDGE_STYLE: Record<string, { stroke: string; dash?: string; label: string }> = {
  direct: { stroke: "#60a5fa", label: "Direct Evidence" },
  contains: { stroke: "#34d399", label: "Contains" },
  related: { stroke: "#94a3b8", dash: "6 4", label: "Related To" },
  redirects: { stroke: "#f87171", dash: "4 3", label: "Redirects To" },
};

// Fixed compass slots so the layout always resolves the same way the
// reference design does: sender top-left, mail server top, domains
// top-right, URLs right, content bottom-right, attachments bottom,
// authentication bottom-left, reply-to left.
const ANGLE_DEG: Record<string, number> = {
  IP: 270,
  SENDER: 225,
  DOMAIN: 315,
  URL: 0,
  CONTENT: 45,
  ATTACHMENT: 90,
  AUTHENTICATION: 135,
  REPLY_TO: 180,
};

const RADIUS = 260;
const CENTER = { x: 480, y: 320 };

interface ClusterItem {
  id: string;
  label: string;
  details: string[];
}

interface Cluster {
  type: string;
  items: ClusterItem[];
  evidenceIds: string[];
  summary?: Record<string, string>;
}

function severityOf(evidence: Evidence[], ids: string[]): Evidence["severity"] | null {
  const order: Evidence["severity"][] = ["Critical", "High", "Medium", "Low", "Info"];
  const linked = evidence.filter((e) => ids.includes(e.evidence_id));
  for (const s of order) {
    if (linked.some((e) => e.severity === s)) return s;
  }
  return null;
}

function buildClusters(graph: EntityGraph, evidence: Evidence[]): Cluster[] {
  // Fold HASH nodes into their parent ATTACHMENT's item details instead of
  // giving them their own slot on the wheel.
  const hashLabels = new Map<string, string[]>(); // attachment node id -> hash labels
  graph.edges.forEach((e) => {
    const source = graph.nodes.find((n) => n.id === e.source);
    const target = graph.nodes.find((n) => n.id === e.target);
    if (source?.type === "ATTACHMENT" && target?.type === "HASH") {
      const list = hashLabels.get(source.id) ?? [];
      list.push(`SHA256: ${target.label}`);
      hashLabels.set(source.id, list);
    }
  });

  const byType = new Map<string, EntityNode[]>();
  graph.nodes
    .filter((n) => n.type !== "EMAIL" && n.type !== "HASH")
    .forEach((n) => {
      const list = byType.get(n.type) ?? [];
      list.push(n);
      byType.set(n.type, list);
    });

  const clusters: Cluster[] = [];
  byType.forEach((nodes, type) => {
    const items: ClusterItem[] = nodes.map((n) => {
      const linked = evidence.filter((e) => n.data.evidence_ids.includes(e.evidence_id));
      const priority: Evidence["severity"][] = ["Critical", "High", "Medium", "Low", "Info"];
      const sorted = [...linked].sort(
        (a, b) => priority.indexOf(a.severity) - priority.indexOf(b.severity)
      );
      const details = sorted.slice(0, 2).map((e) => e.description);
      const extraHash = hashLabels.get(n.id) ?? [];
      return { id: n.id, label: n.label, details: [...details, ...extraHash].slice(0, 2) };
    });
    const evidenceIds = Array.from(new Set(nodes.flatMap((n) => n.data.evidence_ids)));
    const summary = nodes.find((n) => n.data.summary)?.data.summary;
    clusters.push({ type, items, evidenceIds, summary });
  });

  return clusters;
}

/* ------------------------------------------------------------------ */
/* Custom nodes                                                        */
/* ------------------------------------------------------------------ */

function WarningBadge() {
  return (
    <div className="absolute -top-1.5 -right-1.5 bg-soc-bg rounded-full">
      <AlertTriangle size={16} className="text-red-400 fill-red-950" />
    </div>
  );
}

function EmailNode({ data }: NodeProps) {
  return (
    <div className="flex flex-col items-center gap-1.5 w-[210px]">
      <Handle type="source" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div
        className="w-20 h-20 rounded-full flex items-center justify-center border-4 shadow-lg"
        style={{ background: "#0b2540", borderColor: "#3b82f6" }}
      >
        <Mail size={30} color="#60a5fa" />
      </div>
      <div className="text-center">
        <div className="text-white font-bold text-sm tracking-wide">EMAIL</div>
        {data.subject && (
          <div className="text-[11px] text-slate-400 max-w-[220px] break-words">
            Subject: {data.subject}
          </div>
        )}
        {data.date && <div className="text-[10px] text-slate-500">{data.date}</div>}
      </div>
    </div>
  );
}

function ClusterNodeComp({ data }: NodeProps) {
  const meta = TYPE_META[data.type] ?? {
    label: data.type,
    icon: Info,
    color: "#94a3b8",
    plural: false,
  };
  const Icon = meta.icon;
  const count = data.cluster.items.length as number;
  const title = meta.plural ? `${meta.label.toUpperCase()} (${count})` : meta.label.toUpperCase();

  return (
    <div className="flex items-start gap-2.5 w-[230px]">
      <Handle type="source" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="relative shrink-0">
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center border-2"
          style={{ background: "#0f1622", borderColor: meta.color }}
        >
          <Icon size={20} color={meta.color} />
        </div>
        {data.hasWarning && <WarningBadge />}
      </div>
      <div className="pt-0.5 min-w-0">
        <div className="text-xs font-bold tracking-wide" style={{ color: meta.color }}>
          {title}
        </div>
        {data.cluster.summary ? (
          <div className="space-y-0.5 mt-0.5">
            {Object.entries(data.cluster.summary as Record<string, string>).map(([k, v]) => {
              const bad = /FAIL|SOFTFAIL|PERMERROR|NONE/i.test(v);
              return (
                <div key={k} className="text-[11px] text-slate-300">
                  {k}: <span className={bad ? "text-red-400 font-semibold" : "text-emerald-400 font-semibold"}>{v}</span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="space-y-0.5 mt-0.5">
            {data.cluster.items.slice(0, 2).map((it: ClusterItem) => (
              <div key={it.id} className="text-[11px] text-slate-300 break-all leading-tight">
                {it.label.length > 34 ? it.label.slice(0, 31) + "…" : it.label}
              </div>
            ))}
            {count > 2 && <div className="text-[10px] text-slate-500">+{count - 2} more</div>}
          </div>
        )}
        {data.redirectCount > 0 && (
          <div className="text-[10px] text-red-400 mt-0.5">→ Redirects ({data.redirectCount})</div>
        )}
      </div>
    </div>
  );
}

const nodeTypes = { emailNode: EmailNode, clusterNode: ClusterNodeComp };

/* ------------------------------------------------------------------ */
/* Layout                                                               */
/* ------------------------------------------------------------------ */

function buildGraphElements(
  clusters: Cluster[],
  evidence: Evidence[],
  subject?: string | null,
  date?: string | null
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [
    {
      id: "__email__",
      type: "emailNode",
      position: { x: CENTER.x - 105, y: CENTER.y - 55 },
      data: { subject, date },
      draggable: false,
    },
  ];
  const edges: Edge[] = [];

  const redirectCount = evidence.filter(
    (e) => e.type === "REDIRECT_CHAIN" && typeof e.value === "object" && (e.value as any)?.redirect_count > 0
  ).length;

  // Any cluster types not in the fixed compass map get spread into the
  // remaining gaps so the graph still renders sensibly for future entity
  // types without needing a code change here.
  const usedAngles = new Set(clusters.map((c) => ANGLE_DEG[c.type]).filter((a) => a !== undefined));
  let fallbackAngle = 22.5;
  const angleFor = (type: string) => {
    if (ANGLE_DEG[type] !== undefined) return ANGLE_DEG[type];
    while (usedAngles.has(fallbackAngle)) fallbackAngle += 45;
    usedAngles.add(fallbackAngle);
    return fallbackAngle;
  };

  clusters.forEach((cluster) => {
    const angle = (angleFor(cluster.type) * Math.PI) / 180;
    const x = CENTER.x + RADIUS * Math.cos(angle) - 24;
    const y = CENTER.y + RADIUS * Math.sin(angle) - 24;
    const severity = severityOf(evidence, cluster.evidenceIds);
    const hasWarning = severity === "High" || severity === "Critical";
    const nodeId = `cluster:${cluster.type}`;

    nodes.push({
      id: nodeId,
      type: "clusterNode",
      position: { x, y },
      data: {
        type: cluster.type,
        cluster,
        hasWarning,
        redirectCount: cluster.type === "URL" ? redirectCount : 0,
      },
      draggable: false,
    });

    const category = EDGE_CATEGORY[cluster.type] ?? "related";
    const style = EDGE_STYLE[category];
    edges.push({
      id: `e-${nodeId}`,
      source: "__email__",
      target: nodeId,
      style: { stroke: style.stroke, strokeWidth: 2, strokeDasharray: style.dash },
      markerEnd: { type: MarkerType.ArrowClosed, color: style.stroke, width: 16, height: 16 },
    });
  });

  return { nodes, edges };
}

/* ------------------------------------------------------------------ */
/* Main component                                                       */
/* ------------------------------------------------------------------ */

interface Props {
  graph: EntityGraph;
  evidence: Evidence[];
  subject?: string | null;
  date?: string | null;
}

export default function EntityGraphView({ graph, evidence, subject, date }: Props) {
  const clusters = useMemo(() => buildClusters(graph, evidence), [graph, evidence]);
  const { nodes, edges } = useMemo(
    () => buildGraphElements(clusters, evidence, subject, date),
    [clusters, evidence, subject, date]
  );
  const [selected, setSelected] = useState<Cluster | null>(null);
  const [showLegend, setShowLegend] = useState(true);

  const selectedEvidence = selected
    ? evidence.filter((e) => selected.evidenceIds.includes(e.evidence_id))
    : [];

  return (
    <div className="flex gap-4 h-[600px]">
      <div className="flex-1 border border-soc-border rounded-xl overflow-hidden bg-black/20 relative">
        <div className="absolute top-3 left-4 z-10 flex items-center gap-1.5 text-xs font-semibold text-white tracking-wide">
          EVIDENCE GRAPH
          <span title="Click any node to see its underlying evidence.">
            <Info size={13} className="text-slate-500" />
          </span>
        </div>
        <button
          onClick={() => setShowLegend((v) => !v)}
          className="absolute top-3 right-4 z-10 flex items-center gap-2 text-xs bg-soc-panel border border-soc-border rounded-full px-3 py-1.5"
        >
          Legend
          <span
            className={`w-8 h-4 rounded-full relative transition-colors ${
              showLegend ? "bg-soc-accent" : "bg-slate-700"
            }`}
          >
            <span
              className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${
                showLegend ? "translate-x-4" : "translate-x-0.5"
              }`}
            />
          </span>
        </button>

        {showLegend && (
          <div className="absolute bottom-3 left-4 z-10 flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] text-slate-400 bg-black/40 rounded-lg px-3 py-2 backdrop-blur-sm">
            {(["direct", "related", "contains", "redirects"] as const).map((key) => {
              const s = EDGE_STYLE[key];
              return (
                <div key={key} className="flex items-center gap-1.5">
                  <svg width="20" height="6">
                    <line
                      x1="0"
                      y1="3"
                      x2="20"
                      y2="3"
                      stroke={s.stroke}
                      strokeWidth="2"
                      strokeDasharray={s.dash}
                    />
                  </svg>
                  {s.label}
                </div>
              );
            })}
          </div>
        )}

        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => {
            if (node.id === "__email__") return setSelected(null);
            const cluster = clusters.find((c) => `cluster:${c.type}` === node.id) ?? null;
            setSelected(cluster);
          }}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          nodesDraggable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#232833" gap={16} />
        </ReactFlow>
      </div>

      <div className="w-80 shrink-0 card overflow-y-auto">
        <h3 className="font-semibold text-white text-sm mb-2">Node details</h3>
        {!selected && (
          <p className="text-xs text-slate-500">Click a node to see its evidence and relationships.</p>
        )}
        {selected && (
          <div className="space-y-3">
            <div>
              <div className="text-xs text-slate-500">Type</div>
              <div className="text-sm text-slate-200">{TYPE_META[selected.type]?.label ?? selected.type}</div>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Entities ({selected.items.length})</div>
              <ul className="space-y-1">
                {selected.items.map((it) => (
                  <li key={it.id} className="text-xs text-slate-300 break-all bg-black/20 rounded px-2 py-1">
                    {it.label}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Related evidence ({selectedEvidence.length})</div>
              <ul className="space-y-2">
                {selectedEvidence.map((e) => (
                  <li key={e.evidence_id} className="text-xs bg-black/30 border border-soc-border rounded-lg p-2 space-y-1">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={e.severity} />
                      <span className="font-mono text-slate-500">{e.type}</span>
                    </div>
                    <div className="text-slate-300">{e.description}</div>
                  </li>
                ))}
                {selectedEvidence.length === 0 && (
                  <li className="text-xs text-slate-600">No directly linked evidence.</li>
                )}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
