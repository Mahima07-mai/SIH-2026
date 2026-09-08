import { useMemo, useState } from "react";
import type { Evidence } from "../types";
import { FactLevelBadge, ReliabilityBadge, SeverityBadge } from "./Badges";

type Filter = "All" | "Observed" | "Derived" | "Inferred" | "High reliability" | "Medium reliability" | "Low reliability";

const FILTERS: Filter[] = ["All", "Observed", "Derived", "Inferred", "High reliability", "Medium reliability", "Low reliability"];

export default function EvidenceTable({ evidence }: { evidence: Evidence[] }) {
  const [filter, setFilter] = useState<Filter>("All");

  const filtered = useMemo(() => {
    if (filter === "All") return evidence;
    if (filter.endsWith("reliability")) {
      const level = filter.split(" ")[0];
      return evidence.filter((e) => e.reliability === level);
    }
    return evidence.filter((e) => e.fact_level === filter);
  }, [evidence, filter]);

  return (
    <div>
      <div className="flex flex-wrap gap-2 mb-4">
        {FILTERS.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
              filter === f
                ? "bg-soc-accent text-black border-soc-accent"
                : "border-soc-border text-slate-400 hover:border-slate-500"
            }`}
          >
            {f} {f !== "All" ? `(${evidence.filter((e) => (f.endsWith("reliability") ? e.reliability === f.split(" ")[0] : e.fact_level === f)).length})` : `(${evidence.length})`}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto rounded-xl border border-soc-border">
        <table className="w-full text-sm">
          <thead className="bg-black/40 text-slate-400 text-xs uppercase">
            <tr>
              <th className="text-left px-3 py-2">Type</th>
              <th className="text-left px-3 py-2">Value</th>
              <th className="text-left px-3 py-2">Source</th>
              <th className="text-left px-3 py-2">Reliability</th>
              <th className="text-left px-3 py-2">Fact Level</th>
              <th className="text-left px-3 py-2">Severity</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => (
              <tr key={e.evidence_id} className="border-t border-soc-border/60 hover:bg-white/5">
                <td className="px-3 py-2 font-mono text-xs text-slate-300">{e.type}</td>
                <td className="px-3 py-2 text-slate-300 max-w-xs truncate" title={String(e.value)}>
                  {typeof e.value === "object" ? JSON.stringify(e.value) : String(e.value)}
                </td>
                <td className="px-3 py-2 text-slate-500 text-xs">{e.source}</td>
                <td className="px-3 py-2"><ReliabilityBadge reliability={e.reliability} /></td>
                <td className="px-3 py-2"><FactLevelBadge factLevel={e.fact_level} /></td>
                <td className="px-3 py-2"><SeverityBadge severity={e.severity} /></td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-slate-600 text-sm">
                  No evidence matches this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
