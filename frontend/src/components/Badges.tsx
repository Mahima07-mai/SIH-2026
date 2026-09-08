import { useState } from "react";
import clsx from "clsx";
import { Info } from "lucide-react";
import type { FactLevel, Reliability, Severity } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    Info: "bg-slate-700/50 text-slate-300 border-slate-600",
    Low: "bg-sky-900/40 text-sky-300 border-sky-700",
    Medium: "bg-amber-900/40 text-amber-300 border-amber-700",
    High: "bg-orange-900/40 text-orange-300 border-orange-700",
    Critical: "bg-red-900/40 text-red-300 border-red-700",
  };
  return <span className={clsx("badge border", styles[severity])}>{severity}</span>;
}

export function ReliabilityBadge({ reliability }: { reliability: Reliability }) {
  const styles: Record<Reliability, string> = {
    High: "bg-emerald-900/40 text-emerald-300 border-emerald-700",
    Medium: "bg-amber-900/40 text-amber-300 border-amber-700",
    Low: "bg-slate-700/50 text-slate-300 border-slate-600",
  };
  return <span className={clsx("badge border", styles[reliability])}>{reliability}</span>;
}

export function FactLevelBadge({ factLevel }: { factLevel: FactLevel | null }) {
  if (!factLevel) return null;
  const styles: Record<FactLevel, string> = {
    Observed: "bg-cyan-900/40 text-cyan-300 border-cyan-700",
    Derived: "bg-violet-900/40 text-violet-300 border-violet-700",
    Inferred: "bg-fuchsia-900/40 text-fuchsia-300 border-fuchsia-700",
  };
  return <span className={clsx("badge border", styles[factLevel])}>{factLevel}</span>;
}

export function CategoryBadge({ category }: { category: string }) {
  const styles: Record<string, string> = {
    PHISHING: "bg-red-900/50 text-red-300 border-red-700",
    BEC: "bg-orange-900/50 text-orange-300 border-orange-700",
    MALWARE: "bg-red-900/60 text-red-200 border-red-600",
    SPOOFING: "bg-amber-900/50 text-amber-300 border-amber-700",
    SCAM: "bg-orange-900/40 text-orange-300 border-orange-700",
    SPAM: "bg-slate-700/50 text-slate-300 border-slate-600",
    BENIGN: "bg-emerald-900/50 text-emerald-300 border-emerald-700",
  };
  return (
    <span className={clsx("badge border text-sm px-3 py-1", styles[category] ?? styles.SPAM)}>
      {category}
    </span>
  );
}

/**
 * Mirrors backend `confidence_for_score()` (app/correlation/scoring.py) exactly.
 * Confidence is NOT the same axis as risk: risk_score says how dangerous the
 * email looks, confidence says how much corroborating evidence backs that
 * read. A short, urgent email with almost no headers can score High risk
 * but Low confidence — there just isn't much to corroborate it with yet.
 */
function confidenceThresholds(riskScore: number, evidenceCount: number) {
  const meetsHigh = riskScore >= 70 && evidenceCount >= 5;
  const meetsMedium = riskScore >= 40 || evidenceCount >= 3;
  const computed = meetsHigh ? "HIGH" : meetsMedium ? "MEDIUM" : "LOW";
  return { meetsHigh, meetsMedium, computed };
}

const CONFIDENCE_STYLES: Record<string, string> = {
  HIGH: "bg-emerald-900/40 text-emerald-300 border-emerald-700",
  MEDIUM: "bg-amber-900/40 text-amber-300 border-amber-700",
  LOW: "bg-slate-700/50 text-slate-300 border-slate-600",
};

export function ConfidenceBadge({
  confidence,
  riskScore,
  evidenceCount,
}: {
  confidence: string;
  riskScore: number;
  evidenceCount: number;
}) {
  const [open, setOpen] = useState(false);
  const level = confidence.toUpperCase();
  const { meetsHigh, meetsMedium } = confidenceThresholds(riskScore, evidenceCount);

  const rows: { label: string; rule: string; met: boolean }[] = [
    { label: "High", rule: "risk score ≥ 70 AND ≥ 5 pieces of evidence", met: meetsHigh },
    { label: "Medium", rule: "risk score ≥ 40 OR ≥ 3 pieces of evidence", met: !meetsHigh && meetsMedium },
    { label: "Low", rule: "below both of the above", met: !meetsHigh && !meetsMedium },
  ];

  return (
    <span className="relative inline-flex items-center gap-1.5">
      <span className={clsx("badge border", CONFIDENCE_STYLES[level] ?? CONFIDENCE_STYLES.LOW)}>
        {confidence}
      </span>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        onBlur={() => setOpen(false)}
        aria-label="What does confidence mean?"
        className="text-slate-500 hover:text-slate-300"
      >
        <Info size={14} />
      </button>
      {open && (
        <div className="absolute z-20 top-full left-0 mt-2 w-72 card p-3 text-left shadow-2xl">
          <p className="text-xs text-slate-400 mb-2">
            Confidence measures how much corroborating evidence backs this verdict — it is
            separate from the risk score, which measures how dangerous the email looks.
          </p>
          <div className="space-y-1.5">
            {rows.map((r) => (
              <div
                key={r.label}
                className={clsx(
                  "text-xs rounded-lg px-2 py-1.5 border flex items-start gap-2",
                  r.met ? CONFIDENCE_STYLES[r.label.toUpperCase()] : "bg-transparent border-soc-border text-slate-500"
                )}
              >
                <span className="font-semibold w-14 shrink-0">{r.label}</span>
                <span>{r.rule}</span>
              </div>
            ))}
          </div>
          <p className="text-[11px] text-slate-500 mt-2">
            This email: risk score {riskScore}/100, {evidenceCount} evidence item{evidenceCount === 1 ? "" : "s"} →{" "}
            <span className="text-slate-300 font-medium">{confidence}</span>.
          </p>
        </div>
      )}
    </span>
  );
}

export function RiskGauge({ score }: { score: number }) {
  const color = score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : "#22c55e";
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;
  return (
    <div className="relative w-32 h-32">
      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#232833" strokeWidth="10" />
        <circle
          cx="60"
          cy="60"
          r="54"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs text-slate-400">/ 100</span>
      </div>
    </div>
  );
}
