import { ArrowDown } from "lucide-react";
import type { ProofChainStep } from "../types";
import { FactLevelBadge } from "./Badges";

export default function ProofChainView({ steps }: { steps: ProofChainStep[] }) {
  if (steps.length === 0) {
    return <p className="text-sm text-slate-500">No rules fired — no proof chain to display.</p>;
  }

  return (
    <div className="flex flex-col items-start gap-1">
      {steps.map((step, i) => {
        const isLast = i === steps.length - 1;
        return (
          <div key={step.step} className="w-full">
            <div
              className={`card !p-4 flex items-start justify-between gap-4 ${
                isLast ? "border-soc-accent/60 bg-amber-950/10" : ""
              }`}
            >
              <div className="flex gap-3">
                <span className="text-slate-500 text-sm font-mono pt-0.5">{step.step}.</span>
                <p className="text-sm text-slate-200">{step.label}</p>
              </div>
              <FactLevelBadge factLevel={step.fact_level} />
            </div>
            {!isLast && (
              <div className="flex justify-center py-1">
                <ArrowDown size={16} className="text-slate-600" />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
