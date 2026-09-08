import { useEffect, useState } from "react";
import { CheckCircle2, Loader2 } from "lucide-react";

const STEPS = [
  "Ingestion",
  "Header analysis",
  "Authentication analysis",
  "Infrastructure analysis",
  "Domain analysis",
  "URL analysis",
  "Attachment analysis",
  "NLP analysis",
  "Evidence normalization",
  "Correlation",
  "Threat classification",
  "Graph construction",
  "Report generation",
];

/** Purely a visual progress simulation — the real work happens in one
 * request/response on the backend. Steps advance on a timer and the last
 * step waits for `done` to actually become true. */
export default function AnalysisProgress({ done }: { done: boolean }) {
  const [activeStep, setActiveStep] = useState(0);

  useEffect(() => {
    if (done) {
      setActiveStep(STEPS.length);
      return;
    }
    const interval = setInterval(() => {
      setActiveStep((s) => (s < STEPS.length - 1 ? s + 1 : s));
    }, 220);
    return () => clearInterval(interval);
  }, [done]);

  return (
    <div className="max-w-xl mx-auto card">
      <h2 className="text-white font-semibold mb-4">Running analysis pipeline…</h2>
      <ul className="space-y-2">
        {STEPS.map((step, i) => {
          const completed = i < activeStep || (done && i <= activeStep);
          const active = i === activeStep && !done;
          return (
            <li key={step} className="flex items-center gap-3 text-sm">
              {completed ? (
                <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
              ) : active ? (
                <Loader2 size={16} className="text-soc-accent shrink-0 animate-spin" />
              ) : (
                <div className="w-4 h-4 rounded-full border border-soc-border shrink-0" />
              )}
              <span className={completed ? "text-slate-300" : active ? "text-white" : "text-slate-600"}>
                {step}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
