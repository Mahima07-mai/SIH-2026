import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import InputForm from "./components/InputForm";
import AnalysisProgress from "./components/AnalysisProgress";
import Dashboard from "./components/Dashboard";
import { analyzeEmail, type AnalyzeRequestBody } from "./services/api";
import type { AnalysisResult } from "./types";

type Stage = "input" | "analyzing" | "result" | "error";

export default function App() {
  const [stage, setStage] = useState<Stage>("input");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (payload: AnalyzeRequestBody) => {
    setStage("analyzing");
    setError(null);
    try {
      const res = await analyzeEmail(payload);
      // Give the progress animation a moment to feel complete before switching.
      setResult(res);
      setTimeout(() => setStage("result"), 400);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setStage("error");
    }
  };

  const reset = () => {
    setResult(null);
    setError(null);
    setStage("input");
  };

  return (
    <div className="min-h-screen console-field">
      <div className="border-b border-soc-border/80 bg-soc-bg/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-6xl mx-auto px-6 py-3 flex items-center gap-2">
          <ShieldAlert size={18} className="text-soc-accent" />
          <span className="text-sm font-semibold text-white">Email Threat Analysis</span>
          <span className="text-[11px] text-slate-500 border border-soc-border rounded-full px-2 py-0.5 ml-1">
            SOC Prototype
          </span>
        </div>
      </div>

      <div className="px-6 py-10">
        {stage === "input" && <InputForm onAnalyze={handleAnalyze} />}
        {stage === "analyzing" && <AnalysisProgress done={false} />}
        {stage === "error" && (
          <div className="max-w-xl mx-auto card-rail" style={{ ["--rail-color" as string]: "#ef4444" }}>
            <h2 className="text-red-400 font-semibold mb-2">Analysis failed</h2>
            <p className="text-sm text-slate-300 mb-4">{error}</p>
            <p className="text-xs text-slate-500 mb-4">
              Make sure the FastAPI backend is running at the URL configured in vite.config.ts
              (default: http://localhost:8000).
            </p>
            <button onClick={reset} className="text-sm bg-soc-accent text-black px-4 py-2 rounded-lg font-semibold">
              Try again
            </button>
          </div>
        )}
        {stage === "result" && result && <Dashboard result={result} onReset={reset} />}
      </div>
    </div>
  );
}
