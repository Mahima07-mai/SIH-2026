import type { AnalysisResult, AttachmentDraft } from "../types";

const BASE = "/api";

export interface AnalyzeRequestBody {
  headers: {
    from_address?: string;
    to?: string;
    cc?: string;
    reply_to?: string;
    return_path?: string;
    sender?: string;
    subject?: string;
    message_id?: string;
    date?: string;
    received?: string;
    authentication_results?: string;
    dkim_signature?: string;
    arc_headers?: string;
    other_headers?: string;
    raw_headers?: string;
  };
  body: { plain_text?: string; html?: string };
  urls: string[];
  attachments: AttachmentDraft[];
  label?: string;
}

export async function analyzeEmail(payload: AnalyzeRequestBody): Promise<AnalysisResult> {
  const res = await fetch(`${BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Analysis failed (${res.status}): ${detail}`);
  }
  return res.json();
}

export async function fetchEmail(emailId: string): Promise<AnalysisResult> {
  const res = await fetch(`${BASE}/emails/${emailId}`);
  if (!res.ok) throw new Error("Failed to fetch email");
  return res.json();
}

export function pdfReportUrl(emailId: string): string {
  return `${BASE}/reports/${emailId}/pdf`;
}

export async function downloadPdfReport(emailId: string): Promise<void> {
  const res = await fetch(pdfReportUrl(emailId), { method: "POST" });
  if (!res.ok) throw new Error("Failed to generate PDF report");
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${emailId}_forensic_report.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      resolve(result.split(",")[1] ?? "");
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}
