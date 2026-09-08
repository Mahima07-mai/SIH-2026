import { useState, useCallback } from "react";
import {
  Upload,
  Zap,
  FileText,
  X,
  ClipboardPaste,
  CheckCircle2,
  AlertCircle,
  User,
  Link2,
  Paperclip,
  Loader2,
} from "lucide-react";
import { DEMO_EMAILS } from "../data/demoEmails";
import { fileToBase64, type AnalyzeRequestBody } from "../services/api";
import { parseEmlSource } from "../services/emlParser";
import type { AttachmentDraft } from "../types";

interface Props {
  onAnalyze: (payload: AnalyzeRequestBody) => void;
}

const emptyHeaders: AnalyzeRequestBody["headers"] = {
  from_address: "",
  to: "",
  cc: "",
  reply_to: "",
  return_path: "",
  sender: "",
  subject: "",
  message_id: "",
  date: "",
  received: "",
  authentication_results: "",
  dkim_signature: "",
  arc_headers: "",
  other_headers: "",
  raw_headers: "",
};

type ImportStatus = { type: "idle" | "success" | "error"; message?: string };

export default function InputForm({ onAnalyze }: Props) {
  const [headers, setHeaders] = useState(emptyHeaders);
  const [plainText, setPlainText] = useState("");
  const [html, setHtml] = useState("");
  const [urlText, setUrlText] = useState("");
  const [attachments, setAttachments] = useState<AttachmentDraft[]>([]);
  const [useRaw, setUseRaw] = useState(false);

  const [emlSource, setEmlSource] = useState("");
  const [parsing, setParsing] = useState(false);
  const [importStatus, setImportStatus] = useState<ImportStatus>({ type: "idle" });

  const updateHeader = (key: keyof typeof headers) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => setHeaders((h) => ({ ...h, [key]: e.target.value }));

  const handleFiles = useCallback(async (fileList: FileList | null) => {
    if (!fileList) return;
    const drafts: AttachmentDraft[] = [];
    for (const file of Array.from(fileList)) {
      const content_base64 = await fileToBase64(file);
      drafts.push({
        filename: file.name,
        mime_type: file.type || "application/octet-stream",
        size: file.size,
        content_base64,
      });
    }
    setAttachments((prev) => [...prev, ...drafts]);
  }, []);

  const loadDemo = (key: string) => {
    const demo = DEMO_EMAILS.find((d) => d.key === key);
    if (!demo) return;
    setHeaders({ ...emptyHeaders, ...demo.payload.headers });
    setPlainText(demo.payload.body.plain_text ?? "");
    setHtml(demo.payload.body.html ?? "");
    setUrlText(demo.payload.urls.join("\n"));
    setAttachments(demo.payload.attachments);
    setImportStatus({ type: "success", message: `Loaded demo: ${demo.label}` });
  };

  // Parses pasted .eml source entirely client-side and fills the same form
  // state manual entry uses, so testers never have to hand-attach a raw
  // .eml file for it to be treated as an opaque attachment.
  const handleParseEml = async () => {
    if (!emlSource.trim()) return;
    setParsing(true);
    setImportStatus({ type: "idle" });
    try {
      const parsed = await parseEmlSource(emlSource);
      setHeaders({ ...emptyHeaders, ...parsed.headers });
      setPlainText(parsed.plainText);
      setHtml(parsed.html);
      setUrlText(parsed.urls.join("\n"));
      setAttachments(parsed.attachments);
      setUseRaw(false);
      setImportStatus({ type: "success", message: `Parsed "${parsed.subject}" from ${parsed.from}` });
    } catch (e) {
      setImportStatus({
        type: "error",
        message: e instanceof Error ? e.message : "Could not parse this as a .eml source.",
      });
    } finally {
      setParsing(false);
    }
  };

  const submit = () => {
    const urls = urlText.split("\n").map((u) => u.trim()).filter(Boolean);
    onAnalyze({
      headers: useRaw ? { raw_headers: headers.raw_headers } : headers,
      body: { plain_text: plainText, html },
      urls,
      attachments,
    });
  };

  const urlCount = urlText.split("\n").map((u) => u.trim()).filter(Boolean).length;
  const headerFilled = Object.values(headers).some((v) => v && v.trim());

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-28">
      <header>
        <h1 className="text-2xl font-bold text-white">Email Threat Analysis</h1>
        <p className="text-slate-400 text-sm mt-1 max-w-2xl">
          Manually provide email headers, body, URLs, and attachments — this simulates what a
          future .EML parser would supply.
        </p>
      </header>

      {/* QUICK IMPORT */}
      <section className="card-rail" style={{ ["--rail-color" as string]: "#f0a43a" }}>
        <div className="flex items-center gap-2 mb-1">
          <ClipboardPaste size={16} className="text-soc-accent" />
          <h2 className="font-semibold text-white">Quick import</h2>
        </div>
        <p className="text-xs text-slate-400 mb-3 max-w-2xl">
          Paste the raw contents of an .eml file below — headers, body, and attachments are
          parsed in your browser and used to fill in every section on this page.
        </p>
        <textarea
          className="field-input h-32 font-mono text-xs resize-y"
          placeholder={"Delivered-To: ...\nFrom: ...\nSubject: ...\n\n(paste full .eml source, including headers)"}
          value={emlSource}
          onChange={(e) => setEmlSource(e.target.value)}
        />
        <div className="flex flex-wrap items-center gap-3 mt-3">
          <button
            onClick={handleParseEml}
            disabled={parsing || !emlSource.trim()}
            className="flex items-center gap-2 text-sm bg-soc-accent text-black font-semibold px-4 py-2 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition-all"
          >
            {parsing ? <Loader2 size={15} className="animate-spin" /> : <ClipboardPaste size={15} />}
            {parsing ? "Parsing…" : "Parse & fill form"}
          </button>

          <span className="text-xs text-slate-600">or load a sample —</span>
          <div className="flex flex-wrap gap-2">
            {DEMO_EMAILS.map((d) => (
              <button
                key={d.key}
                onClick={() => loadDemo(d.key)}
                title={d.description}
                className="text-xs px-3 py-1.5 rounded-lg border border-soc-border bg-black/20 hover:border-soc-accent hover:text-soc-accent transition-colors"
              >
                {d.label}
              </button>
            ))}
          </div>
        </div>

        {importStatus.type !== "idle" && (
          <div
            className={`mt-3 flex items-start gap-2 text-xs rounded-lg px-3 py-2 border ${
              importStatus.type === "success"
                ? "border-emerald-800 bg-emerald-950/30 text-emerald-300"
                : "border-red-800 bg-red-950/30 text-red-300"
            }`}
          >
            {importStatus.type === "success" ? (
              <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
            ) : (
              <AlertCircle size={14} className="mt-0.5 shrink-0" />
            )}
            {importStatus.message}
          </div>
        )}
      </section>

      {/* HEADERS */}
      <section className="card-rail" style={{ ["--rail-color" as string]: "#fbbf24" }}>
        <div className="flex items-center justify-between mb-4 gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <User size={15} className="text-amber-400" />
            <h2 className="font-semibold text-white">A. Email Information</h2>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input type="checkbox" checked={useRaw} onChange={(e) => setUseRaw(e.target.checked)} />
            Use raw headers instead of fields
          </label>
        </div>

        {useRaw ? (
          <textarea
            className="field-input h-48 font-mono"
            placeholder={"Paste raw RFC-5322 headers here, e.g.\nFrom: ...\nReply-To: ...\nAuthentication-Results: ...\nReceived: ..."}
            value={headers.raw_headers}
            onChange={updateHeader("raw_headers")}
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              ["from_address", "From"],
              ["to", "To"],
              ["cc", "CC"],
              ["reply_to", "Reply-To"],
              ["return_path", "Return-Path"],
              ["sender", "Sender"],
              ["subject", "Subject"],
              ["message_id", "Message-ID"],
              ["date", "Date"],
            ].map(([key, label]) => (
              <div key={key}>
                <label className="field-label">{label}</label>
                <input
                  className="field-input"
                  value={(headers as any)[key] ?? ""}
                  onChange={updateHeader(key as keyof typeof headers)}
                />
              </div>
            ))}
            <div className="md:col-span-2">
              <label className="field-label">Received headers (one per line, oldest→newest or as received)</label>
              <textarea
                className="field-input h-20 font-mono"
                value={headers.received}
                onChange={updateHeader("received")}
              />
            </div>
            <div className="md:col-span-2">
              <label className="field-label">Authentication-Results</label>
              <textarea
                className="field-input h-16 font-mono"
                value={headers.authentication_results}
                onChange={updateHeader("authentication_results")}
              />
            </div>
            <div>
              <label className="field-label">DKIM-Signature</label>
              <textarea
                className="field-input h-16 font-mono"
                value={headers.dkim_signature}
                onChange={updateHeader("dkim_signature")}
              />
            </div>
            <div>
              <label className="field-label">ARC headers</label>
              <textarea
                className="field-input h-16 font-mono"
                value={headers.arc_headers}
                onChange={updateHeader("arc_headers")}
              />
            </div>
          </div>
        )}
      </section>

      {/* BODY */}
      <section className="card-rail" style={{ ["--rail-color" as string]: "#34d399" }}>
        <div className="flex items-center gap-2 mb-4">
          <FileText size={15} className="text-emerald-400" />
          <h2 className="font-semibold text-white">B. Email Body</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="field-label">Plain text</label>
            <textarea className="field-input h-40" value={plainText} onChange={(e) => setPlainText(e.target.value)} />
          </div>
          <div>
            <label className="field-label">HTML (optional)</label>
            <textarea className="field-input h-40 font-mono" value={html} onChange={(e) => setHtml(e.target.value)} />
          </div>
        </div>
      </section>

      {/* URLS */}
      <section className="card-rail" style={{ ["--rail-color" as string]: "#f87171" }}>
        <div className="flex items-center gap-2 mb-3">
          <Link2 size={15} className="text-red-400" />
          <h2 className="font-semibold text-white">C. URLs</h2>
        </div>
        <p className="text-xs text-slate-400 mb-2">
          Paste one or more URLs (newline-separated). URLs found in the body above are also
          extracted automatically and deduplicated.
        </p>
        <textarea
          className="field-input h-24 font-mono"
          value={urlText}
          onChange={(e) => setUrlText(e.target.value)}
          placeholder={"https://example.com/one\nhttps://example.com/two"}
        />
      </section>

      {/* ATTACHMENTS */}
      <section className="card-rail" style={{ ["--rail-color" as string]: "#60a5fa" }}>
        <div className="flex items-center gap-2 mb-4">
          <Paperclip size={15} className="text-sky-400" />
          <h2 className="font-semibold text-white">D. Attachments</h2>
        </div>
        <label
          className="flex flex-col items-center justify-center border-2 border-dashed border-soc-border rounded-xl p-8 cursor-pointer hover:border-soc-accent transition-colors"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            handleFiles(e.dataTransfer.files);
          }}
        >
          <Upload className="text-slate-500 mb-2" size={28} />
          <span className="text-sm text-slate-400">Drag & drop files here, or click to browse</span>
          <input type="file" multiple className="hidden" onChange={(e) => handleFiles(e.target.files)} />
        </label>

        {attachments.length > 0 && (
          <ul className="mt-4 space-y-2">
            {attachments.map((a, i) => (
              <li
                key={i}
                className="flex items-center justify-between bg-black/30 border border-soc-border rounded-lg px-3 py-2 text-sm"
              >
                <span className="flex items-center gap-2 text-slate-300">
                  <FileText size={16} className="text-slate-500" />
                  {a.filename} <span className="text-slate-500 text-xs">({a.size} bytes)</span>
                </span>
                <button onClick={() => setAttachments((prev) => prev.filter((_, idx) => idx !== i))}>
                  <X size={16} className="text-slate-500 hover:text-red-400" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="fixed bottom-0 left-0 right-0 z-20 border-t border-soc-border bg-soc-bg/90 backdrop-blur">
        <div className="max-w-5xl mx-auto px-6 py-3 flex items-center justify-between gap-4">
          <div className="hidden sm:flex items-center gap-4 text-xs text-slate-500">
            <span className={headerFilled ? "text-slate-300" : ""}>Headers {headerFilled ? "✓" : "—"}</span>
            <span className={plainText || html ? "text-slate-300" : ""}>Body {plainText || html ? "✓" : "—"}</span>
            <span className={urlCount ? "text-slate-300" : ""}>{urlCount} URL{urlCount === 1 ? "" : "s"}</span>
            <span className={attachments.length ? "text-slate-300" : ""}>
              {attachments.length} attachment{attachments.length === 1 ? "" : "s"}
            </span>
          </div>
          <button
            onClick={submit}
            className="flex items-center gap-2 bg-soc-accent text-black font-semibold px-8 py-2.5 rounded-xl shadow-lg shadow-amber-500/20 hover:brightness-110 transition-all ml-auto"
          >
            <Zap size={18} />
            ANALYZE EMAIL
          </button>
        </div>
      </div>
    </div>
  );
}
