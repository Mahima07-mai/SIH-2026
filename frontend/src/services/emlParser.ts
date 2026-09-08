import PostalMime, { type Address, type Email } from "postal-mime";
import type { AnalyzeRequestBody } from "./api";
import type { AttachmentDraft } from "../types";

export interface ParsedEml {
  headers: AnalyzeRequestBody["headers"];
  plainText: string;
  html: string;
  urls: string[];
  attachments: AttachmentDraft[];
  subject: string;
  from: string;
}

function formatAddress(addr?: Address): string {
  if (!addr) return "";
  if ("group" in addr && addr.group) {
    return addr.group.map((m) => (m.name ? `${m.name} <${m.address}>` : m.address)).join(", ");
  }
  const mailbox = addr as { name?: string; address?: string };
  if (mailbox.name && mailbox.address) return `${mailbox.name} <${mailbox.address}>`;
  return mailbox.address ?? "";
}

function formatAddressList(list?: Address[]): string {
  if (!list || list.length === 0) return "";
  return list.map(formatAddress).join(", ");
}

function headerValues(email: Email, key: string): string {
  return email.headers
    .filter((h) => h.key === key)
    .map((h) => h.value)
    .join("\n");
}

function arcHeaders(email: Email): string {
  return email.headers
    .filter((h) => h.key.startsWith("arc-"))
    .map((h) => `${h.originalKey}: ${h.value}`)
    .join("\n");
}

function otherHeaders(email: Email): string {
  const known = new Set([
    "from",
    "to",
    "cc",
    "reply-to",
    "return-path",
    "sender",
    "subject",
    "message-id",
    "date",
    "received",
    "authentication-results",
    "dkim-signature",
  ]);
  return email.headers
    .filter((h) => !known.has(h.key) && !h.key.startsWith("arc-"))
    .map((h) => `${h.originalKey}: ${h.value}`)
    .join("\n");
}

// Lightweight URL extraction so the URLs tab is pre-populated for review;
// the backend independently extracts + dedupes URLs from the body as well.
function extractUrls(...texts: (string | undefined)[]): string[] {
  const found = new Set<string>();
  const pattern = /https?:\/\/[^\s"'<>()]+/gi;
  for (const text of texts) {
    if (!text) continue;
    const matches = text.match(pattern);
    matches?.forEach((m) => found.add(m.replace(/[),.]+$/, "")));
  }
  return Array.from(found);
}

function base64ByteLength(base64: string): number {
  const clean = base64.replace(/=+$/, "");
  return Math.floor((clean.length * 3) / 4);
}

/** Parses the raw text contents of an .eml file entirely client-side and
 * maps the result onto the shapes InputForm already works with, so a pasted
 * email flows through the exact same analyze pipeline as manual entry. */
export async function parseEmlSource(raw: string): Promise<ParsedEml> {
  const email = await PostalMime.parse(raw, { attachmentEncoding: "base64" });

  const headers: AnalyzeRequestBody["headers"] = {
    from_address: formatAddress(email.from),
    to: formatAddressList(email.to),
    cc: formatAddressList(email.cc),
    reply_to: formatAddressList(email.replyTo),
    return_path: email.returnPath ?? "",
    sender: formatAddress(email.sender),
    subject: email.subject ?? "",
    message_id: email.messageId ?? "",
    date: email.date ?? "",
    received: headerValues(email, "received"),
    authentication_results: headerValues(email, "authentication-results"),
    dkim_signature: headerValues(email, "dkim-signature"),
    arc_headers: arcHeaders(email),
    other_headers: otherHeaders(email),
    raw_headers: email.headerLines.map((h) => h.line).join("\n"),
  };

  const attachments: AttachmentDraft[] = email.attachments.map((a) => {
    const content_base64 = typeof a.content === "string" ? a.content : "";
    return {
      filename: a.filename ?? "unnamed-attachment",
      mime_type: a.mimeType || "application/octet-stream",
      size: base64ByteLength(content_base64),
      content_base64,
    };
  });

  return {
    headers,
    plainText: email.text ?? "",
    html: email.html ?? "",
    urls: extractUrls(email.text, email.html),
    attachments,
    subject: email.subject ?? "(no subject)",
    from: formatAddress(email.from) || "(unknown sender)",
  };
}
