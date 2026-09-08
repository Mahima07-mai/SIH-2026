"""
Layer 8 (part) — PDF forensic report, generated with ReportLab.

Kept intentionally plain (no external fonts/assets) so it renders anywhere
ReportLab is installed, with zero extra setup.
"""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def _severity_color(risk_score: int):
    if risk_score >= 70:
        return colors.HexColor("#dc2626")
    if risk_score >= 40:
        return colors.HexColor("#f59e0b")
    return colors.HexColor("#16a34a")


def generate_pdf_report(result: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER, topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1Custom", fontSize=20, spaceAfter=12, textColor=colors.HexColor("#0f172a")))
    styles.add(ParagraphStyle(name="H2Custom", fontSize=14, spaceBefore=14, spaceAfter=8, textColor=colors.HexColor("#0f172a")))
    styles.add(ParagraphStyle(name="Small", fontSize=9, textColor=colors.HexColor("#475569")))

    story = []
    threat = result["threat_result"]

    story.append(Paragraph("Email Threat Forensic Report", styles["H1Custom"]))
    story.append(Paragraph(f"Email ID: {result['email_id']} &nbsp;&nbsp;|&nbsp;&nbsp; Analyzed at: {result['analyzed_at']}", styles["Small"]))
    story.append(Spacer(1, 12))

    # --- Executive summary -------------------------------------------------
    summary_data = [
        ["Threat Category", threat["category"] + (f" / {threat['subcategory']}" if threat.get("subcategory") else "")],
        ["Risk Score", f"{threat['risk_score']} / 100"],
        ["Confidence", threat["confidence"]],
    ]
    t = Table(summary_data, colWidths=[150, 350])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR", (1, 1), (1, 1), _severity_color(threat["risk_score"])),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # --- Sender identity -----------------------------------------------------
    headers = result["headers"]
    story.append(Paragraph("Sender Identity", styles["H2Custom"]))
    for label, key in [("From", "from"), ("Reply-To", "reply_to"), ("Return-Path", "return_path"),
                        ("Sender", "sender"), ("Message-ID", "message_id")]:
        val = headers.get(key) or "(not supplied)"
        story.append(Paragraph(f"<b>{label}:</b> {val}", styles["Normal"]))

    # --- Evidence table --------------------------------------------------------
    story.append(Paragraph("Evidence Table", styles["H2Custom"]))
    ev_rows = [["Type", "Value", "Source", "Reliability", "Fact Level"]]
    for ev in result["evidence"][:60]:  # cap for report length
        val = str(ev["value"])
        if len(val) > 40:
            val = val[:37] + "..."
        ev_rows.append([ev["type"], val, ev["source"], ev["reliability"], ev["fact_level"]])
    ev_table = Table(ev_rows, colWidths=[120, 140, 90, 70, 70], repeatRows=1)
    ev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.append(ev_table)
    story.append(PageBreak())

    # --- Proof chain -------------------------------------------------------
    story.append(Paragraph("Proof Chain", styles["H2Custom"]))
    for step in result["proof_chain"]:
        fl = f" [{step['fact_level']}]" if step.get("fact_level") else ""
        story.append(Paragraph(f"{step['step']}. {step['label']}{fl}", styles["Normal"]))
        story.append(Spacer(1, 4))

    # --- Reasoning ------------------------------------------------------------
    story.append(Paragraph("Classification Reasoning", styles["H2Custom"]))
    for r in threat["reasoning"]:
        story.append(Paragraph(f"&bull; {r}", styles["Normal"]))

    # --- Limitations ---------------------------------------------------------
    story.append(Paragraph("What We Cannot Know", styles["H2Custom"]))
    for lim in result["limitations"]:
        story.append(Paragraph(f"&bull; {lim}", styles["Normal"]))

    doc.build(story)
    return buf.getvalue()
