from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.reporting.pdf_report import generate_pdf_report
from app.storage import STORE

router = APIRouter(tags=["reports"])


@router.post("/api/reports/{email_id}/pdf")
def export_pdf(email_id: str):
    record = STORE.get(email_id)
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    pdf_bytes = generate_pdf_report(record.full_result)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{email_id}_forensic_report.pdf"'},
    )
