from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.pipeline import run_analysis
from app.schemas.input import AnalyzeRequest
from app.storage import STORE

router = APIRouter(tags=["analysis"])


@router.post("/api/analyze")
def analyze_email(request: AnalyzeRequest):
    """Orchestrates the entire pipeline synchronously and returns the full
    result. (For the prototype this is fast enough to do inline; a
    production version would kick this off as a background task and let
    the frontend poll /api/emails/{id}.)"""
    try:
        return run_analysis(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline failed: {exc}")


@router.get("/api/emails/{email_id}")
def get_email(email_id: str):
    record = STORE.get(email_id)
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    return record.full_result


@router.get("/api/emails/{email_id}/evidence")
def get_evidence(email_id: str):
    record = STORE.get(email_id)
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    return record.full_result["evidence"]


@router.get("/api/emails/{email_id}/graph")
def get_graph(email_id: str):
    record = STORE.get(email_id)
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    return record.full_result["entity_graph"]


@router.get("/api/emails/{email_id}/proof-chain")
def get_proof_chain(email_id: str):
    record = STORE.get(email_id)
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    return record.full_result["proof_chain"]


@router.get("/api/emails/{email_id}/timeline")
def get_timeline(email_id: str):
    record = STORE.get(email_id)
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    return record.full_result["timeline"]


@router.get("/api/emails/{email_id}/campaigns")
def get_campaigns(email_id: str):
    record = STORE.get(email_id)
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    return record.full_result["campaign_relationships"]


@router.get("/api/emails")
def list_emails():
    return [
        {
            "email_id": a.email_id,
            "label": a.label,
            "category": a.category,
            "risk_score": a.risk_score,
        }
        for a in STORE.all()
    ]
