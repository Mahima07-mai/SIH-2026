from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import analyze, reports
from app.config import get_settings

settings = get_settings()

app = FastAPI(
    title="AI-Powered Email Threat Detection & Forensic Intelligence Platform",
    description=(
        "Prototype pipeline: ingestion -> parallel analyzers -> evidence "
        "normalization -> correlation/rules -> local ML content analysis "
        "-> deterministic threat classification -> entity graph -> proof "
        "chain -> forensic report. The ML model is an advisory evidence source "
        "only; final classification is rule-based and explainable."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)
app.include_router(reports.router)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "ml_model": "tfidf-logistic-regression",
        "geo_enabled": settings.geo_enabled,
    }
