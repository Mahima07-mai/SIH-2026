"""
Advisory content/NLP layer.

CRITICAL ARCHITECTURE RULE: this service NEVER returns a final verdict like
"phishing" or "malware". It returns bounded [0,1] semantic scores that the
correlation engine treats as `fact_level=Inferred`, `reliability=Medium`
evidence — one input among many, not the decision-maker.

Talks to OpenRouter's OpenAI-compatible /chat/completions endpoint. If no
API key is configured, or the call fails for any reason, the pipeline must
keep working using only deterministic evidence — so this returns an
explicit "unavailable" status rather than raising.
"""
from __future__ import annotations

import json

from pydantic import BaseModel, Field, ValidationError

from app.config import get_settings

SYSTEM_PROMPT = """You are a content-analysis component inside a larger email \
security pipeline. You do NOT make the final threat decision — a separate \
deterministic rule engine does that. Your job is ONLY to rate the semantic \
characteristics of the email text below on a 0.0-1.0 scale.

Respond with STRICT JSON only, matching exactly this schema, no prose, no \
markdown fences:

{
  "urgency": <0-1 float>,
  "phishing_intent": <0-1 float>,
  "impersonation_style": <0-1 float>,
  "social_engineering": <0-1 float>,
  "credential_request": <0-1 float>,
  "financial_request": <0-1 float>,
  "account_threat": <0-1 float>,
  "brand_mention": <string or null>
}
"""


class NlpScores(BaseModel):
    urgency: float = Field(ge=0, le=1)
    phishing_intent: float = Field(ge=0, le=1)
    impersonation_style: float = Field(ge=0, le=1)
    social_engineering: float = Field(ge=0, le=1)
    credential_request: float = Field(ge=0, le=1)
    financial_request: float = Field(ge=0, le=1)
    account_threat: float = Field(ge=0, le=1)
    brand_mention: str | None = None


def analyze_content(subject: str | None, body: str | None) -> dict:
    settings = get_settings()

    if not settings.llm_enabled:
        return {"status": "unavailable", "reason": "OPENROUTER_API_KEY not configured"}

    text = f"SUBJECT: {subject or '(none)'}\n\nBODY:\n{body or '(none)'}"
    # Keep the prompt bounded — this is content analysis, not a document
    # summarizer, and very long bodies cost tokens without adding signal.
    text = text[:8000]

    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=settings.openrouter_api_key,
            base_url=settings.openrouter_base_url,
        )
        response = client.chat.completions.create(
            model=settings.openrouter_model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            temperature=0,
            max_tokens=300,
        )
        raw = response.choices[0].message.content or ""
        raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(raw)
        scores = NlpScores(**parsed)
        return {"status": "success", "scores": scores.model_dump()}
    except (ValidationError, json.JSONDecodeError) as exc:
        return {"status": "error", "reason": f"LLM returned malformed output: {exc}"}
    except Exception as exc:
        return {"status": "unavailable", "reason": str(exc)}
