from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class EmailHeadersInput(BaseModel):
    from_address: Optional[str] = None
    to: Optional[str] = None
    cc: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    message_id: Optional[str] = None
    date: Optional[str] = None
    received: Optional[str] = None  # newline separated, most-recent-first not assumed
    authentication_results: Optional[str] = None
    dkim_signature: Optional[str] = None
    arc_headers: Optional[str] = None
    other_headers: Optional[str] = None
    raw_headers: Optional[str] = None  # if provided, takes priority / fills gaps


class EmailBodyInput(BaseModel):
    plain_text: Optional[str] = None
    html: Optional[str] = None


class AttachmentInput(BaseModel):
    filename: str
    mime_type: Optional[str] = None
    size: Optional[int] = None
    content_base64: str


class AnalyzeRequest(BaseModel):
    headers: EmailHeadersInput = Field(default_factory=EmailHeadersInput)
    body: EmailBodyInput = Field(default_factory=EmailBodyInput)
    urls: list[str] = Field(default_factory=list)
    attachments: list[AttachmentInput] = Field(default_factory=list)
    label: Optional[str] = None  # optional human label, e.g. "Demo: Phishing"
