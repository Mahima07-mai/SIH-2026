"""
Layer 1.1 — Header parsing.

Parses a raw pasted header block (RFC 5322-ish) into a dict, using Python's
standard `email` library. Used to auto-fill structured fields when the user
pastes raw headers instead of (or in addition to) filling the form fields.
"""
from __future__ import annotations

from email import message_from_string
from email.policy import default as default_policy


def parse_raw_headers(raw: str) -> dict[str, str]:
    """Best-effort parse of a raw header block into a flat dict.

    Falls back gracefully on malformed input — a partial dict is still
    useful, and the rest of the pipeline treats missing fields as None
    rather than crashing.
    """
    if not raw or not raw.strip():
        return {}

    try:
        msg = message_from_string(raw, policy=default_policy)
    except Exception:
        return {}

    def get(name: str) -> str | None:
        val = msg.get(name)
        return str(val) if val is not None else None

    received_all = msg.get_all("Received") or []

    return {
        "from": get("From"),
        "to": get("To"),
        "cc": get("Cc"),
        "reply_to": get("Reply-To"),
        "return_path": get("Return-Path"),
        "sender": get("Sender"),
        "subject": get("Subject"),
        "message_id": get("Message-ID"),
        "date": get("Date"),
        "received": "\n".join(str(r) for r in received_all) if received_all else None,
        "authentication_results": get("Authentication-Results"),
        "dkim_signature": get("DKIM-Signature"),
        "arc_headers": "\n".join(
            str(v) for k, v in msg.items() if k.lower().startswith("arc-")
        ) or None,
    }


def merge_headers(structured: dict, parsed_from_raw: dict) -> dict:
    """Structured form fields win; raw-header parse fills in gaps."""
    merged = dict(structured)
    for key, value in parsed_from_raw.items():
        if not merged.get(key) and value:
            merged[key] = value
    return merged
