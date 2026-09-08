"""
WHOIS lookup service. Uses the `python-whois` library (no API key needed),
but WHOIS servers are often slow, rate-limited, or blocked on sandboxed
networks — every failure degrades to an explicit "unavailable" status.
"""
from __future__ import annotations

from datetime import datetime, timezone


def lookup_whois(domain: str) -> dict:
    try:
        import whois  # python-whois; imported lazily so its absence doesn't
                       # break the rest of the app.
    except ImportError:
        return {"status": "unavailable", "reason": "python-whois not installed", "domain": domain}

    try:
        record = whois.whois(domain)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        if not creation_date:
            return {"status": "unavailable", "reason": "no creation date returned", "domain": domain}

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days

        return {
            "status": "success",
            "domain": domain,
            "creation_date": creation_date.isoformat(),
            "age_days": age_days,
            "registrar": getattr(record, "registrar", None),
        }
    except Exception as exc:
        return {"status": "unavailable", "reason": str(exc), "domain": domain}
