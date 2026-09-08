"""
IP geolocation / ASN lookup service.

Uses ipinfo.io if IPINFO_TOKEN is configured. If not configured, or if the
request fails for any reason, returns an explicit "unavailable" status —
never a fabricated location.
"""
from __future__ import annotations

import httpx

from app.config import get_settings

_WELL_KNOWN_ASN_HINTS = {
    "google": "Google",
    "microsoft": "Microsoft",
    "amazon": "Amazon / AWS",
    "cloudflare": "Cloudflare",
    "digitalocean": "DigitalOcean",
    "ovh": "OVH",
    "hetzner": "Hetzner",
    "linode": "Akamai/Linode",
}


def lookup_ip(ip: str) -> dict:
    """Return geolocation/ASN info for an IP, or an explicit unavailable status."""
    settings = get_settings()

    if not settings.geo_enabled:
        return {
            "status": "unavailable",
            "reason": "IPINFO_TOKEN not configured",
            "ip": ip,
        }

    try:
        resp = httpx.get(
            f"https://ipinfo.io/{ip}/json",
            params={"token": settings.ipinfo_token},
            timeout=5.0,
        )
        resp.raise_for_status()
        data = resp.json()
        org = data.get("org", "") or ""
        is_cloud_or_relay = any(hint in org.lower() for hint in _WELL_KNOWN_ASN_HINTS)
        return {
            "status": "success",
            "ip": ip,
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "org": org or None,
            "timezone": data.get("timezone"),
            "is_likely_cloud_or_relay": is_cloud_or_relay,
        }
    except Exception as exc:
        return {"status": "unavailable", "reason": str(exc), "ip": ip}
