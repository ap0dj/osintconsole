"""Reverse geocoding — turn GPS coordinates into a human-readable place.

EXIF/photo modules extract raw lat/lon but never resolved them. BigDataCloud's
reverse-geocode-client endpoint is free, keyless and does not gate the shared
CGNAT IP (verified live). OpenStreetMap Nominatim is kept as a fallback, but it
403s this box, so it is secondary. Read-only, no key.
"""
from core import http

_BDC = "https://api.bigdatacloud.net/data/reverse-geocode-client"
_NOMINATIM = "https://nominatim.openstreetmap.org/reverse"


def _valid(lat, lon):
    try:
        la, lo = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    if -90 <= la <= 90 and -180 <= lo <= 180:
        return la, lo
    return None


def reverse(lat, lon):
    """{city, locality, region, country, country_code, postcode, display_name,
    source} for a coordinate pair, or None when both services fail / coords
    are invalid."""
    coords = _valid(lat, lon)
    if not coords:
        return None
    la, lo = coords

    try:
        r = http.get(_BDC, params={"latitude": la, "longitude": lo,
                                   "localityLanguage": "en"}, timeout=20)
        if r.status_code == 200:
            d = r.json()
            city = d.get("city") or d.get("locality")
            region = d.get("principalSubdivision")
            country = d.get("countryName")
            parts = [p for p in (city, region, country) if p]
            return {
                "city": city,
                "locality": d.get("locality"),
                "region": region,
                "country": country,
                "country_code": d.get("countryCode"),
                "postcode": d.get("postcode") or None,
                "display_name": ", ".join(parts) or None,
                "source": "bigdatacloud",
            }
    except Exception:
        pass

    # Fallback: OSM Nominatim (usage policy: descriptive UA, 1 req/s).
    try:
        r = http.get(_NOMINATIM,
                     params={"lat": la, "lon": lo, "format": "jsonv2"},
                     headers={"User-Agent":
                              "OsintConsole/1.0 (OSINT research)"}, timeout=20)
        if r.status_code == 200:
            d = r.json()
            a = d.get("address") or {}
            return {
                "city": a.get("city") or a.get("town") or a.get("village"),
                "locality": a.get("suburb") or a.get("neighbourhood"),
                "region": a.get("state"),
                "country": a.get("country"),
                "country_code": (a.get("country_code") or "").upper() or None,
                "postcode": a.get("postcode"),
                "display_name": d.get("display_name"),
                "source": "nominatim",
            }
    except Exception:
        pass
    return None
