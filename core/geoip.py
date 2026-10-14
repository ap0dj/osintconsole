"""Shared IP geolocation / network lookup.

ip-api.com's FREE tier is HTTP-only: the https:// endpoint answers 403 "SSL
unavailable for this endpoint, order a key" (verified live). An earlier
"HTTPS everywhere" pass switched three modules to https, which made every
ip-api lookup fail silently. This helper uses the working free endpoint and
falls back to ipwho.is (free, HTTPS) so a lookup still succeeds if ip-api is
down or rate-limited.

The queried IP already crosses the wire in cleartext via DNSBL lookups, so the
HTTP call adds no new class of exposure.
"""
from core import http

_IPAPI_FIELDS = 66846719


def lookup(ip):
    """ip-api-shaped dict (status == 'success') or None.

    Keys follow ip-api (country, countryCode, regionName, city, lat, lon,
    timezone, isp, org, as, asname, reverse, mobile, proxy, hosting) plus
    `_source`. On the ipwho.is fallback the proxy/hosting/mobile flags are
    None — unknown, never assumed False.
    """
    try:
        resp = http.get(f"http://ip-api.com/json/{ip}",
                        params={"fields": _IPAPI_FIELDS}, timeout=15)
        if resp.status_code == 200:
            d = resp.json()
            if d.get("status") == "success":
                d["_source"] = "ip-api.com"
                return d
    except Exception:
        pass

    try:
        resp = http.get(f"https://ipwho.is/{ip}", timeout=15)
        if resp.status_code == 200:
            w = resp.json()
            if w.get("success"):
                conn = w.get("connection") or {}
                asn = conn.get("asn")
                return {
                    "status": "success",
                    "query": w.get("ip"),
                    "continent": w.get("continent"),
                    "country": w.get("country"),
                    "countryCode": w.get("country_code"),
                    "regionName": w.get("region"),
                    "city": w.get("city"),
                    "lat": w.get("latitude"),
                    "lon": w.get("longitude"),
                    "timezone": (w.get("timezone") or {}).get("id"),
                    "isp": conn.get("isp"),
                    "org": conn.get("org"),
                    "as": f"AS{asn} {conn.get('org') or ''}".strip() if asn else None,
                    "asname": conn.get("org"),
                    "reverse": None,
                    "mobile": None, "proxy": None, "hosting": None,
                    "_source": "ipwho.is",
                }
    except Exception:
        pass
    return None
