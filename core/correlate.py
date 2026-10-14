"""Cross-module correlation: fold per-module findings into one entity map.

full_recon dispatches ~100 modules that each report in their own shape. This
walks every result tree, classifies the leaves it recognises, and scores each
entity by how many independent modules reported it, so corroboration is visible
instead of every finding looking equally certain.
"""
import re
from collections import defaultdict

from core.utils import is_valid_domain, is_valid_ip
from core.chains import detect_chain

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)

# "platform:handle" is the convention crypto_identity uses for social handles
# (e.g. "twitter:VitalikButerin"). It is explicit, never page chrome, so the
# handle is safe to read as a username.
SOCIAL_HANDLE_RE = re.compile(
    r"^(twitter|github|lens|farcaster|telegram|discord|reddit|instagram|tiktok|"
    r"youtube|mastodon|bluesky|keybase|linkedin):([A-Za-z0-9._\-@]{1,60})$",
    re.IGNORECASE)

# Keys whose 0x / Base58 values are TOKEN CONTRACTS, not people's wallets.
# Folding them in as wallets made USDT/USDC contracts look like counterparties.
TOKEN_CONTRACT_KEYS = frozenset({
    "token_address", "contract", "contract_address", "token_id", "token_contract",
})
# A leading + is required: without it any 10-digit id scrapes in as a phone.
PHONE_RE = re.compile(r"^\+\d[\d\s\-()]{8,19}$")
URL_RE = re.compile(r"^https?://[^\s<>\"']+$", re.IGNORECASE)
HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{2,38}$")

# RFC-reserved names, XML namespaces and CDN/analytics hosts turn up in almost
# every scrape and are never what the scrape is about.
NOISE_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "example.edu",
    "localhost", "localhost.localdomain", "test.com", "test.net",
    "invalid", "local", "domain.com", "yourdomain.com", "site.com",
    "w3.org", "schema.org", "purl.org", "xml.org", "ietf.org", "rfc-editor.org",
    "gstatic.com", "googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com", "jquery.com", "cdn.jsdelivr.net", "polyfill.io",
    "sentry.io", "newrelic.com", "hotjar.com", "segment.io", "intercom.io",
    "facebook.com", "fbcdn.net", "twitter.com", "t.co", "x.com",
    "youtube.com", "youtu.be", "instagram.com", "linkedin.com", "licdn.com",
    "pinterest.com", "tiktok.com", "reddit.com", "wordpress.org", "gravatar.com",
})

NOISE_EMAIL_PREFIXES = ("noreply", "no-reply", "donotreply", "do-not-reply",
                        "postmaster", "abuse", "mailer-daemon", "bounce")

# Keys whose values are raw payloads: classifying inside them is all noise.
SKIP_KEYS = frozenset({
    "raw", "raw_html", "html", "body", "content", "text", "snippet", "source",
    "headers", "response_headers", "certificate", "cert", "pem", "key",
    "public_key", "ssh_keys", "gpg_keys", "stacktrace", "traceback", "error",
    "description", "bio", "readme", "message", "summary", "disclaimer",
    "uncertainty", "note", "notes", "payload", "payloads", "wordlist",
})

# Entities longer than this are payloads, not identifiers.
MAX_LEAF_LEN = 253

# A bare handle matches almost any short token, so a value is only read as a
# username when its key says that is what it is.
USERNAME_KEYS = frozenset({
    "username", "login", "handle", "screen_name", "nick", "nickname",
    "account", "profile_name", "owner", "org", "organization", "user",
})

NOISE_HANDLES = frozenset({
    "none", "null", "true", "false", "unknown", "anonymous", "admin",
    "test", "user", "username", "example", "default", "root", "guest",
})

# Keep the graph readable when a crawl reports thousands of URLs.
MAX_GRAPH_NODES_PER_TYPE = 40

CONFIDENCE_TIERS = ((3, "strong"), (2, "corroborated"), (1, "single-source"))


def _confidence(module_count):
    for threshold, label in CONFIDENCE_TIERS:
        if module_count >= threshold:
            return label
    return "single-source"


def _registrable(domain):
    """Last two labels of a domain, used to match the noise list."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def classify(value):
    """Return the entity type of a scalar, or None when it isn't one."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_LEAF_LEN:
        return None

    # A phone number is the only entity allowed to contain spaces.
    if " " in text:
        if PHONE_RE.match(text):
            digits = re.sub(r"\D", "", text)
            return "phone" if 10 <= len(digits) <= 15 else None
        return None

    if EMAIL_RE.match(text):
        local = text.split("@", 1)[0].lower()
        domain = text.split("@", 1)[1].lower()
        if local.startswith(NOISE_EMAIL_PREFIXES):
            return None
        if _registrable(domain) in NOISE_DOMAINS or domain.endswith("noreply.github.com"):
            return None
        return "email"

    if URL_RE.match(text):
        # A CDN or analytics URL is the same noise as its bare domain.
        host = text.split("//", 1)[-1].split("/", 1)[0].split("@")[-1]
        host = host.split(":", 1)[0].lower()
        if _registrable(host) in NOISE_DOMAINS:
            return None
        return "url"

    # Shared strict classifier: ETH, BTC, LTC, DOGE and Tron.
    if detect_chain(text):
        return "wallet"

    if ASN_RE.match(text):
        return "asn"

    if PHONE_RE.match(text):
        digits = re.sub(r"\D", "", text)
        return "phone" if 10 <= len(digits) <= 15 else None

    if is_valid_ip(text):
        return "ip"

    if "." in text and is_valid_domain(text):
        return None if _registrable(text) in NOISE_DOMAINS else "domain"

    return None


def _norm(kind, value):
    """Canonical form for de-duplication WITHOUT corrupting identifiers.

    Base58 wallets (BTC/LTC/DOGE/Tron) are case-sensitive — lowercasing turned
    1A1zP1eP5Q... into an invalid address — so only ETH (hex) is lowercased.
    URL paths are case-sensitive too, so only the scheme and host are.
    """
    v = str(value).strip()
    if kind in ("wallet", "token_contract"):
        return v.lower() if v.lower().startswith("0x") else v
    if kind == "url":
        m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/]*)(.*)$", v)
        return (m.group(1).lower() + m.group(2).lower() + m.group(3)) if m else v
    return v.lower()


def _walk(node, module, found, key=None, depth=0):
    """Collect (type, value) -> {modules} from an arbitrary result tree."""
    if depth > 12:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            k_low = str(k).lower()
            # A recognisable dict key is itself a finding (e.g. {email: score}).
            kind = classify(k)
            if kind:
                found[(kind, _norm(kind, k))].add(module)
            if k_low in SKIP_KEYS:
                continue
            _walk(v, module, found, key=k_low, depth=depth + 1)
    elif isinstance(node, (list, tuple, set)):
        for item in node:
            _walk(item, module, found, key=key, depth=depth + 1)
    else:
        if not isinstance(node, str):
            return
        social = SOCIAL_HANDLE_RE.match(node.strip())
        if social:
            handle = social.group(2).lstrip("@")
            if handle.lower() not in NOISE_HANDLES:
                found[("username", handle.lower())].add(module)
            return
        kind = classify(node)
        if kind == "wallet" and key in TOKEN_CONTRACT_KEYS:
            kind = "token_contract"
        if kind:
            found[(kind, _norm(kind, node))].add(module)
        elif key in USERNAME_KEYS:
            handle = node.strip()
            if HANDLE_RE.match(handle) and handle.lower() not in NOISE_HANDLES:
                found[("username", handle.lower())].add(module)


def correlate(target, per_module_results, target_type=None):
    """Merge every module's findings for one target into a single entity map."""
    found = defaultdict(set)
    for module, results in (per_module_results or {}).items():
        _walk(results, module, found)

    target_norm = (target or "").strip().lower()
    entities = defaultdict(list)
    for (kind, value), modules in found.items():
        # Case-insensitive: wallet values keep their (significant) case.
        if value.lower() == target_norm:
            continue
        entities[kind].append({
            "value": value,
            "type": kind,
            "modules": sorted(modules),
            "module_count": len(modules),
            "confidence": _confidence(len(modules)),
        })

    for kind in entities:
        entities[kind].sort(key=lambda e: (-e["module_count"], e["value"]))

    corroborated = sorted(
        (e for group in entities.values() for e in group if e["module_count"] >= 2),
        key=lambda e: -e["module_count"],
    )

    return {
        "target": target,
        "target_type": target_type,
        "entities": dict(entities),
        "totals": {kind: len(group) for kind, group in sorted(entities.items())},
        "total_entities": sum(len(group) for group in entities.values()),
        "corroborated": corroborated,
        "modules_contributing": sorted({
            m for modules in found.values() for m in modules
        }),
        "graph": build_graph(target, entities),
        "pivot_suggestions": pivot_suggestions(entities),
    }


def build_graph(target, entities):
    """Nodes/edges shaped for Reporter.generate_graph_html."""
    nodes = [{
        "id": target,
        "label": target,
        "group": "target",
        "title": "scan target",
        "value": 30,
    }]
    edges = []
    seen = {target}

    for kind, group in entities.items():
        for entity in group[:MAX_GRAPH_NODES_PER_TYPE]:
            value = entity["value"]
            if value not in seen:
                seen.add(value)
                nodes.append({
                    "id": value,
                    "label": value,
                    "group": kind,
                    "title": (f"{kind} | {entity['confidence']} | "
                              f"{entity['module_count']} module(s): "
                              f"{', '.join(entity['modules'][:6])}"),
                    "value": 5 + 5 * entity["module_count"],
                })
            edges.append({
                "from": target,
                "to": value,
                "label": f"{kind} ({entity['module_count']})",
            })

    # Tie each email to its own domain when both made it into the graph. The
    # target is skipped: target -> email already carries that relationship.
    for entity in entities.get("email", [])[:MAX_GRAPH_NODES_PER_TYPE]:
        domain = entity["value"].split("@", 1)[-1]
        if domain != target and domain in seen and entity["value"] in seen:
            edges.append({"from": entity["value"], "to": domain, "label": "domain-of"})

    return {"nodes": nodes, "edges": edges}


PIVOTABLE = ("email", "username", "domain", "phone", "wallet")


def pivot_suggestions(entities, limit=10):
    """Corroborated entities worth feeding back into identity_pivot."""
    out = []
    for kind in PIVOTABLE:
        for entity in entities.get(kind, []):
            if entity["module_count"] >= 2:
                out.append({
                    "value": entity["value"],
                    "type": kind,
                    "module_count": entity["module_count"],
                    "command": f"use identity_pivot; set TARGET {entity['value']}; run",
                })
    out.sort(key=lambda e: -e["module_count"])
    return out[:limit]
