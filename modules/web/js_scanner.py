"""JavaScript file scanner.

Extracts secrets, API endpoints, GraphQL schemas, source maps (and the
original file paths they reveal), WebSocket/SSE targets, framework-specific
routes and hard-coded config blobs from the JS a page ships. All manual
OSINT -- no third-party APIs. Uses ``core.http`` so proxy/Tor/rate limiting
and retries all come along for free.
"""
import json
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.utils import Colors, print_status
from core import http


# ---------------------------------------------------------------------------
# Secret detection (existing, kept intact)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = {
    "AWS Access Key ID": r'\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA)[A-Z0-9]{16}\b',
    "AWS Secret Key": r'(?i)aws[_\-]?(?:secret|private)?[_\-]?(?:access)?[_\-]?key["\'\s:=]{1,10}[A-Za-z0-9/+=]{35,45}',
    "Google API Key": r'\bAIza[0-9A-Za-z_\-]{35}\b',
    "GitHub Token": r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b',
    "Slack Token": r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b',
    "Stripe Live Key": r'\bsk_live_[A-Za-z0-9]{24,}\b',
    "Stripe Publishable": r'\bpk_live_[A-Za-z0-9]{24,}\b',
    "JWT": r'\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b',
    "Private Key": r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
    "Firebase URL": r'\bhttps://[a-z0-9\-]+\.firebaseio\.com\b',
    "Mapbox Token": r'\bpk\.ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b',
}

_COMPILED_SECRETS = {name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()}

PLACEHOLDER_MARKERS = ('example', 'your', 'xxxxx', 'placeholder', 'test')


def _has_placeholder_context(content, start, end):
    ctx_start = max(0, start - 20)
    ctx_end = min(len(content), end + 20)
    context = content[ctx_start:ctx_end].lower()
    return any(w in context for w in PLACEHOLDER_MARKERS)


def _jwt_is_trivial(val):
    """Skip JWTs whose header is alg:none or whose total length is trivially small."""
    import base64 as _b64
    try:
        if len(val) < 60:
            return True
        parts = val.split('.')
        if len(parts) != 3:
            return True
        pad = '=' * (-len(parts[0]) % 4)
        header_bytes = _b64.urlsafe_b64decode(parts[0] + pad)
        header_text = header_bytes.decode('utf-8', errors='ignore').replace(' ', '').lower()
        if '"alg":"none"' in header_text:
            return True
    except Exception:
        return True
    return False


# ---------------------------------------------------------------------------
# Endpoint extraction
# ---------------------------------------------------------------------------

ENDPOINT_PATTERNS = [
    # Absolute URLs that look like API surfaces.
    re.compile(r'["\'`]((?:https?://[^"\'`\s]+?)(?:/api|/v\d+|/graphql|/admin|/user|/users|/auth|/login|/token|/oauth)[^"\'`\s]*)["\'`]'),
    # Relative API-shaped paths.
    re.compile(r'["\'`](/(?:api|v\d+|graphql|rest|admin|auth|user|users|login|register|oauth|token|internal|private|signup|signin|logout|me|account)(?:/[A-Za-z0-9_\-\.~:/?#\[\]@!$&\'()*+,;=%]*)?)["\'`]'),
    # fetch("...") / axios.get("...") / axios("...").
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch|head|options|request)|axios)\s*\(\s*["\'`]([^"\'`\s]+)["\'`]'),
    # XMLHttpRequest.open("METHOD", "url", ...)
    re.compile(r'\.open\s*\(\s*["\'`][A-Z]+["\'`]\s*,\s*["\'`]([^"\'`\s]+)["\'`]'),
    # jQuery $.ajax({url: "..."})
    re.compile(r'\.ajax\s*\(\s*\{[^}]{0,500}?url\s*:\s*["\'`]([^"\'`\s]+)["\'`]'),
]

# WebSocket / Server-Sent Events.
WS_PATTERNS = [
    re.compile(r'new\s+WebSocket\s*\(\s*["\'`]([^"\'`\s]+)["\'`]'),
    re.compile(r'["\'`](wss?://[^"\'`\s]+)["\'`]'),
]
SSE_PATTERNS = [
    re.compile(r'new\s+EventSource\s*\(\s*["\'`]([^"\'`\s]+)["\'`]'),
]

# Framework-specific routes.
FRAMEWORK_PATTERNS = {
    "nextjs": [
        re.compile(r'["\'`](/_next/data/[^"\'`\s]+)["\'`]'),
        re.compile(r'["\'`](/_next/image[^"\'`\s]*)["\'`]'),
        re.compile(r'["\'`](/_next/static/[^"\'`\s]+)["\'`]'),
    ],
    "nuxt": [
        re.compile(r'["\'`](/_nuxt/[^"\'`\s]+)["\'`]'),
    ],
    "vite": [
        re.compile(r'["\'`](/@vite/[^"\'`\s]+)["\'`]'),
        re.compile(r'["\'`](/@fs/[^"\'`\s]+)["\'`]'),
        re.compile(r'["\'`](/@id/[^"\'`\s]+)["\'`]'),
    ],
    "gatsby": [
        re.compile(r'["\'`](/page-data/[^"\'`\s]+)["\'`]'),
        re.compile(r'["\'`](/___graphql[^"\'`\s]*)["\'`]'),
    ],
    "sveltekit": [
        re.compile(r'["\'`](/__data\.json[^"\'`\s]*)["\'`]'),
        re.compile(r'["\'`](/_app/immutable/[^"\'`\s]+)["\'`]'),
    ],
    "angular": [
        # Angular router config: { path: 'foo/bar', ... }
        re.compile(r'\bpath\s*:\s*["\'`]([A-Za-z0-9_\-/:]+)["\'`]'),
    ],
}

# GraphQL.
GQL_QUERY_RE = re.compile(
    r'(?:^|[\s`"\'(,=])'
    r'(query|mutation|subscription)'
    r'(?:\s+([A-Za-z_][A-Za-z0-9_]*))?'
    r'\s*(?:\([^)]*\))?\s*\{([^{}]{0,2000}(?:\{[^{}]{0,1000}\}[^{}]{0,2000})*)\}',
    re.IGNORECASE,
)
GQL_TYPENAME_RE = re.compile(r'__typename\s*[:=]\s*["\'`]([A-Za-z_][A-Za-z0-9_]*)["\'`]')
GQL_ENDPOINT_RE = re.compile(r'["\'`]((?:https?://[^"\'`\s]+)?/(?:api/)?graphql[^"\'`\s]*)["\'`]')

# Source maps.
SOURCEMAP_COMMENT_RE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')

# Config blobs: window.CONFIG, window.__INITIAL_STATE__, const config = { ... }
CONFIG_BLOB_PATTERNS = [
    re.compile(r'window\.(CONFIG|APP_CONFIG|RUNTIME_CONFIG|ENV)\s*=\s*(\{[^;]{10,20000}?\})\s*[;\n]', re.DOTALL),
    re.compile(r'window\.(__INITIAL_STATE__|__PRELOADED_STATE__|__APOLLO_STATE__|__NUXT__|__NEXT_DATA__|__INITIAL_DATA__)\s*=\s*(\{[^;]{10,100000}?\})\s*[;\n]', re.DOTALL),
    re.compile(r'(?:^|[\n;])\s*(?:const|let|var)\s+(config|CONFIG|appConfig|APP_CONFIG|settings)\s*=\s*(\{[^;]{10,10000}?\})\s*[;\n]', re.DOTALL),
]
# Keys inside a config blob that are especially interesting.
CONFIG_KEY_RE = re.compile(
    r'["\']?(API_URL|API_BASE|API_HOST|API_ENDPOINT|BACKEND_URL|BACKEND_HOST|AUTH_URL|AUTH_HOST|'
    r'CDN_URL|CDN_HOST|GRAPHQL_URL|GRAPHQL_ENDPOINT|WS_URL|WEBSOCKET_URL|APP_ENV|ENVIRONMENT|'
    r'STAGE|REGION|CLIENT_ID|TENANT_ID|PROJECT_ID|FIREBASE_[A-Z_]+|SENTRY_DSN|GTM_ID|GA_ID)'
    r'["\']?\s*[:=]\s*["\'`]([^"\'`\n]{1,200})["\'`]',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------

def _classify_endpoint(ep):
    """Return a tuple (category, normalized) for an endpoint string.

    Categories: graphql, admin, auth, internal, rest, other.
    """
    low = ep.lower()
    # Normalize: strip surrounding whitespace, keep case for the path portion.
    norm = ep.strip()

    if 'graphql' in low:
        return "graphql", norm
    if '/admin' in low or low.startswith('admin/'):
        return "admin", norm
    if any(a in low for a in ('/login', '/logout', '/signin', '/signup', '/register',
                              '/oauth', '/token', '/auth', '/sso', '/jwt')):
        return "auth", norm
    if 'internal' in low or 'private' in low:
        return "internal", norm
    if (re.search(r'/v\d+/', low) or '/api/' in low or '/rest/' in low
            or low.startswith('/api') or low.startswith('/rest')):
        return "rest", norm
    return "other", norm


def _looks_like_endpoint(s):
    """Reject obvious false positives before classification."""
    if not s or len(s) < 2 or len(s) > 2048:
        return False
    # Filter out data: / blob: / javascript: URIs and MIME-like strings.
    low = s.lower()
    if low.startswith(('data:', 'blob:', 'javascript:', 'mailto:', 'tel:')):
        return False
    # Reject strings that are clearly file extensions on their own.
    if s in ('/', '//', './', '../'):
        return False
    return True


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------


class JsScanner(BaseModule):
    name = "web/js_scanner"
    description = ("JavaScript file scanner - find secrets, endpoints, GraphQL schemas, "
                   "source maps, websockets and hard-coded config")
    category = "web"
    target_type = "domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain or URL")
        self.add_option("MAX_FILES", "30", False, "Maximum JS files to scan")
        self.add_option("MAX_SIZE_KB", "5000", False, "Max file size to download in KB")
        self.add_option("VERIFY_TLS", "true", False,
                        "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")
        self.add_option("FETCH_SOURCE_MAPS", "true", False,
                        "Fetch .map files when detected to extract original source paths")

    # ---- JS discovery -----------------------------------------------------

    def _find_js_files(self, base_url):
        js_files = set()
        try:
            resp = http.get(base_url, timeout=10, verify=self._verify_tls)
            soup = BeautifulSoup(resp.text, "html.parser")
            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_url = urljoin(base_url, src)
                js_files.add(full_url)
            inline_srcs = re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', resp.text)
            for src in inline_srcs:
                if not src.startswith(("data:", "blob:")):
                    js_files.add(urljoin(base_url, src))
        except Exception as e:
            print_status(f"Failed to discover JS files: {e}", "error")
        return list(js_files)

    # ---- Per-content extractors -------------------------------------------

    def _extract_secrets(self, content, url):
        secrets = []
        for name, pattern in _COMPILED_SECRETS.items():
            seen = set()
            for m in pattern.finditer(content):
                val = m.group(0)
                if not val or len(val) <= 4 or val in seen:
                    continue
                if _has_placeholder_context(content, m.start(), m.end()):
                    continue
                if name == "JWT" and _jwt_is_trivial(val):
                    continue
                seen.add(val)
                secrets.append({
                    "type": name,
                    "value": val[:100],
                    "source": url,
                })
        return secrets

    def _extract_endpoints(self, content):
        """Return list of raw endpoint strings; dedup done by caller."""
        found = []
        for pattern in ENDPOINT_PATTERNS:
            for m in pattern.finditer(content):
                try:
                    val = m.group(1)
                except IndexError:
                    continue
                if _looks_like_endpoint(val):
                    found.append(val)
        return found

    def _extract_websockets(self, content):
        urls = []
        for pattern in WS_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(1)
                if _looks_like_endpoint(val):
                    urls.append(val)
        return urls

    def _extract_sse(self, content):
        urls = []
        for pattern in SSE_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(1)
                if _looks_like_endpoint(val):
                    urls.append(val)
        return urls

    def _extract_framework(self, content):
        """Return {framework: [routes...]} dict for anything matched."""
        out = {}
        for fw, patterns in FRAMEWORK_PATTERNS.items():
            matches = []
            for p in patterns:
                for m in p.finditer(content):
                    val = m.group(1)
                    if _looks_like_endpoint(val):
                        matches.append(val)
            if matches:
                out[fw] = matches
        return out

    def _extract_graphql(self, content):
        """Return {queries, mutations, subscriptions, endpoints, types_seen}."""
        queries, mutations, subscriptions = [], [], []
        for m in GQL_QUERY_RE.finditer(content):
            kind = (m.group(1) or "").lower()
            name = m.group(2) or "<anonymous>"
            body = m.group(3) or ""
            # Pull field names (first identifier on each line of the body).
            fields = re.findall(r'(?:^|[\s,{])([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*[{\n]', body)
            fields = sorted(set(fields))[:30]
            entry = {"name": name, "fields": fields}
            if kind == "query":
                queries.append(entry)
            elif kind == "mutation":
                mutations.append(entry)
            elif kind == "subscription":
                subscriptions.append(entry)

        endpoints = sorted(set(
            m.group(1) for m in GQL_ENDPOINT_RE.finditer(content)
            if _looks_like_endpoint(m.group(1))
        ))
        types_seen = sorted(set(GQL_TYPENAME_RE.findall(content)))

        return {
            "endpoints": endpoints,
            "queries": queries,
            "mutations": mutations,
            "subscriptions": subscriptions,
            "types_seen": types_seen,
        }

    def _extract_config(self, content):
        """Return list of {source, name, keys: {API_URL: ...}} entries."""
        results = []
        for pattern in CONFIG_BLOB_PATTERNS:
            for m in pattern.finditer(content):
                var_name = m.group(1)
                blob = m.group(2)
                # Try JSON first; otherwise fall back to regex key extraction.
                keys = {}
                try:
                    data = json.loads(blob)
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if isinstance(v, (str, int, float, bool)) and re.search(
                                    r'URL|HOST|ENDPOINT|KEY|ID|DSN|ENV|REGION|STAGE', k, re.I):
                                keys[k] = str(v)[:200]
                except Exception:
                    for km in CONFIG_KEY_RE.finditer(blob):
                        keys[km.group(1)] = km.group(2)
                # Also scan for keys outside pure JSON parsing (object literal syntax).
                if not keys:
                    for km in CONFIG_KEY_RE.finditer(blob):
                        keys[km.group(1)] = km.group(2)
                if keys:
                    results.append({"name": var_name, "keys": keys})
        return results

    def _detect_sourcemap_url(self, content, headers, js_url):
        """Prefer response header; fall back to // #sourceMappingURL comment."""
        for header in ("SourceMap", "X-SourceMap", "sourcemap", "x-sourcemap"):
            if header in headers and headers[header]:
                return urljoin(js_url, headers[header].strip())
        # Only look at the last 2KB -- that's where sourceMappingURL lives.
        tail = content[-4096:]
        m = SOURCEMAP_COMMENT_RE.search(tail)
        if m:
            ref = m.group(1).strip().strip("'\"")
            if ref.startswith("data:"):
                return None
            return urljoin(js_url, ref)
        return None

    def _fetch_sourcemap(self, map_url):
        """Fetch and parse a source map; return {map_url, sources_count, sources_sample}."""
        try:
            resp = http.get(map_url, timeout=15, verify=self._verify_tls)
            if resp.status_code >= 400:
                return None
            data = resp.json()
        except ValueError:
            # Not JSON, probably 404 HTML.
            return None
        except Exception as e:
            print_status(f"  source map fetch failed ({map_url}): {e}", "warning")
            return None

        sources = data.get("sources") if isinstance(data, dict) else None
        if not isinstance(sources, list):
            return None
        return {
            "map_url": map_url,
            "sources_count": len(sources),
            "sources_sample": [str(s) for s in sources[:20]],
            # Highlight the juiciest paths -- user homes, repo roots, Windows paths.
            "revealed_paths": sorted({
                str(s) for s in sources
                if isinstance(s, str) and re.search(r'(?:/Users/|/home/|C:\\|/opt/|/var/|/src/|webpack://)', s)
            })[:20],
        }

    # ---- Main pipeline ----------------------------------------------------

    def _scan_js(self, resp, url):
        """Full per-file extraction. Returns dict of findings."""
        content = resp.text if hasattr(resp, "text") else ""
        findings = {
            "secrets": self._extract_secrets(content, url),
            "endpoints_raw": self._extract_endpoints(content),
            "websocket": self._extract_websockets(content),
            "sse": self._extract_sse(content),
            "framework": self._extract_framework(content),
            "graphql": self._extract_graphql(content),
            "config": self._extract_config(content),
            "sourcemap_url": self._detect_sourcemap_url(content, resp.headers, url),
            "size": len(content),
        }
        return findings

    def _fetch_js(self, js_url, max_size):
        """Fetch a JS file with size cap. Returns a lightweight object with .text and .headers."""
        resp = http.get(js_url, timeout=15, verify=self._verify_tls, stream=True)
        content_length = int(resp.headers.get("Content-Length", 0) or 0)
        if content_length and content_length > max_size:
            resp.close()
            raise ValueError(f"too large: {content_length // 1024}KB")
        raw = resp.raw.read(max_size + 1, decode_content=True)
        headers = dict(resp.headers)
        resp.close()
        text = raw.decode("utf-8", errors="ignore")

        class _R:
            pass
        r = _R()
        r.text = text
        r.headers = headers
        return r

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        max_files = max(1, int(self.get_option("MAX_FILES") or 30))
        max_size = int(self.get_option("MAX_SIZE_KB") or 5000) * 1024
        self._verify_tls = self.get_option("VERIFY_TLS").lower() != "false"
        fetch_maps = self.get_option("FETCH_SOURCE_MAPS").lower() != "false"

        print_status(f"Scanning JavaScript files on {target}", "info")

        js_files = self._find_js_files(target)
        print_status(f"Found {len(js_files)} JavaScript files", "info")

        # Aggregates.
        all_secrets = []
        endpoints_by_category = {
            "rest": set(), "graphql": set(), "admin": set(),
            "auth": set(), "internal": set(), "other": set(),
            "websocket": set(),
        }
        graphql_agg = {
            "endpoints": set(),
            "queries": [],
            "mutations": [],
            "subscriptions": [],
            "types_seen": set(),
        }
        source_maps = []
        framework_agg = {}
        config_blobs = []
        scanned = 0
        total_endpoints = 0

        files_to_scan = js_files[:max_files]
        for idx, js_url in enumerate(files_to_scan, start=1):
            fname = js_url.split('/')[-1].split('?')[0] or js_url
            try:
                try:
                    resp = self._fetch_js(js_url, max_size)
                except ValueError as e:
                    print_status(f"[{idx}/{len(files_to_scan)}] skipping {fname} ({e})", "warning")
                    continue

                findings = self._scan_js(resp, js_url)
                size_kb = findings["size"] // 1024

                # ---- Secrets ----
                all_secrets.extend(findings["secrets"])
                for s in findings["secrets"]:
                    print_status(
                        f"  {Colors.RED}[SECRET]{Colors.RESET} {s['type']}: {s['value'][:60]}",
                        "success"
                    )

                # ---- Endpoints (classify + dedup) ----
                file_ep_count = 0
                seen_file = set()
                for raw_ep in findings["endpoints_raw"]:
                    if raw_ep in seen_file:
                        continue
                    seen_file.add(raw_ep)
                    cat, norm = _classify_endpoint(raw_ep)
                    endpoints_by_category[cat].add(norm)
                    file_ep_count += 1

                # WebSocket / SSE both routed to the websocket bucket, but SSE kept too.
                ws_count = 0
                for w in findings["websocket"]:
                    endpoints_by_category["websocket"].add(w)
                    ws_count += 1
                for w in findings["sse"]:
                    endpoints_by_category["websocket"].add(w)
                    ws_count += 1
                total_endpoints += file_ep_count

                # ---- GraphQL aggregation ----
                gql = findings["graphql"]
                graphql_agg["endpoints"].update(gql["endpoints"])
                graphql_agg["queries"].extend(gql["queries"])
                graphql_agg["mutations"].extend(gql["mutations"])
                graphql_agg["subscriptions"].extend(gql["subscriptions"])
                graphql_agg["types_seen"].update(gql["types_seen"])

                # ---- Framework routes ----
                for fw, routes in findings["framework"].items():
                    framework_agg.setdefault(fw, set()).update(routes)

                # ---- Config blobs ----
                for cb in findings["config"]:
                    config_blobs.append({"source": js_url, **cb})

                # ---- Source maps ----
                sm_note = ""
                if findings["sourcemap_url"]:
                    if fetch_maps:
                        sm = self._fetch_sourcemap(findings["sourcemap_url"])
                        if sm:
                            sm["js_url"] = js_url
                            source_maps.append(sm)
                            sm_note = f", {Colors.RED}{Colors.BOLD}1 source map{Colors.RESET}"
                            print_status(
                                f"  {Colors.RED}{Colors.BOLD}[SOURCE MAP]{Colors.RESET} "
                                f"{findings['sourcemap_url']} -- "
                                f"revealed {Colors.RED}{sm['sources_count']} original file paths{Colors.RESET}",
                                "success"
                            )
                            # Preview the two juiciest paths.
                            for pth in sm["revealed_paths"][:3]:
                                print_status(f"      {Colors.DIM}>{Colors.RESET} {pth}", "info")
                        else:
                            sm_note = f", {Colors.YELLOW}sourcemap link (fetch failed){Colors.RESET}"
                    else:
                        source_maps.append({
                            "js_url": js_url,
                            "map_url": findings["sourcemap_url"],
                            "sources_count": None,
                            "sources_sample": [],
                            "revealed_paths": [],
                            "note": "FETCH_SOURCE_MAPS=false",
                        })
                        sm_note = f", {Colors.YELLOW}sourcemap link{Colors.RESET}"

                scanned += 1

                # Per-file one-liner summary (requested format).
                print_status(
                    f"[{idx}/{len(files_to_scan)}] {Colors.BOLD}{fname}{Colors.RESET} "
                    f"({size_kb}KB): "
                    f"{Colors.RED if findings['secrets'] else Colors.DIM}"
                    f"{len(findings['secrets'])} secrets{Colors.RESET}, "
                    f"{Colors.CYAN}{file_ep_count} endpoints{Colors.RESET}"
                    f"{(', ' + Colors.MAGENTA + str(ws_count) + ' ws/sse' + Colors.RESET) if ws_count else ''}"
                    f"{sm_note}",
                    "info"
                )

            except Exception as e:
                print_status(f"Error scanning {js_url}: {e}", "warning")

        # ---- Dedup graphql queries/mutations/subscriptions by name ----
        def _dedup_by_name(items):
            seen = {}
            for it in items:
                key = it.get("name") or "<anonymous>"
                if key not in seen:
                    seen[key] = it
                else:
                    # Merge field lists.
                    merged = sorted(set((seen[key].get("fields") or []) + (it.get("fields") or [])))
                    seen[key]["fields"] = merged
            return list(seen.values())

        graphql_out = {
            "endpoints": sorted(graphql_agg["endpoints"]),
            "queries": _dedup_by_name(graphql_agg["queries"]),
            "mutations": _dedup_by_name(graphql_agg["mutations"]),
            "subscriptions": _dedup_by_name(graphql_agg["subscriptions"]),
            "types_seen": sorted(graphql_agg["types_seen"]),
        }

        endpoints_out = {k: sorted(v) for k, v in endpoints_by_category.items()}
        framework_out = {k: sorted(v) for k, v in framework_agg.items()}

        self.results = {
            "target": target,
            "js_files_found": len(js_files),
            "js_files_scanned": scanned,
            "secrets": all_secrets,
            "endpoints": endpoints_out,
            "graphql_schema": graphql_out,
            "source_maps": source_maps,
            "framework_endpoints": framework_out,
            "config_blobs": config_blobs,
            "stats": {
                "files_scanned": scanned,
                "total_endpoints": sum(len(v) for v in endpoints_out.values()),
                "total_secrets": len(all_secrets),
                "source_maps_found": len(source_maps),
                "graphql_queries": len(graphql_out["queries"]),
                "graphql_mutations": len(graphql_out["mutations"]),
                "websocket_targets": len(endpoints_out["websocket"]),
                "frameworks_detected": sorted(framework_out.keys()),
                "config_blobs": len(config_blobs),
            },
        }

        # ---- Final summary ----
        print()
        print_status(f"{Colors.BOLD}=== JS Scan Summary ==={Colors.RESET}", "info")
        print_status(f"  Files: {scanned}/{len(js_files)} scanned", "info")
        if all_secrets:
            print_status(
                f"  {Colors.RED}{Colors.BOLD}Secrets:{Colors.RESET} {len(all_secrets)} "
                f"({', '.join(sorted({s['type'] for s in all_secrets}))})",
                "warning"
            )
        else:
            print_status(f"  Secrets: 0", "info")

        print_status(f"  {Colors.CYAN}Endpoints by category:{Colors.RESET}", "info")
        for cat in ("rest", "graphql", "admin", "auth", "internal", "websocket", "other"):
            n = len(endpoints_out.get(cat, []))
            if n:
                color = Colors.RED if cat in ("admin", "internal") else Colors.CYAN
                print_status(f"      {color}{cat:<10}{Colors.RESET}: {n}", "info")

        if graphql_out["queries"] or graphql_out["mutations"] or graphql_out["endpoints"]:
            print_status(
                f"  {Colors.MAGENTA}GraphQL:{Colors.RESET} "
                f"{len(graphql_out['queries'])} queries, "
                f"{len(graphql_out['mutations'])} mutations, "
                f"{len(graphql_out['subscriptions'])} subscriptions, "
                f"{len(graphql_out['endpoints'])} endpoints, "
                f"{len(graphql_out['types_seen'])} types",
                "info"
            )

        if source_maps:
            total_paths = sum((sm.get("sources_count") or 0) for sm in source_maps)
            print_status(
                f"  {Colors.RED}{Colors.BOLD}Source maps:{Colors.RESET} "
                f"{len(source_maps)} ({total_paths} original paths revealed)",
                "warning"
            )

        if framework_out:
            print_status(
                f"  Frameworks detected: {Colors.GREEN}{', '.join(framework_out.keys())}{Colors.RESET}",
                "info"
            )

        if config_blobs:
            print_status(
                f"  Config blobs: {len(config_blobs)} "
                f"({sum(len(c['keys']) for c in config_blobs)} interesting keys)",
                "info"
            )

        return True
