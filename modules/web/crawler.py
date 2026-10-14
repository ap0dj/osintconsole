"""Deep web crawler for OSINT reconnaissance.

Pure manual, no-API crawling: BFS over same-host pages, deep per-page
extraction (forms, hidden inputs, comments, meta, emails, phones, socials),
JavaScript endpoint mining via regex, robots/sitemap seeding, and per-depth
progress reporting.
"""
import re
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
from xml.etree import ElementTree as ET
from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.config import Config
from core import http


# ---------------------------------------------------------------------------
# Regex library (compiled once).
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
# International phone - +CC then 8-14 more digits (allowing separators)
PHONE_RE = re.compile(r'(?<![\w\d])\+?\d{1,3}[\s\-\.]?\(?\d{1,4}\)?[\s\-\.]?\d{2,4}[\s\-\.]?\d{2,4}(?:[\s\-\.]?\d{1,4})?(?![\w\d])')
SOCIAL_HANDLE_RE = re.compile(r'(?<![\w@/])@([A-Za-z0-9_]{2,30})(?![\w])')
HTML_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)

# JS endpoint harvesting - quoted string literals that look like URLs/paths
JS_ENDPOINT_RE = re.compile(
    r'["\']((?:/|https?://)[a-zA-Z0-9_\-./:]+(?:\?[a-zA-Z0-9_\-?&=.%+]*)?)["\']'
)
JS_FETCH_RE = re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']')
JS_AXIOS_RE = re.compile(r'axios\.(?:get|post|put|delete|patch|request)\s*\(\s*["\']([^"\']+)["\']')
JS_XHR_OPEN_RE = re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH|HEAD)["\']\s*,\s*["\']([^"\']+)["\']', re.I)
JS_WS_RE = re.compile(r'["\'](wss?://[^"\']+)["\']')
JS_GRAPHQL_RE = re.compile(r'(query|mutation|subscription)\s+(\w+)?\s*(?:\([^)]*\))?\s*\{', re.IGNORECASE)
JS_ROUTE_RE = re.compile(r'(?:router|app|route)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*["\']([^"\']+)["\']', re.I)

# Hint tokens that mark a URL as "probably an endpoint"
ENDPOINT_HINTS = (
    "/api/", "/api.", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/",
    "/graphql", "/gql", "/admin", "/auth", "/login", "/logout",
    "/signup", "/register", "/user", "/users", "/account", "/me",
    "/oauth", "/token", "/session", "/upload", "/download",
    "/search", "/query", "/data", "/json", "/.json", "/ajax",
    "/webhook", "/callback", "/notify", "/rpc", "/service", "/svc",
    "/internal", "/private", "/dashboard", "/management",
)
# Static assets we don't crawl as HTML pages.
STATIC_EXT = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".exe", ".dmg",
)


class Crawler(BaseModule):
    name = "web/crawler"
    description = "Deep web crawler: forms, endpoints, JS, comments, OSINT"
    category = "web"
    target_type = "domain/url"

    # ------------------------------------------------------------------
    # Options
    # ------------------------------------------------------------------
    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        # Legacy knob kept for backward compat; MAX_DEPTH overrides when set.
        self.add_option("DEPTH", "2", False, "Legacy depth alias (prefer MAX_DEPTH)")
        self.add_option("MAX_DEPTH", "2", False, "Maximum crawl depth (BFS)")
        self.add_option("MAX_PAGES", "50", False, "Maximum pages to fetch")
        self.add_option("SAME_HOST_ONLY", "true", False, "Restrict crawl to the seed host")
        self.add_option("JS_SCAN", "true", False, "Download and mine linked .js files")
        self.add_option("MAX_JS_FILES", "25", False, "Cap on JS files fetched")
        self.add_option("RESPECT_ROBOTS", "false", False, "Honor robots.txt Disallow (default off: OSINT mode)")
        self.add_option("USE_SITEMAP", "true", False, "Seed queue from robots.txt + sitemaps")
        self.add_option("TIMEOUT", "10", False, "Per-request timeout seconds")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs")

    # ------------------------------------------------------------------
    # URL utilities
    # ------------------------------------------------------------------
    @staticmethod
    def _canonical(url):
        """Deduplication-friendly URL form: lowercase scheme/host, no fragment,
        sorted query params, no trailing slash on paths."""
        try:
            p = urlparse(url)
        except Exception:
            return url
        scheme = (p.scheme or "http").lower()
        netloc = p.netloc.lower()
        path = p.path or "/"
        # Collapse duplicate slashes but preserve a leading one.
        path = re.sub(r"/{2,}", "/", path)
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        try:
            q = sorted(parse_qsl(p.query, keep_blank_values=True))
            query = urlencode(q, doseq=True)
        except Exception:
            query = p.query
        return urlunparse((scheme, netloc, path, "", query, ""))

    @staticmethod
    def _looks_static(url):
        path = urlparse(url).path.lower()
        return path.endswith(STATIC_EXT)

    @staticmethod
    def _strip_www(host):
        # Not lstrip("www."): that strips any leading run of 'w'/'.' chars, so
        # wax.com -> ax.com and the crawler would wander off onto ax.com.
        return host[4:] if host.startswith("www.") else host

    @staticmethod
    def _same_host(a, b):
        ha = urlparse(a).netloc.lower()
        hb = urlparse(b).netloc.lower()
        if not ha or not hb:
            return False
        # treat www.example.com and example.com as same host
        return Crawler._strip_www(ha) == Crawler._strip_www(hb)

    # ------------------------------------------------------------------
    # Content extraction helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_form(action, inputs):
        names = {(i.get("name") or "").lower() for i in inputs}
        types = {(i.get("type") or "").lower() for i in inputs}
        action_l = (action or "").lower()
        has_pw = "password" in types
        has_file = "file" in types
        has_email = "email" in types or any("email" in n or "mail" in n for n in names)
        has_user = any(n in names for n in ("username", "user", "login", "userid", "uid"))
        has_confirm = any("confirm" in n or "repeat" in n or n.endswith("2") for n in names)
        text_inputs = sum(1 for i in inputs if (i.get("type") or "text").lower() in ("text", "email", "tel", "url"))

        if "admin" in action_l or "manage" in action_l or any("admin" in n for n in names):
            return "admin"
        if has_pw and has_confirm and (has_email or has_user):
            return "signup"
        if has_pw and (has_user or has_email):
            return "login"
        if has_file:
            return "upload"
        if ("reset" in action_l or "forgot" in action_l) and has_email:
            return "password_reset"
        if has_email and not has_pw and text_inputs <= 1:
            return "newsletter"
        if any(n in names for n in ("q", "query", "search", "s", "keyword")) and text_inputs == 1 and not has_pw:
            return "search"
        if any(i.get("type", "") == "textarea" for i in inputs) and (has_email or text_inputs >= 2):
            return "contact"
        return "unknown"

    def _extract_forms(self, soup, page_url):
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action", "") or page_url)
            method = (form.get("method") or "GET").upper()
            inputs = []
            for el in form.find_all(["input", "textarea", "select"]):
                tag = el.name
                itype = (el.get("type") or ("textarea" if tag == "textarea" else "text")).lower()
                inputs.append({
                    "tag": tag,
                    "type": itype,
                    "name": el.get("name") or "",
                    "value": (el.get("value") or "")[:200],
                    "placeholder": el.get("placeholder") or "",
                    "required": el.has_attr("required"),
                })
            forms.append({
                "url": page_url,
                "action": action,
                "method": method,
                "classification": self._classify_form(action, inputs),
                "inputs": inputs,
            })
        return forms

    @staticmethod
    def _extract_meta(soup):
        meta = {}
        for m in soup.find_all("meta"):
            key = (m.get("name") or m.get("property") or m.get("http-equiv") or "").lower()
            if not key:
                continue
            val = m.get("content") or ""
            if val:
                meta[key] = val[:400]
        return meta

    @staticmethod
    def _extract_hidden_inputs(soup, page_url):
        out = []
        for inp in soup.find_all("input"):
            if (inp.get("type") or "").lower() == "hidden":
                out.append({
                    "url": page_url,
                    "name": inp.get("name") or "",
                    "value": (inp.get("value") or "")[:300],
                })
        return out

    @staticmethod
    def _extract_comments(html, page_url):
        found = []
        for raw in HTML_COMMENT_RE.findall(html):
            txt = raw.strip()
            if 5 <= len(txt) <= 2000 and not txt.lower().startswith(("[if", "<![")):
                found.append({"url": page_url, "comment": txt[:400]})
        return found

    @staticmethod
    def _collect_resource_urls(soup, page_url):
        """Return (links, js_srcs, assets) where assets covers img/iframe/link."""
        links, js_srcs, assets = set(), set(), set()
        for a in soup.find_all("a", href=True):
            links.add(urljoin(page_url, a["href"]))
        for s in soup.find_all("script", src=True):
            js_srcs.add(urljoin(page_url, s["src"]))
        for l in soup.find_all("link", href=True):
            assets.add(urljoin(page_url, l["href"]))
        for img in soup.find_all("img", src=True):
            assets.add(urljoin(page_url, img["src"]))
        for frame in soup.find_all(["iframe", "frame"], src=True):
            assets.add(urljoin(page_url, frame["src"]))
        return links, js_srcs, assets

    # ------------------------------------------------------------------
    # JavaScript mining
    # ------------------------------------------------------------------
    @staticmethod
    def _is_endpointish(url):
        low = url.lower()
        if any(low.endswith(ext) for ext in STATIC_EXT):
            return False
        if len(low) > 400:
            return False
        return any(hint in low for hint in ENDPOINT_HINTS)

    def _mine_js(self, text, base_url=""):
        """Return dict of findings from a JS blob (inline or external)."""
        endpoints = set()
        graphql_ops = set()
        websockets = set()

        for m in JS_ENDPOINT_RE.findall(text):
            m = m.strip()
            if 3 <= len(m) <= 300 and not m.startswith(("//cdn", "//fonts")):
                endpoints.add(m)
        for m in JS_FETCH_RE.findall(text):
            endpoints.add(m.strip())
        for m in JS_AXIOS_RE.findall(text):
            endpoints.add(m.strip())
        for m in JS_XHR_OPEN_RE.findall(text):
            endpoints.add(m.strip())
        for m in JS_ROUTE_RE.findall(text):
            endpoints.add(m.strip())
        for m in JS_WS_RE.findall(text):
            websockets.add(m.strip())
        for kind, name in JS_GRAPHQL_RE.findall(text):
            graphql_ops.add(f"{kind.lower()}:{name or '<anonymous>'}")

        # Filter endpoints: resolve to absolute if we have a base, then keep only
        # URLs that look like endpoints.
        kept = set()
        for ep in endpoints:
            if ep.startswith("//"):
                ep = "https:" + ep
            if ep.startswith("/") and base_url:
                try:
                    ep = urljoin(base_url, ep)
                except Exception:
                    pass
            if self._is_endpointish(ep):
                kept.add(ep)
        return {
            "endpoints": kept,
            "graphql": graphql_ops,
            "websockets": websockets,
        }

    # ------------------------------------------------------------------
    # robots.txt + sitemap seeding
    # ------------------------------------------------------------------
    def _fetch_text(self, url, timeout, verify_tls):
        try:
            r = http.get(url, timeout=timeout, verify=verify_tls, allow_redirects=True)
            if r.status_code == 200 and r.text:
                return r.text
        except Exception:
            return None
        return None

    def _parse_robots(self, text, base):
        disallowed, allowed, sitemaps = [], [], []
        if not text:
            return disallowed, allowed, sitemaps
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key, val = key.strip().lower(), val.strip()
            if key == "disallow" and val and val != "/":
                disallowed.append(urljoin(base, val.split()[0]))
            elif key == "allow" and val:
                allowed.append(urljoin(base, val.split()[0]))
            elif key == "sitemap" and val:
                sitemaps.append(val.split()[0])
        return disallowed, allowed, sitemaps

    def _parse_sitemap(self, text):
        urls, nested = [], []
        if not text:
            return urls, nested
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            # Fallback regex for broken XML.
            return re.findall(r"<loc>\s*([^<]+?)\s*</loc>", text, re.I), []
        tag = root.tag.lower()
        for loc in root.iter():
            if loc.tag.lower().endswith("loc") and loc.text:
                u = loc.text.strip()
                if "sitemapindex" in tag:
                    nested.append(u)
                else:
                    urls.append(u)
        return urls, nested

    def _seed_from_robots_and_sitemap(self, base, timeout, verify_tls):
        """Return (seed_urls, disallowed_from_robots, sitemaps_seen, warnings)."""
        seeds = []
        disallowed_total = []
        sitemaps_seen = []
        warnings = []

        robots_url = urljoin(base, "/robots.txt")
        robots_text = self._fetch_text(robots_url, timeout, verify_tls)
        if robots_text:
            disallowed, allowed, sitemaps = self._parse_robots(robots_text, base)
            disallowed_total.extend(disallowed)
            seeds.extend(disallowed)
            seeds.extend(allowed)
            seeds.extend(sitemaps)
            print_status(
                f"robots.txt -> {len(disallowed)} disallow, "
                f"{len(allowed)} allow, {len(sitemaps)} sitemap(s)",
                "success",
            )
        else:
            warnings.append("robots.txt not available")

        candidate_sitemaps = [
            urljoin(base, "/sitemap.xml"),
            urljoin(base, "/sitemap_index.xml"),
            urljoin(base, "/sitemap1.xml"),
            urljoin(base, "/post-sitemap.xml"),
            urljoin(base, "/page-sitemap.xml"),
            urljoin(base, "/sitemap-news.xml"),
        ]
        visited_sitemaps = set()
        queue = list(candidate_sitemaps)
        hops = 0
        while queue and hops < 15:
            sm = queue.pop(0)
            if sm in visited_sitemaps:
                continue
            visited_sitemaps.add(sm)
            hops += 1
            text = self._fetch_text(sm, timeout, verify_tls)
            if not text:
                continue
            sitemaps_seen.append(sm)
            urls, nested = self._parse_sitemap(text)
            seeds.extend(urls)
            queue.extend(nested)
        if sitemaps_seen:
            print_status(
                f"sitemap seeds: {sum(1 for _ in sitemaps_seen)} map(s), "
                f"{len(seeds)} candidate url(s)",
                "success",
            )
        return seeds, disallowed_total, sitemaps_seen, warnings

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        # ---- resolve options -----------------------------------------
        target = (self.get_option("TARGET") or "").strip()
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        target = target.rstrip("/")

        def _int(opt, default):
            raw = str(self.get_option(opt) or "").strip()
            return int(raw) if raw.lstrip("-").isdigit() else default

        def _bool(opt, default):
            raw = str(self.get_option(opt) or "").strip().lower()
            if not raw:
                return default
            return raw in ("1", "true", "yes", "y", "on")

        max_depth = _int("MAX_DEPTH", _int("DEPTH", 2))
        max_pages = max(1, _int("MAX_PAGES", 50))
        same_host_only = _bool("SAME_HOST_ONLY", True)
        js_scan = _bool("JS_SCAN", True)
        max_js = max(0, _int("MAX_JS_FILES", 25))
        respect_robots = _bool("RESPECT_ROBOTS", False)
        use_sitemap = _bool("USE_SITEMAP", True)
        timeout = _int("TIMEOUT", int(Config().get("timeout", 10)))
        verify_tls = _bool("VERIFY_TLS", True)

        print_status(
            f"{Colors.BOLD}Deep crawl{Colors.RESET} {Colors.CYAN}{target}{Colors.RESET} "
            f"(depth={max_depth}, max_pages={max_pages}, "
            f"same_host={same_host_only}, js={js_scan})",
            "info",
        )

        # ---- state ---------------------------------------------------
        base = target
        seed_canon = self._canonical(target)
        queue = deque([(target, 0)])
        enqueued = {seed_canon}
        visited_canon = set()

        pages_meta = []
        all_forms = []
        all_hidden_inputs = []
        all_comments = []
        meta_tags = {}
        emails = set()
        phones = set()
        socials = {"twitter": set(), "instagram": set(), "github": set(), "generic": set()}
        js_files = set()
        js_endpoints = set()
        graphql_ops = set()
        websocket_urls = set()
        external_links = set()
        internal_links = set()
        assets = set()
        warnings = []
        disallowed_paths = []
        depth_stats = {}

        start = time.time()

        # ---- robots.txt + sitemap seed -------------------------------
        if use_sitemap:
            seeds, disallowed_paths, sitemaps_seen, w = self._seed_from_robots_and_sitemap(
                base, timeout, verify_tls
            )
            warnings.extend(w)
            for s in seeds:
                if self._looks_static(s):
                    continue
                cs = self._canonical(s)
                if cs in enqueued:
                    continue
                if same_host_only and not self._same_host(base, s):
                    continue
                queue.append((s, 1))
                enqueued.add(cs)

        robots_disallowed_canon = {self._canonical(u) for u in disallowed_paths} if respect_robots else set()

        # ---- BFS -----------------------------------------------------
        max_depth_reached = 0
        while queue and len(visited_canon) < max_pages:
            url, depth = queue.popleft()
            curl = self._canonical(url)
            if curl in visited_canon:
                continue
            if depth > max_depth:
                continue
            if respect_robots and curl in robots_disallowed_canon:
                warnings.append(f"skipped by robots: {url}")
                continue
            if self._looks_static(url):
                continue

            try:
                resp = http.get(url, timeout=timeout, verify=verify_tls, allow_redirects=True)
            except Exception as exc:
                warnings.append(f"fetch error {url}: {exc.__class__.__name__}")
                continue

            visited_canon.add(curl)
            max_depth_reached = max(max_depth_reached, depth)
            depth_stats.setdefault(depth, {"pages": 0, "forms": 0, "endpoints": 0})
            depth_stats[depth]["pages"] += 1

            ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            page_record = {
                "url": url,
                "status": resp.status_code,
                "title": "",
                "content_type": ctype,
                "depth": depth,
                "size": len(resp.content or b""),
            }

            if "html" not in ctype and not ctype.startswith("application/xhtml"):
                pages_meta.append(page_record)
                continue

            html_text = resp.text or ""
            soup = BeautifulSoup(html_text, "html.parser")
            if soup.title and soup.title.string:
                page_record["title"] = soup.title.string.strip()[:200]
            pages_meta.append(page_record)

            # Forms
            forms = self._extract_forms(soup, url)
            all_forms.extend(forms)
            depth_stats[depth]["forms"] += len(forms)

            # Meta tags
            page_meta = self._extract_meta(soup)
            if page_meta:
                meta_tags[url] = page_meta

            # Hidden inputs
            all_hidden_inputs.extend(self._extract_hidden_inputs(soup, url))

            # Comments
            all_comments.extend(self._extract_comments(html_text, url))

            # Resource URLs
            links, js_srcs, more_assets = self._collect_resource_urls(soup, url)
            assets.update(more_assets)

            # <noscript> content occasionally hides fallback endpoints
            for ns in soup.find_all("noscript"):
                text = ns.get_text(" ", strip=True)
                for m in re.findall(r'https?://[^\s"\'<>]+', text):
                    (external_links if not self._same_host(base, m) else internal_links).add(m)

            # Inline scripts: mine endpoints before enqueueing externals
            inline_findings_count = 0
            for script in soup.find_all("script"):
                if script.get("src"):
                    continue
                body = script.string or script.get_text() or ""
                if not body or len(body) < 20:
                    continue
                mined = self._mine_js(body, base_url=url)
                js_endpoints.update(mined["endpoints"])
                graphql_ops.update(mined["graphql"])
                websocket_urls.update(mined["websockets"])
                inline_findings_count += len(mined["endpoints"])
            depth_stats[depth]["endpoints"] += inline_findings_count

            # Link harvest
            for href in links:
                href_clean = href.split("#")[0]
                parsed = urlparse(href_clean)
                if parsed.scheme not in ("http", "https"):
                    continue
                same = self._same_host(base, href_clean)
                if same:
                    internal_links.add(href_clean)
                else:
                    external_links.add(href_clean)
                if same_host_only and not same:
                    continue
                if self._looks_static(href_clean):
                    continue
                ch = self._canonical(href_clean)
                if ch in enqueued or ch in visited_canon:
                    continue
                if depth + 1 > max_depth:
                    continue
                enqueued.add(ch)
                queue.append((href_clean, depth + 1))

            # External JS: queue for later mining
            for js_url in js_srcs:
                if same_host_only and not self._same_host(base, js_url):
                    continue
                js_files.add(js_url)

            # Entity extraction from raw HTML (catches text + attrs)
            for em in EMAIL_RE.findall(html_text):
                emails.add(em.lower())
            for ph in PHONE_RE.findall(html_text):
                digits = re.sub(r"\D", "", ph)
                if 10 <= len(digits) <= 15:
                    phones.add(ph.strip())

            # Social handles - scan links + visible text to attribute platform
            for a in soup.find_all("a", href=True):
                href_l = a["href"].lower()
                if "twitter.com/" in href_l or "x.com/" in href_l:
                    m = re.search(r"(?:twitter|x)\.com/([A-Za-z0-9_]{2,30})", href_l)
                    if m:
                        socials["twitter"].add(m.group(1))
                elif "instagram.com/" in href_l:
                    m = re.search(r"instagram\.com/([A-Za-z0-9_.]{2,30})", href_l)
                    if m:
                        socials["instagram"].add(m.group(1))
                elif "github.com/" in href_l:
                    m = re.search(r"github\.com/([A-Za-z0-9_\-]{1,39})", href_l)
                    if m:
                        socials["github"].add(m.group(1))
            visible = soup.get_text(" ", strip=True)
            for handle in SOCIAL_HANDLE_RE.findall(visible):
                socials["generic"].add(handle)

            print_status(
                f"[d{depth}] {url} -> {len(forms)} forms, {len(links)} links, "
                f"{len(js_srcs)} scripts, {inline_findings_count} inline eps",
                "success",
            )

        # ---- JS mining (external) ------------------------------------
        if js_scan and js_files:
            print_status(
                f"Mining {min(len(js_files), max_js)}/{len(js_files)} external JS files...",
                "info",
            )
            fetched = 0
            for js_url in sorted(js_files):
                if fetched >= max_js:
                    break
                try:
                    r = http.get(js_url, timeout=timeout, verify=verify_tls, allow_redirects=True)
                except Exception as exc:
                    warnings.append(f"js fetch error {js_url}: {exc.__class__.__name__}")
                    continue
                if r.status_code != 200 or not r.text:
                    continue
                mined = self._mine_js(r.text, base_url=js_url)
                js_endpoints.update(mined["endpoints"])
                graphql_ops.update(mined["graphql"])
                websocket_urls.update(mined["websockets"])
                fetched += 1

        # ---- per-depth summary --------------------------------------
        for d in sorted(depth_stats):
            st = depth_stats[d]
            print_status(
                f"{Colors.BOLD}[depth {d}]{Colors.RESET} crawled "
                f"{Colors.GREEN}{st['pages']}{Colors.RESET} pages, found "
                f"{Colors.YELLOW}{st['forms']}{Colors.RESET} forms, "
                f"{Colors.CYAN}{st['endpoints']}{Colors.RESET} endpoints",
                "info",
            )

        duration = round(time.time() - start, 2)

        # ---- compile results ----------------------------------------
        self.results = {
            "target": target,
            "pages_crawled": len(visited_canon),
            "max_depth_reached": max_depth_reached,
            "duration_sec": duration,
            "pages": pages_meta,
            "forms": all_forms,
            "endpoints_from_js": sorted(js_endpoints),
            "graphql_operations": sorted(graphql_ops),
            "websocket_urls": sorted(websocket_urls),
            "emails": sorted(emails),
            "phones": sorted(phones),
            "social_handles": {k: sorted(v) for k, v in socials.items()},
            "comments": all_comments[:200],
            "hidden_inputs": all_hidden_inputs,
            "meta_tags": meta_tags,
            "internal_links": sorted(internal_links),
            "external_links": sorted(external_links),
            "assets": sorted(assets),
            "js_files": sorted(js_files),
            "robots_disallowed": sorted(disallowed_paths),
            "warnings": warnings[-50:],
            # Back-compat aliases from the previous shape:
            "emails_found": sorted(emails),
            "html_comments": all_comments[:50],
            "total_internal": len(internal_links),
            "total_external": len(external_links),
        }

        form_classes = {}
        for f in all_forms:
            form_classes[f["classification"]] = form_classes.get(f["classification"], 0) + 1
        class_summary = ", ".join(f"{v} {k}" for k, v in sorted(form_classes.items())) or "0"

        print_status(
            f"Done in {duration}s: {len(visited_canon)} pages, "
            f"{len(all_forms)} forms ({class_summary}), "
            f"{len(js_endpoints)} JS endpoints, {len(emails)} emails",
            "info",
        )
        return True
