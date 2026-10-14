"""robots.txt / sitemap.xml / .well-known / feed / API-doc discovery.

Comprehensive passive reconnaissance against a target's advertised metadata
surface:
  * robots.txt   - parses user-agents, allow/disallow, declared sitemaps
  * sitemaps     - probes common filenames + follows sitemap indexes (depth 2)
  * .well-known  - probes RFC 8615 standard paths and extracts structured fields
  * feeds        - RSS / Atom / WP REST
  * api docs     - OpenAPI / Swagger

Each probe is isolated in try/except; .well-known / feeds / api-docs probes
run concurrently through a ThreadPoolExecutor.
"""
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from core.base_module import BaseModule
from core.utils import print_status
from core import http


SITEMAP_NS = {
    "sm": "http://www.sitemaps.org/schemas/sitemap/0.9",
    "news": "http://www.google.com/schemas/sitemap-news/0.9",
    "image": "http://www.google.com/schemas/sitemap-image/1.1",
    "video": "http://www.google.com/schemas/sitemap-video/1.1",
}

# Default sitemap paths probed when robots.txt lists none (or in addition).
DEFAULT_SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemap.xml.gz",
    "/sitemap-news.xml",
    "/sitemap-images.xml",
    "/sitemap-image.xml",
    "/sitemap-video.xml",
    "/sitemap-posts.xml",
    "/sitemap-pages.xml",
    # WordPress common
    "/post-sitemap.xml",
    "/page-sitemap.xml",
    "/category-sitemap.xml",
    "/author-sitemap.xml",
    "/tag-sitemap.xml",
    "/product-sitemap.xml",
    # Shopify
    "/sitemap_products_1.xml",
    "/sitemap_pages_1.xml",
    "/sitemap_collections_1.xml",
    "/sitemap_blogs_1.xml",
]
# Numbered sitemaps 1..10
DEFAULT_SITEMAP_PATHS += [f"/sitemap{i}.xml" for i in range(1, 11)]

# .well-known catalog with a per-path classification tag.
WELL_KNOWN_PATHS = [
    ("/.well-known/security.txt", "security_txt"),
    ("/.well-known/change-password", "change_password"),
    ("/.well-known/openid-configuration", "openid_config"),
    ("/.well-known/oauth-authorization-server", "oauth_server"),
    ("/.well-known/webfinger", "webfinger"),
    ("/.well-known/host-meta", "host_meta"),
    ("/.well-known/host-meta.json", "host_meta_json"),
    ("/.well-known/apple-app-site-association", "apple_app_site_association"),
    ("/.well-known/assetlinks.json", "assetlinks"),
    ("/.well-known/matrix/client", "matrix_client"),
    ("/.well-known/matrix/server", "matrix_server"),
    ("/.well-known/mta-sts.txt", "mta_sts"),
    ("/.well-known/jwks.json", "jwks"),
    ("/.well-known/openpgpkey/hu/", "openpgpkey"),
    ("/.well-known/discovery", "discovery"),
    ("/.well-known/caldav", "caldav"),
    ("/.well-known/carddav", "carddav"),
    ("/.well-known/dnt-policy.txt", "dnt_policy"),
    ("/.well-known/nodeinfo", "nodeinfo"),
    ("/.well-known/trust.txt", "trust_txt"),
]

FEED_PATHS = [
    "/rss.xml", "/feed.xml", "/atom.xml",
    "/feed", "/rss", "/atom",
    "/feed.rss", "/feeds/all.rss",
    "/wp-json/wp/v2/posts",
]

API_DOC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api/docs", "/api-docs", "/docs",
    "/swagger-ui.html", "/swagger-ui/", "/redoc",
    "/v1/openapi.json", "/v2/api-docs", "/v3/api-docs",
]

INTERESTING_KEYWORDS = [
    "admin", "api", "backup", "config", "database", "db", "debug",
    "dev", "internal", "login", "manage", "panel", "private",
    "secret", "staging", "test", "tmp", "upload", "wp-admin",
    "console", "git",
]


class RobotsSitemap(BaseModule):
    name = "web/robots_sitemap"
    description = ("Parse robots.txt, sitemaps, .well-known/* paths, feeds "
                   "and API docs for a target domain")
    category = "web"
    target_type = "domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain or URL")
        self.add_option("PARSE_SITEMAPS", "true", False,
                        "Follow and parse linked sitemaps")
        self.add_option("FOLLOW_SITEMAP_INDEX", "true", False,
                        "Recurse into sitemap index files (max depth 2)")
        self.add_option("WELL_KNOWN_PROBE", "true", False,
                        "Probe .well-known/* standard paths")
        self.add_option("FEED_PROBE", "true", False,
                        "Probe RSS/Atom/WP REST feed paths")
        self.add_option("API_DOC_PROBE", "true", False,
                        "Probe OpenAPI/Swagger documentation paths")
        self.add_option("MAX_SITEMAP_URLS", "5000", False,
                        "Safety cap for total URLs harvested from sitemaps")
        self.add_option("THREADS", "10", False,
                        "Parallel workers for probe fan-out")

    # ------------------------------------------------------------------ #
    # helpers                                                             #
    # ------------------------------------------------------------------ #
    def _bool_opt(self, name):
        return str(self.get_option(name)).strip().lower() == "true"

    def _int_opt(self, name, default):
        try:
            return int(self.get_option(name))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_json(resp):
        try:
            return resp.json()
        except Exception:
            try:
                return json.loads(resp.text)
            except Exception:
                return None

    @staticmethod
    def _is_200(resp):
        return resp is not None and getattr(resp, "status_code", 0) == 200

    # ------------------------------------------------------------------ #
    # robots.txt                                                          #
    # ------------------------------------------------------------------ #
    def _parse_robots(self, base_url):
        robots_url = f"{base_url}/robots.txt"
        result = {
            "found": False,
            "url": robots_url,
            "user_agents": {},
            "disallow": [],
            "allow": [],
            "sitemaps": [],
            "crawl_delay": None,
            "interesting_paths": [],
        }
        try:
            resp = http.get(robots_url, timeout=10)
            if not self._is_200(resp):
                print_status("robots.txt not found", "warning")
                return result

            result["found"] = True
            result["raw"] = resp.text
            print_status(
                f"Found robots.txt ({len(resp.text)} bytes)", "success")

            current_ua = "*"
            result["user_agents"].setdefault(
                current_ua, {"disallow": [], "allow": []})

            for raw_line in resp.text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                lower = line.lower()

                if lower.startswith("user-agent:"):
                    current_ua = line.split(":", 1)[1].strip() or "*"
                    result["user_agents"].setdefault(
                        current_ua, {"disallow": [], "allow": []})

                elif lower.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["disallow"].append(path)
                        result["user_agents"][current_ua]["disallow"].append(path)

                elif lower.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["allow"].append(path)
                        result["user_agents"][current_ua]["allow"].append(path)

                elif lower.startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm.startswith("//"):
                        sm = "https:" + sm
                    if sm:
                        result["sitemaps"].append(sm)
                        print_status(f"Sitemap declared: {sm}", "success")

                elif lower.startswith("crawl-delay:"):
                    try:
                        result["crawl_delay"] = float(
                            line.split(":", 1)[1].strip())
                    except ValueError:
                        pass

            # dedupe while preserving order
            result["disallow"] = list(dict.fromkeys(result["disallow"]))
            result["allow"] = list(dict.fromkeys(result["allow"]))
            result["sitemaps"] = list(dict.fromkeys(result["sitemaps"]))

            # flag interesting
            for path in result["disallow"]:
                lp = path.lower()
                for kw in INTERESTING_KEYWORDS:
                    if re.search(r"\b" + re.escape(kw) + r"\b", lp):
                        result["interesting_paths"].append(path)
                        print_status(f"[INTERESTING] {path}", "success")
                        break

        except Exception as exc:
            print_status(f"Failed to fetch robots.txt: {exc}", "error")
        return result

    # ------------------------------------------------------------------ #
    # sitemaps                                                            #
    # ------------------------------------------------------------------ #
    def _detect_sitemap_type(self, root):
        tag = root.tag.lower()
        if tag.endswith("sitemapindex"):
            return "index"
        if tag.endswith("urlset"):
            # look for news/image children
            for child in root.iter():
                ctag = child.tag.lower()
                if ctag.endswith("news"):
                    return "news"
                if ctag.endswith("image"):
                    return "image"
                if ctag.endswith("video"):
                    return "video"
            return "urlset"
        return "unknown"

    def _parse_sitemap(self, sitemap_url):
        """Return (meta, urls_from_this_file, nested_sitemap_urls)."""
        meta = {"url": sitemap_url, "type": None, "entries": 0, "status": 0}
        urls, nested = [], []
        try:
            resp = http.get(sitemap_url, timeout=15)
            meta["status"] = getattr(resp, "status_code", 0)
            if not self._is_200(resp):
                return meta, urls, nested

            try:
                root = ElementTree.fromstring(resp.content)
                meta["type"] = self._detect_sitemap_type(root)

                for sm in root.findall(".//sm:sitemap/sm:loc", SITEMAP_NS):
                    if sm.text:
                        nested.append(sm.text.strip())

                for url_el in root.findall(".//sm:url", SITEMAP_NS):
                    loc = url_el.find("sm:loc", SITEMAP_NS)
                    if loc is None or not loc.text:
                        continue
                    entry = {"url": loc.text.strip()}
                    lastmod = url_el.find("sm:lastmod", SITEMAP_NS)
                    changefreq = url_el.find("sm:changefreq", SITEMAP_NS)
                    priority = url_el.find("sm:priority", SITEMAP_NS)
                    if lastmod is not None and lastmod.text:
                        entry["lastmod"] = lastmod.text.strip()
                    if changefreq is not None and changefreq.text:
                        entry["changefreq"] = changefreq.text.strip()
                    if priority is not None and priority.text:
                        entry["priority"] = priority.text.strip()
                    urls.append(entry)

            except ElementTree.ParseError:
                # malformed XML or plain text; fall back to regex
                meta["type"] = "regex_fallback"
                for u in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", resp.text):
                    urls.append({"url": u.strip()})

            meta["entries"] = len(urls)
        except Exception as exc:
            print_status(f"Sitemap parse failed ({sitemap_url}): {exc}",
                         "warning")
        return meta, urls, nested

    def _collect_sitemaps(self, base_url, declared):
        """Breadth-first walk through declared + default sitemap paths.

        Returns (found_meta, all_urls, tree).
        """
        follow_index = self._bool_opt("FOLLOW_SITEMAP_INDEX")
        max_urls = self._int_opt("MAX_SITEMAP_URLS", 5000)

        queue = []
        for sm in declared:
            queue.append((sm, 0))
        for path in DEFAULT_SITEMAP_PATHS:
            queue.append((base_url + path, 0))

        seen = set()
        found_meta = []
        all_urls = []
        tree = {}

        step = 0
        total = len(queue)
        while queue and len(all_urls) < max_urls:
            sm_url, depth = queue.pop(0)
            if sm_url in seen:
                continue
            seen.add(sm_url)
            step += 1

            meta, urls, nested = self._parse_sitemap(sm_url)
            if meta["status"] != 200:
                continue

            found_meta.append(meta)
            if urls:
                all_urls.extend(urls)
            tree[sm_url] = {
                "type": meta["type"],
                "entries": meta["entries"],
                "nested": nested,
            }
            label = meta["type"] or "unknown"
            print_status(
                f"[{step}/{total}] {sm_url}: {len(urls)} URLs "
                f"({label}, {len(nested)} nested)",
                "success")

            if follow_index and depth < 2:
                for n in nested:
                    if n not in seen:
                        queue.append((n, depth + 1))
                        total += 1

        if len(all_urls) >= max_urls:
            print_status(
                f"MAX_SITEMAP_URLS cap hit at {max_urls}; stopping.",
                "warning")

        # deduplicate URLs while preserving order
        seen_u = set()
        deduped = []
        for e in all_urls:
            u = e.get("url")
            if u and u not in seen_u:
                seen_u.add(u)
                deduped.append(e)
        return found_meta, deduped, tree

    # ------------------------------------------------------------------ #
    # .well-known extractors                                              #
    # ------------------------------------------------------------------ #
    def _extract_openid(self, data):
        if not isinstance(data, dict):
            return {}
        keep = [
            "issuer", "authorization_endpoint", "token_endpoint",
            "userinfo_endpoint", "jwks_uri", "registration_endpoint",
            "end_session_endpoint", "introspection_endpoint",
            "revocation_endpoint", "device_authorization_endpoint",
            "scopes_supported", "response_types_supported",
            "grant_types_supported", "subject_types_supported",
            "id_token_signing_alg_values_supported",
            "token_endpoint_auth_methods_supported",
            "claims_supported",
        ]
        extracted = {k: data[k] for k in keep if k in data}
        endpoint_keys = [k for k in extracted
                         if k.endswith("_endpoint") or k == "jwks_uri"]
        extracted["_endpoint_count"] = len(endpoint_keys)
        return extracted

    def _extract_webfinger(self, data):
        if not isinstance(data, dict):
            return {}
        return {
            "subject": data.get("subject"),
            "aliases": data.get("aliases", []),
            "links": data.get("links", []),
        }

    def _extract_apple_aasa(self, data):
        if not isinstance(data, dict):
            return {"apps": []}
        apps = []
        applinks = data.get("applinks") or {}
        for d in applinks.get("details", []) or []:
            if isinstance(d, dict):
                app_ids = d.get("appIDs") or (
                    [d.get("appID")] if d.get("appID") else [])
                for aid in app_ids:
                    if aid:
                        apps.append(aid)
        for sect in ("webcredentials", "activitycontinuation"):
            data_sect = data.get(sect) or {}
            for aid in data_sect.get("apps", []) or []:
                apps.append(aid)
        return {"apps": sorted(set(apps))}

    def _extract_assetlinks(self, data):
        if not isinstance(data, list):
            return {"packages": []}
        packages = []
        for item in data:
            target = item.get("target", {}) if isinstance(item, dict) else {}
            if target.get("namespace") == "android_app":
                packages.append({
                    "package_name": target.get("package_name"),
                    "sha256_cert_fingerprints":
                        target.get("sha256_cert_fingerprints", []),
                    "relation": item.get("relation", []),
                })
        return {"packages": packages}

    def _extract_matrix(self, data):
        if not isinstance(data, dict):
            return {}
        out = {}
        for key in ("m.homeserver", "m.identity_server",
                    "m.server", "org.matrix.msc3575.proxy"):
            if key in data and isinstance(data[key], dict):
                out[key] = data[key].get("base_url") or data[key]
        return out

    def _extract_jwks(self, data):
        if not isinstance(data, dict):
            return {"keys": 0}
        keys = data.get("keys", [])
        return {
            "keys": len(keys),
            "algorithms": sorted({
                k.get("alg") for k in keys
                if isinstance(k, dict) and k.get("alg")
            }),
            "kids": [k.get("kid") for k in keys
                     if isinstance(k, dict) and k.get("kid")],
        }

    # ------------------------------------------------------------------ #
    # single-path probe (used by well-known / feeds / api docs)           #
    # ------------------------------------------------------------------ #
    def _probe_path(self, url):
        try:
            resp = http.get(url, timeout=10, allow_redirects=True)
            return resp, None
        except Exception as exc:
            return None, str(exc)

    def _probe_well_known(self, base_url):
        results = {}
        tasks = [(base_url + path, tag) for path, tag in WELL_KNOWN_PATHS]
        threads = max(1, self._int_opt("THREADS", 10))
        total = len(tasks)
        counter = {"n": 0}

        def worker(url, tag):
            resp, err = self._probe_path(url)
            return url, tag, resp, err

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(worker, u, t) for u, t in tasks]
            for fut in as_completed(futures):
                url, tag, resp, err = fut.result()
                counter["n"] += 1
                idx = counter["n"]
                if err:
                    continue
                if not self._is_200(resp):
                    continue

                entry = {
                    "url": url,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "size": len(resp.content or b""),
                }
                summary = ""

                try:
                    if tag in ("openid_config", "oauth_server"):
                        data = self._safe_json(resp)
                        parsed = self._extract_openid(data)
                        entry["data"] = parsed
                        summary = (f"{parsed.get('_endpoint_count', 0)} "
                                   f"endpoints revealed")
                    elif tag == "webfinger":
                        entry["data"] = self._extract_webfinger(
                            self._safe_json(resp))
                        summary = (
                            f"subject={entry['data'].get('subject')} "
                            f"links={len(entry['data'].get('links', []))}")
                    elif tag == "apple_app_site_association":
                        entry["data"] = self._extract_apple_aasa(
                            self._safe_json(resp))
                        summary = f"{len(entry['data']['apps'])} iOS apps"
                    elif tag == "assetlinks":
                        entry["data"] = self._extract_assetlinks(
                            self._safe_json(resp))
                        summary = (f"{len(entry['data']['packages'])} "
                                   f"Android packages")
                    elif tag in ("matrix_client", "matrix_server"):
                        entry["data"] = self._extract_matrix(
                            self._safe_json(resp))
                        summary = f"{len(entry['data'])} matrix entries"
                    elif tag == "jwks":
                        entry["data"] = self._extract_jwks(
                            self._safe_json(resp))
                        summary = f"{entry['data']['keys']} JWKs"
                    elif tag == "mta_sts":
                        entry["data"] = resp.text[:2000]
                        summary = f"{len(resp.text)} bytes"
                    elif tag in ("host_meta", "host_meta_json",
                                 "security_txt", "change_password",
                                 "dnt_policy", "discovery", "caldav",
                                 "carddav", "openpgpkey", "nodeinfo",
                                 "trust_txt"):
                        if entry["content_type"].startswith("application/json"):
                            entry["data"] = self._safe_json(resp)
                        else:
                            entry["data"] = resp.text[:2000]
                        summary = f"{entry['size']} bytes"
                    else:
                        entry["data"] = resp.text[:1000]
                        summary = f"{entry['size']} bytes"
                except Exception as exc:
                    entry["parse_error"] = str(exc)
                    summary = f"parse-error {exc}"

                results[tag] = entry
                print_status(
                    f"[{idx}/{total}] {url}: found ({summary})",
                    "success")
        return results

    def _probe_feeds(self, base_url):
        feeds = []
        threads = max(1, self._int_opt("THREADS", 10))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(self._probe_path, base_url + p): p
                for p in FEED_PATHS
            }
            for fut in as_completed(futures):
                path = futures[fut]
                resp, err = fut.result()
                if err or not self._is_200(resp):
                    continue
                ctype = resp.headers.get("Content-Type", "")
                size = len(resp.content or b"")
                looks_like_feed = (
                    "xml" in ctype or "rss" in ctype or "atom" in ctype
                    or "<rss" in resp.text[:400].lower()
                    or "<feed" in resp.text[:400].lower()
                    or path.startswith("/wp-json")
                )
                if not looks_like_feed and "json" not in ctype:
                    continue
                feeds.append({
                    "url": base_url + path,
                    "content_type": ctype,
                    "size": size,
                })
                print_status(f"Feed: {base_url + path} ({ctype})",
                             "success")
        return feeds

    def _probe_api_docs(self, base_url):
        docs = []
        threads = max(1, self._int_opt("THREADS", 10))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(self._probe_path, base_url + p): p
                for p in API_DOC_PATHS
            }
            for fut in as_completed(futures):
                path = futures[fut]
                resp, err = fut.result()
                if err or not self._is_200(resp):
                    continue
                ctype = resp.headers.get("Content-Type", "")
                head = resp.text[:400].lower()
                is_api = (
                    "openapi" in head or "swagger" in head
                    or "yaml" in ctype or "json" in ctype
                    or path.endswith((".json", ".yaml", ".yml"))
                    or "swagger-ui" in head
                )
                if not is_api:
                    continue
                docs.append({
                    "url": base_url + path,
                    "content_type": ctype,
                    "size": len(resp.content or b""),
                })
                print_status(f"API doc: {base_url + path} ({ctype})",
                             "success")
        return docs

    # ------------------------------------------------------------------ #
    # entrypoint                                                          #
    # ------------------------------------------------------------------ #
    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        base_url = target.rstrip("/")
        parsed = urlparse(base_url)
        if not parsed.netloc:
            print_status("Invalid TARGET", "error")
            return False

        print_status(f"Analyzing {base_url}", "info")
        start = time.time()
        warnings = []

        # robots.txt
        robots = self._parse_robots(base_url)

        # sitemaps
        sitemap_meta, sitemap_urls, sitemap_tree = [], [], {}
        if self._bool_opt("PARSE_SITEMAPS"):
            try:
                sitemap_meta, sitemap_urls, sitemap_tree = (
                    self._collect_sitemaps(base_url, robots["sitemaps"]))
            except Exception as exc:
                warnings.append(f"sitemap-walk: {exc}")
                print_status(f"Sitemap walk failed: {exc}", "error")

        # .well-known
        well_known = {}
        if self._bool_opt("WELL_KNOWN_PROBE"):
            try:
                well_known = self._probe_well_known(base_url)
            except Exception as exc:
                warnings.append(f"well-known: {exc}")
                print_status(f".well-known probe failed: {exc}", "error")

        # feeds
        feeds = []
        if self._bool_opt("FEED_PROBE"):
            try:
                feeds = self._probe_feeds(base_url)
            except Exception as exc:
                warnings.append(f"feeds: {exc}")

        # api docs
        api_docs = []
        if self._bool_opt("API_DOC_PROBE"):
            try:
                api_docs = self._probe_api_docs(base_url)
            except Exception as exc:
                warnings.append(f"api-docs: {exc}")

        duration = round(time.time() - start, 2)
        paths_probed = (
            1  # robots.txt
            + len(DEFAULT_SITEMAP_PATHS) + len(robots.get("sitemaps", []))
            + (len(WELL_KNOWN_PATHS) if self._bool_opt("WELL_KNOWN_PROBE") else 0)
            + (len(FEED_PATHS) if self._bool_opt("FEED_PROBE") else 0)
            + (len(API_DOC_PATHS) if self._bool_opt("API_DOC_PROBE") else 0)
        )
        paths_found = (
            (1 if robots["found"] else 0)
            + len(sitemap_meta)
            + len(well_known)
            + len(feeds)
            + len(api_docs)
        )

        self.results = {
            "target": base_url,
            "robots_txt": {
                "found": robots["found"],
                "url": robots["url"],
                "user_agents": robots["user_agents"],
                "disallow": robots["disallow"],
                "allow": robots["allow"],
                "sitemaps": robots["sitemaps"],
                "crawl_delay": robots["crawl_delay"],
                "interesting_paths": robots["interesting_paths"],
            },
            "sitemaps": {
                "found": sitemap_meta,
                "all_urls": [e["url"] for e in sitemap_urls],
                "entries": sitemap_urls[:1000],
                "sitemap_tree": sitemap_tree,
            },
            "well_known": well_known,
            "feeds": feeds,
            "api_docs": api_docs,
            "stats": {
                "paths_probed": paths_probed,
                "paths_found": paths_found,
                "sitemap_urls": len(sitemap_urls),
                "duration_sec": duration,
            },
            "warnings": warnings,
        }

        print_status(
            f"Complete in {duration}s - probed {paths_probed} paths, "
            f"{paths_found} found; "
            f"{len(robots['disallow'])} disallow, "
            f"{len(sitemap_urls)} sitemap URLs, "
            f"{len(well_known)} well-known, "
            f"{len(feeds)} feeds, {len(api_docs)} api docs",
            "info")
        return True
