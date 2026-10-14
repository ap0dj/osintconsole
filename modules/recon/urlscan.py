import time
from collections import Counter
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.config import Config
from core import http


class UrlScan(BaseModule):
    name = "recon/urlscan"
    description = "URLScan.io passive URL/domain OSINT - historical scans + optional new public scan"
    category = "recon"
    target_type = "domain/url"

    SEARCH_URL = "https://urlscan.io/api/v1/search/"
    SCAN_URL = "https://urlscan.io/api/v1/scan/"
    RESULT_URL = "https://urlscan.io/api/v1/result/{}/"

    POLL_MAX_TRIES = 10
    POLL_DELAY = 3

    def _register_options(self):
        self.add_option("TARGET", "", True, "Domain, URL, or free-form urlscan query (e.g. 'domain:example.com')")
        self.add_option("SCAN", "false", False, "Submit a new PUBLIC scan to urlscan.io (opt-in)")
        self.add_option("MAX_RESULTS", "25", False, "Max historical scans to fetch (1-10000)")
        self.add_option("COUNTRY", "", False, "Optional ISO country code filter (e.g. IQ, US)")

    def _build_query(self, target, country):
        """Build a urlscan Lucene-style query from a target and optional country."""
        t = target.strip()
        # Field-based free-form query - trust it as-is
        if (" " in t) or (":" in t and not t.startswith(("http://", "https://"))):
            query = t
        elif t.startswith(("http://", "https://")):
            query = f'page.url:"{t}"'
        elif "." in t:
            query = f"domain:{t}"
        else:
            query = t
        if country:
            query = f"({query}) AND page.country:{country.upper()}"
        return query

    def _auth_headers(self, api_key, extra=None):
        headers = dict(extra) if extra else {}
        if api_key:
            headers["API-Key"] = api_key
        return headers

    def _search(self, query, size, api_key):
        try:
            resp = http.get(
                self.SEARCH_URL,
                params={"q": query, "size": size},
                headers=self._auth_headers(api_key),
                timeout=20,
            )
        except Exception as e:
            print_status(f"URLScan search failed: {e}", "error")
            return None

        if resp.status_code == 429:
            print_status("URLScan rate limit hit (429). Wait a minute or add an API key.", "warning")
            return None
        if resp.status_code == 403:
            print_status("URLScan forbidden (403). API key invalid or result is private.", "warning")
            return None
        if resp.status_code != 200:
            print_status(f"URLScan search returned HTTP {resp.status_code}", "warning")
            return None
        try:
            return resp.json()
        except Exception as e:
            print_status(f"Could not parse URLScan JSON: {e}", "error")
            return None

    def _submit_scan(self, url, api_key):
        payload = {"url": url, "visibility": "public"}
        headers = self._auth_headers(api_key, {"Content-Type": "application/json"})
        try:
            resp = http.post(self.SCAN_URL, json=payload, headers=headers, timeout=20)
        except Exception as e:
            print_status(f"URLScan scan submission failed: {e}", "error")
            return None

        if resp.status_code in (200, 201):
            try:
                return resp.json()
            except Exception:
                return None
        if resp.status_code == 401:
            print_status("URLScan scan submission needs an API key (401). "
                         "Set api_keys.urlscan in config.", "warning")
            return None
        if resp.status_code == 429:
            print_status("URLScan submission rate limited (429).", "warning")
            return None
        if resp.status_code == 400:
            try:
                msg = resp.json().get("message", "")
            except Exception:
                msg = (resp.text or "")[:200]
            print_status(f"URLScan submission rejected (400): {msg}", "warning")
            return None
        if resp.status_code == 403:
            print_status("URLScan submission forbidden (403) - URL may be blocked.", "warning")
            return None
        print_status(f"URLScan submission returned HTTP {resp.status_code}", "warning")
        return None

    def _poll_result(self, uuid, api_key):
        url = self.RESULT_URL.format(uuid)
        headers = self._auth_headers(api_key)
        for attempt in range(1, self.POLL_MAX_TRIES + 1):
            print(f"\r {Colors.BLUE}[*]{Colors.RESET} Polling scan result... "
                  f"attempt {attempt}/{self.POLL_MAX_TRIES}", end="", flush=True)
            try:
                resp = http.get(url, headers=headers, timeout=20)
            except Exception as e:
                print()
                print_status(f"Polling error: {e}", "warning")
                return None
            if resp.status_code == 200:
                print()
                try:
                    return resp.json()
                except Exception as e:
                    print_status(f"Could not parse scan result JSON: {e}", "error")
                    return None
            if resp.status_code == 404:
                time.sleep(self.POLL_DELAY)
                continue
            if resp.status_code == 429:
                print()
                print_status("Polling rate limited (429). Backing off.", "warning")
                time.sleep(self.POLL_DELAY * 2)
                continue
            print()
            print_status(f"Polling returned HTTP {resp.status_code}", "warning")
            return None
        print()
        return None

    def _resolve_scan_url(self, target, warnings):
        """Turn TARGET into something scannable, or None if it is a free-form query."""
        t = target.strip()
        if t.startswith(("http://", "https://")):
            return t
        if " " in t or ":" in t:
            print_status("SCAN=true requires a URL or domain in TARGET (not a free-form query). "
                         "Skipping new scan.", "warning")
            warnings.append("scan_target_not_url")
            return None
        if "." in t:
            return f"https://{t}"
        print_status("SCAN=true needs a URL or domain in TARGET. Skipping new scan.", "warning")
        warnings.append("scan_target_not_url")
        return None

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        scan_mode = self.get_option("SCAN").lower() == "true"
        country = (self.get_option("COUNTRY") or "").strip()
        try:
            max_results = max(1, min(10000, int(self.get_option("MAX_RESULTS") or 25)))
        except (TypeError, ValueError):
            max_results = 25

        api_key = Config().get("api_keys.urlscan") or ""
        warnings = []

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  URLScan.io: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        if api_key:
            print_status("Using URLScan API key for authenticated requests", "info")
        else:
            print_status("No API key - using free public search (lower rate limit)", "info")

        query = self._build_query(target, country)
        print_status(f"Query: {query}", "info")
        print_status(f"Fetching up to {max_results} historical scans...", "info")

        start = time.time()
        data = self._search(query, max_results, api_key)
        search_results = []
        total_reported = 0

        if data is None:
            warnings.append("search_failed")
        else:
            results = data.get("results", []) or []
            total_reported = data.get("total", len(results))
            print_status(f"URLScan reports {total_reported} historical scans "
                         f"(fetched {len(results)})", "success")

            for r in results:
                page = r.get("page", {}) or {}
                task = r.get("task", {}) or {}
                entry = {
                    "task_time": task.get("time"),
                    "url": page.get("url") or task.get("url"),
                    "domain": page.get("domain"),
                    "country": page.get("country"),
                    "screenshot": r.get("screenshot"),
                    "result_url": r.get("result"),
                    "server_ip": page.get("ip"),
                    "server_asn": page.get("asn"),
                    "asnname": page.get("asnname"),
                    "server": page.get("server"),
                }
                search_results.append(entry)
                ctry = entry["country"] or "??"
                ip = entry["server_ip"] or "?"
                asn = entry["server_asn"] or ""
                asn_str = f" {asn}" if asn else ""
                print_status(f"[{ctry}] {entry['url']}  ({ip}{asn_str})", "success")

        new_scan = None
        if scan_mode:
            url_to_scan = self._resolve_scan_url(target, warnings)
            if url_to_scan:
                print_status(f"Submitting NEW public scan: {url_to_scan}", "info")
                sub = self._submit_scan(url_to_scan, api_key)
                if sub and sub.get("uuid"):
                    uuid = sub["uuid"]
                    print_status(f"Scan accepted  uuid={uuid}", "success")
                    if sub.get("result"):
                        print_status(f"Result page: {sub['result']}", "info")
                    result = self._poll_result(uuid, api_key)
                    if result:
                        page = result.get("page", {}) or {}
                        task = result.get("task", {}) or {}
                        verdicts = result.get("verdicts", {}) or {}
                        overall = verdicts.get("overall", {}) or {}
                        new_scan = {
                            "uuid": uuid,
                            "result_url": task.get("reportURL") or sub.get("result"),
                            "screenshot": task.get("screenshotURL"),
                            "verdict": {
                                "malicious": overall.get("malicious"),
                                "score": overall.get("score"),
                                "tags": overall.get("tags", []) or [],
                            },
                            "page": {
                                "url": page.get("url"),
                                "domain": page.get("domain"),
                                "country": page.get("country"),
                                "ip": page.get("ip"),
                                "server": page.get("server"),
                                "asn": page.get("asn"),
                            },
                        }
                        v = new_scan["verdict"]
                        v_status = "warning" if v.get("malicious") else "success"
                        tags_str = ", ".join(v["tags"]) if v["tags"] else "none"
                        print_status(
                            f"Verdict: malicious={v.get('malicious')} "
                            f"score={v.get('score')} tags={tags_str}",
                            v_status,
                        )
                        if new_scan["screenshot"]:
                            print_status(f"Screenshot: {new_scan['screenshot']}", "info")
                    else:
                        print_status("Scan submitted but result did not finalize in time", "warning")
                        new_scan = {
                            "uuid": uuid,
                            "result_url": sub.get("result"),
                            "screenshot": None,
                            "verdict": None,
                        }
                        warnings.append("poll_timeout")
                else:
                    warnings.append("scan_submission_failed")

        duration = round(time.time() - start, 2)
        countries = Counter(r["country"] for r in search_results if r.get("country"))
        asns = Counter(
            (r.get("asnname") or r.get("server_asn"))
            for r in search_results
            if r.get("asnname") or r.get("server_asn")
        )
        servers = Counter(r["server"] for r in search_results if r.get("server"))

        self.results = {
            "target": target,
            "query_used": query,
            "search_results": search_results,
            "new_scan": new_scan,
            "stats": {
                "total": len(search_results),
                "total_reported": total_reported,
                "duration_sec": duration,
                "top_countries": dict(countries.most_common(5)),
                "top_asns": dict(asns.most_common(5)),
                "top_servers": dict(servers.most_common(5)),
            },
            "warnings": warnings,
        }

        print(f"\n{Colors.BOLD}{Colors.CYAN}--- Summary ---{Colors.RESET}")
        print_status(f"Historical scans fetched: {len(search_results)} "
                     f"(reported total: {total_reported})", "info")
        if countries:
            tops = ", ".join(f"{c}({n})" for c, n in countries.most_common(5))
            print_status(f"Top countries: {tops}", "info")
        if asns:
            tops = ", ".join(f"{a}({n})" for a, n in asns.most_common(5))
            print_status(f"Top ASNs: {tops}", "info")
        if servers:
            tops = ", ".join(f"{s}({n})" for s, n in servers.most_common(5))
            print_status(f"Top server banners: {tops}", "info")
        print_status(f"Duration: {duration}s", "info")
        if warnings:
            print_status(f"Warnings: {', '.join(warnings)}", "warning")
        print(f"\n{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return bool(search_results) or bool(new_scan)
