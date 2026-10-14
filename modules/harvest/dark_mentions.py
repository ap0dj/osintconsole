"""Dark web & deep web mention search — Ahmia, Torch, and dark-web search APIs."""
from core.base_module import BaseModule
import core.http as http_client
from core.utils import print_status
from core.config import Config


class DarkMentions(BaseModule):
    name = "harvest/dark_mentions"
    description = "Search Ahmia and dark-web indexes for target mentions (.onion / deep web)"
    category = "harvest"
    target_type = "domain/email/username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Domain, email, or username to search for")
        self.add_option("MAX_RESULTS", "20", False, "Max results to return per source")

    def run(self):
        if not self.validate():
            return False

        target = (self.get_option("TARGET") or "").strip()
        try:
            max_results = int(self.get_option("MAX_RESULTS") or "20")
        except (TypeError, ValueError):
            max_results = 20

        results = {
            "target": target,
            "sources_checked": [],   # queried and returned usable output
            "sources_failed": [],    # errored / timed out / unusable response
            "sources_skipped": [],   # not attempted (e.g. no API key / no Tor)
            "mentions": [],
            "onion_urls": [],
            "total_found": 0,
        }

        # --- Ahmia (clearnet index of .onion sites) ---
        # Verified live 2026-10-13: ahmia.fi/search/ now renders its result list
        # client-side with JavaScript. A plain HTTP GET returns only a ~4.7 KB
        # skeleton (it even ships a hidden "no non-JavaScript version yet" note),
        # and the ONLY .onion on that skeleton is Ahmia's own address. So we must
        # (a) never count Ahmia's own onion as a hit, and (b) treat a skeleton
        # with no result markup as a FAILED fetch, not as "0 results / clean".
        print_status("Checking Ahmia...", "info")
        ahmia_own = ("juhanurmihxlp77", "msydqstlz2kzerdg")  # Ahmia's own + mirror
        try:
            r = http_client.get(
                "https://ahmia.fi/search/",
                params={"q": target},
                headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT-research)"},
                timeout=20,
            )
            if r is not None and r.status_code == 200:
                import re
                onion_re = re.compile(r'href="(https?://[a-z2-7]{16,56}\.onion[^"]*)"', re.I)
                title_re = re.compile(r'<h4[^>]*>\s*<a[^>]*>([^<]+)</a>', re.I)
                found_onions = [u for u in onion_re.findall(r.text)
                                if not any(own in u.lower() for own in ahmia_own)][:max_results]
                found_titles = title_re.findall(r.text)[:max_results]
                # Real result pages always carry result titles, /search/redirect
                # links, or third-party onions; the JS skeleton carries none.
                has_results = bool(found_onions or found_titles
                                   or "/search/redirect" in r.text)
                if has_results:
                    results["sources_checked"].append("ahmia.fi")
                    for url in found_onions:
                        if url not in results["onion_urls"]:
                            results["onion_urls"].append(url)
                    for title in found_titles:
                        results["mentions"].append(
                            {"source": "ahmia.fi", "title": title.strip(), "query": target})
                    print_status(f"Ahmia: {len(found_onions)} onion links, "
                                 f"{len(found_titles)} results", "success")
                else:
                    results["sources_failed"].append(
                        {"source": "ahmia.fi", "reason": "no server-side results (JS-rendered page)"})
                    print_status("Ahmia: JS-only page, no server-side results - FAILED", "warning")
            elif r is not None:
                results["sources_failed"].append(
                    {"source": "ahmia.fi", "reason": f"HTTP {r.status_code}"})
                print_status(f"Ahmia: HTTP {r.status_code} - FAILED", "warning")
            else:
                results["sources_failed"].append({"source": "ahmia.fi", "reason": "no response"})
                print_status("Ahmia: no response - FAILED", "warning")
        except Exception as e:
            results["sources_failed"].append({"source": "ahmia.fi", "reason": f"error: {e}"})
            print_status(f"Ahmia error: {e} - FAILED", "warning")

        # --- Grep.app (public code search, occasionally surfaces leaked mentions) ---
        # Verified live 2026-10-13: grep.app's API now answers programmatic
        # clients with HTTP 429 and a bot "challenge", so in practice it is
        # reported as FAILED. The 200-path parser is kept for the rare
        # unchallenged case; it never counts a failed fetch as "clean".
        print_status("Checking grep.app for leaked mentions...", "info")
        try:
            r = http_client.get(
                "https://grep.app/api/search",
                params={"q": target, "case": "false"},
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if r is not None and r.status_code == 200:
                results["sources_checked"].append("grep.app")
                try:
                    data = r.json()
                except Exception:
                    data = {}
                hits = data.get("hits", {}).get("hits", [])
                for hit in hits[:max_results]:
                    src = hit.get("_source", {})
                    results["mentions"].append({
                        "source": "grep.app",
                        "repo": src.get("repo", {}).get("raw", ""),
                        "path": src.get("path", {}).get("raw", ""),
                        "content": src.get("content", {}).get("snippet", "")[:200],
                    })
                print_status(f"grep.app: {len(hits)} matches", "success" if hits else "info")
            elif r is not None:
                results["sources_failed"].append(
                    {"source": "grep.app", "reason": f"HTTP {r.status_code}"})
                print_status(f"grep.app: HTTP {r.status_code} - FAILED", "warning")
            else:
                results["sources_failed"].append({"source": "grep.app", "reason": "no response"})
                print_status("grep.app: no response - FAILED", "warning")
        except Exception as e:
            results["sources_failed"].append({"source": "grep.app", "reason": f"error: {e}"})
            print_status(f"grep.app error: {e} - FAILED", "warning")

        # --- IntelligenceX (requires a real API key) ---
        # Verified live 2026-10-13: the public all-zeros key is now rejected
        # (HTTP 401) and GET is not allowed (HTTP 405). The real API is a 2-phase
        # POST search + GET result. Only attempt it when a real key is set;
        # otherwise skip it explicitly instead of padding the report with a
        # throttled no-op.
        print_status("Checking IntelligenceX...", "info")
        intelx_key = (Config().get("api_keys.intelx") or "").strip()
        if not intelx_key:
            results["sources_skipped"].append(
                {"source": "intelx.io", "reason": "no api_keys.intelx key configured"})
            print_status("IntelligenceX: skipped (set api_keys.intelx to enable)", "info")
        else:
            try:
                r = http_client.post(
                    "https://2.intelx.io/intelligent/search",
                    headers={"x-key": intelx_key, "Content-Type": "application/json"},
                    json={"term": target, "maxresults": max_results,
                          "media": 0, "sort": 4, "terminate": []},
                    timeout=20,
                )
                if r is not None and r.status_code == 200:
                    results["sources_checked"].append("intelx.io")
                    try:
                        search_id = r.json().get("id")
                    except Exception:
                        search_id = None
                    recs = []
                    if search_id:
                        rr = http_client.get(
                            "https://2.intelx.io/intelligent/search/result",
                            params={"id": search_id, "limit": max_results},
                            headers={"x-key": intelx_key},
                            timeout=20,
                        )
                        if rr is not None and rr.status_code == 200:
                            try:
                                recs = rr.json().get("records", []) or []
                            except Exception:
                                recs = []
                            for item in recs[:max_results]:
                                results["mentions"].append({
                                    "source": "intelx.io",
                                    "selectvalue": item.get("name") or item.get("systemid", ""),
                                    "date": item.get("date", ""),
                                })
                    print_status(f"IntelligenceX: {len(recs)} records",
                                 "success" if recs else "info")
                elif r is not None:
                    results["sources_failed"].append(
                        {"source": "intelx.io", "reason": f"HTTP {r.status_code}"})
                    print_status(f"IntelligenceX: HTTP {r.status_code} - FAILED", "warning")
                else:
                    results["sources_failed"].append(
                        {"source": "intelx.io", "reason": "no response"})
                    print_status("IntelligenceX: no response - FAILED", "warning")
            except Exception as e:
                results["sources_failed"].append({"source": "intelx.io", "reason": f"error: {e}"})
                print_status(f"IntelligenceX error: {e} - FAILED", "warning")

        results["total_found"] = len(results["mentions"]) + len(results["onion_urls"])

        # Print summary
        print(f"\n  Target:       {target}")
        print(f"  Sources:      {', '.join(results['sources_checked']) or '(none)'}")
        if results["sources_failed"]:
            print(f"  Failed:       "
                  f"{', '.join(f['source'] for f in results['sources_failed'])}")
        if results["sources_skipped"]:
            print(f"  Skipped:      "
                  f"{', '.join(s['source'] for s in results['sources_skipped'])}")
        print(f"  Mentions:     {len(results['mentions'])}")
        print(f"  Onion URLs:   {len(results['onion_urls'])}")
        for m in results["mentions"][:5]:
            src = m.get("source", "")
            detail = m.get("title") or m.get("repo") or m.get("selectvalue") or ""
            print(f"    [{src}] {detail[:80]}")
        for url in results["onion_urls"][:3]:
            print(f"    [onion] {url[:80]}")

        self.results = results
        return True
