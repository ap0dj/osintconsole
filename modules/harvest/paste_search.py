from bs4 import BeautifulSoup
from core import http
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config
from modules.harvest.crypto_transactions import FetchErrorsMixin

DEFAULT_PASTE_SITES = [
    "pastebin.com",
    "ghostbin.com",
    "paste.ee",
    "dpaste.org",
    "hastebin.com",
    "justpaste.it",
    "paste2.org",
    "codepad.org",
    "ideone.com",
    "paste.mozilla.org",
]


class PasteSearch(FetchErrorsMixin, BaseModule):
    name = "harvest/paste_search"
    description = "Search paste sites for target mentions via search engines"
    category = "harvest"
    target_type = "domain/keyword"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain, email, or keyword")
        self.add_option("PASTE_SITES", ",".join(DEFAULT_PASTE_SITES), False, "Comma-separated list of paste sites to search")
        self.add_option("MAX_PAGES", "3", False, "Max search engine pages per site")

    def _search_bing(self, query, pages, config):
        """Scrape Bing for paste results.

        Returns (results, ok). ok is False only when EVERY page request failed
        (non-200 / exception) - a clean 200 with no hits is a genuine
        'nothing found', never a failure. A blocked/429 Bing must therefore not
        be reported as '0 pastes found'.
        """
        results = []
        headers = {"User-Agent": config.get("user_agent")}
        any_ok = False
        for page in range(pages):
            try:
                url = f"https://www.bing.com/search?q={query}&first={page * 10 + 1}"
                resp = http.get(url, headers=headers, timeout=10)
            except Exception as exc:
                self._note_error(f"Bing request error for '{query}': {exc}")
                continue
            if resp.status_code != 200:
                self._note_error(f"Bing HTTP {resp.status_code} for '{query}'")
                continue
            any_ok = True
            soup = BeautifulSoup(resp.text, "html.parser")
            for li in soup.find_all("li", class_="b_algo"):
                link = li.find("a")
                if not link:
                    continue
                href = link.get("href", "")
                title = link.text.strip()
                snippet_el = li.find("p")
                snippet = snippet_el.text.strip() if snippet_el else ""
                if href:
                    results.append({
                        "title": title,
                        "url": href,
                        "snippet": snippet,
                    })
        return results, any_ok

    def _deduplicate(self, results):
        """Remove duplicate URLs from results."""
        seen = set()
        unique = []
        for r in results:
            if r["url"] not in seen:
                seen.add(r["url"])
                unique.append(r)
        return unique

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        paste_sites_raw = self.get_option("PASTE_SITES") or ",".join(DEFAULT_PASTE_SITES)
        paste_sites = [s.strip() for s in paste_sites_raw.split(",") if s.strip()]
        max_pages = int(self.get_option("MAX_PAGES") or 3)
        config = Config()

        print_status(f"Searching paste sites for mentions of '{target}'", "info")
        print_status(f"Searching across {len(paste_sites)} paste sites", "info")

        self._errors = []
        all_results = []
        site_results = {}
        sources_failed = []
        any_ok = False

        for site in paste_sites:
            query = f'site:{site} "{target}"'
            print_status(f"Searching: {query}", "info")

            results, ok = self._search_bing(query, max_pages, config)
            any_ok = any_ok or ok

            if not ok:
                # Bing blocked/unreachable for this query - this is NOT a clean
                # "no mentions found" for the site.
                sources_failed.append(site)
                print_status(f"{site}: search FAILED (Bing blocked/unreachable) - "
                             f"NOT evidence of no mentions", "warning")
                continue

            if results:
                site_results[site] = results
                all_results.extend(results)
                print_status(f"Found {len(results)} result(s) on {site}", "success")
                for r in results:
                    print_status(f"  -> {r['url']}", "success")
                    if r["snippet"]:
                        snippet_short = r["snippet"][:120] + "..." if len(r["snippet"]) > 120 else r["snippet"]
                        print_status(f"     {snippet_short}", "info")
            else:
                print_status(f"No results on {site}", "info")

        # Also do a general search without site restriction
        print_status(f"Running general paste search for '{target}'...", "info")
        general_query = f'"{target}" paste OR pastebin OR pastie'
        general_results, general_ok = self._search_bing(general_query, max_pages, config)
        any_ok = any_ok or general_ok
        if not general_ok:
            sources_failed.append("general_search")
            print_status("General search FAILED (Bing blocked/unreachable)", "warning")
        elif general_results:
            site_results["general_search"] = general_results
            all_results.extend(general_results)
            print_status(f"General search found {len(general_results)} additional result(s)", "success")

        all_results = self._deduplicate(all_results)

        # Categorize results by apparent sensitivity
        pastes_with_keywords = []
        sensitive_keywords = [
            "password", "passwd", "credential", "secret", "api_key",
            "apikey", "token", "leak", "dump", "breach", "hack",
            "database", "admin", "login", "config",
        ]
        for r in all_results:
            text = (r.get("title", "") + " " + r.get("snippet", "")).lower()
            found_keywords = [kw for kw in sensitive_keywords if kw in text]
            if found_keywords:
                pastes_with_keywords.append({
                    "url": r["url"],
                    "title": r["title"],
                    "matched_keywords": found_keywords,
                    "snippet": r["snippet"],
                })

        if pastes_with_keywords:
            print_status(f"Found {len(pastes_with_keywords)} paste(s) with sensitive keywords!", "warning")
            for p in pastes_with_keywords:
                print_status(f"  Keywords {p['matched_keywords']}: {p['url']}", "warning")

        self.results = {
            "target": target,
            "paste_sites_searched": paste_sites,
            "total_results": len(all_results),
            "results_by_site": site_results,
            "all_results": all_results,
            "sensitive_pastes": pastes_with_keywords,
            "total_sensitive": len(pastes_with_keywords),
            "sources_failed": sources_failed,
            "fetch_errors": list(self._errors),
        }

        # Every Bing request failed -> fetch failure, never a clean "0 pastes".
        if not any_ok:
            return self._fail()

        if sources_failed:
            print_status(f"{len(sources_failed)} search(es) FAILED (blocked/unreachable, "
                         f"not 'no results'): {', '.join(sources_failed)}", "warning")

        print_status(f"Paste search complete. {len(all_results)} total result(s), {len(pastes_with_keywords)} with sensitive keywords", "info")
        return True
