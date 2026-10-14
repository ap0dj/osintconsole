import re
from bs4 import BeautifulSoup
from core import http
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config
from modules.harvest.crypto_transactions import FetchErrorsMixin


class EmailHarvest(FetchErrorsMixin, BaseModule):
    name = "harvest/email_harvest"
    description = "Email address harvesting from web pages, search engines, and pattern generation"
    category = "harvest"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain")
        self.add_option("DEPTH", "3", False, "Pages to crawl per source")
        self.add_option("GENERATE_PATTERNS", "true", False, "Generate common email patterns")

    def _search_bing(self, domain, pages=3):
        """Returns (emails, ok). ok is False only when every page request failed
        (non-200 / exception). A 429/captcha body must NOT be scraped as a clean
        'no emails' - without a 200 the search simply did not run."""
        emails = set()
        config = Config()
        headers = {"User-Agent": config.get("user_agent")}
        any_ok = False
        for page in range(pages):
            try:
                url = f"https://www.bing.com/search?q=%40{domain}&first={page*10}"
                resp = http.get(url, headers=headers, timeout=10)
            except Exception as exc:
                self._note_error(f"Bing request error: {exc}")
                continue
            if resp.status_code != 200:
                self._note_error(f"Bing HTTP {resp.status_code}")
                continue
            any_ok = True
            found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), resp.text)
            emails.update(found)
        return emails, any_ok

    def _crawl_site(self, domain, depth=3):
        """Returns (emails, ok). ok is False only when no page fetched cleanly,
        so a blocked/unreachable site is not reported as 'no emails on site'."""
        emails = set()
        config = Config()
        headers = {"User-Agent": config.get("user_agent")}
        visited = set()
        to_visit = [f"https://{domain}"]
        any_ok = False

        for _ in range(depth):
            if not to_visit:
                break
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = http.get(url, headers=headers, timeout=10)
            except Exception as exc:
                self._note_error(f"crawl error ({url}): {exc}")
                continue
            if resp.status_code != 200:
                self._note_error(f"crawl HTTP {resp.status_code} ({url})")
                continue
            any_ok = True
            found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
            emails.update(found)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/"):
                    href = f"https://{domain}{href}"
                if domain in href and href not in visited:
                    to_visit.append(href)
        return emails, any_ok

    def _generate_patterns(self, domain):
        common_names = [
            "admin", "info", "contact", "support", "sales", "hr", "help",
            "office", "marketing", "careers", "jobs", "press", "media",
            "webmaster", "postmaster", "abuse", "security", "noc",
            "billing", "legal", "privacy", "compliance",
        ]
        return [f"{name}@{domain}" for name in common_names]

    def _check_email_exists(self, email):
        try:
            import dns.resolver
            domain = email.split("@")[1]
            mx_records = dns.resolver.resolve(domain, "MX")
            return len(list(mx_records)) > 0
        except Exception:
            return False

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        depth = int(self.get_option("DEPTH") or 3)

        print_status(f"Harvesting emails for {target}", "info")

        self._errors = []
        all_emails = set()
        sources = {}
        sources_failed = []

        print_status("Searching via Bing...", "info")
        bing_emails, bing_ok = self._search_bing(target, depth)
        if not bing_ok:
            sources_failed.append("bing")
            print_status("Bing search FAILED (blocked/unreachable) - NOT evidence "
                         "of no emails", "warning")
        if bing_emails:
            sources["bing"] = list(bing_emails)
            all_emails.update(bing_emails)
            print_status(f"Bing: found {len(bing_emails)} emails", "success")

        print_status("Crawling target website...", "info")
        crawl_emails, crawl_ok = self._crawl_site(target, depth)
        if not crawl_ok:
            sources_failed.append("website_crawl")
            print_status("Website crawl FAILED (blocked/unreachable) - NOT evidence "
                         "of no emails", "warning")
        if crawl_emails:
            sources["website_crawl"] = list(crawl_emails)
            all_emails.update(crawl_emails)
            print_status(f"Crawl: found {len(crawl_emails)} emails", "success")

        patterns = []
        if self.get_option("GENERATE_PATTERNS").lower() == "true":
            patterns = self._generate_patterns(target)
            print_status(f"Generated {len(patterns)} common email patterns", "info")

        has_mx = self._check_email_exists(f"test@{target}")

        for email in all_emails:
            print_status(f"Found: {email}", "success")

        self.results = {
            "target": target,
            "emails_found": sorted(list(all_emails)),
            "total_found": len(all_emails),
            "sources": sources,
            "common_patterns": patterns,
            "mx_exists": has_mx,
            "sources_failed": sources_failed,
            "fetch_errors": list(self._errors),
        }

        # Both live harvesters failed to fetch -> this is a FETCH FAILURE, never
        # a clean "no emails found" (pattern generation is offline and still in
        # the results for the caller).
        if not bing_ok and not crawl_ok:
            return self._fail()

        print_status(f"Email harvesting complete. {len(all_emails)} unique emails found", "info")
        return True
