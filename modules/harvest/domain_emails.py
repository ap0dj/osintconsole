import re

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

ROLE_PREFIXES = ["info", "admin", "contact", "support", "sales", "hello", "security"]


class DomainEmails(FetchErrorsMixin, BaseModule):
    """Harvest email addresses associated with a domain (Bing + crt.sh + verified role addresses)."""

    name = "harvest/domain_emails"
    description = "Harvest emails for a domain via Bing scrape, crt.sh, and MX-verified role addresses"
    category = "harvest"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain (e.g. example.com)")

    def _email_pattern(self, domain):
        # Matches addresses at the domain itself or any subdomain of it.
        # Scraped pages reflect the URL-encoded query (e.g. %22%40domain, where
        # %40='@' and %22='"'). To avoid turning those artifacts into
        # false-positive "emails" (e.g. 22@domain from %22@domain):
        #   - '%' is excluded from the local part, and
        #   - a negative lookbehind forbids a match starting right after any
        #     local-part char or '%', so partial-decode remnants can't anchor.
        return re.compile(
            r'(?<![a-zA-Z0-9._%+-])[a-zA-Z0-9._+-]+@(?:[a-zA-Z0-9-]+\.)*' + re.escape(domain),
            re.IGNORECASE,
        )

    @staticmethod
    def _is_real_email(email):
        """Reject scraping artifacts: local part must contain a letter/digit
        and not be a run of punctuation."""
        local = email.split("@", 1)[0]
        if not re.search(r'[a-zA-Z0-9]', local):
            return False
        if local.startswith(".") or local.endswith(".") or ".." in local:
            return False
        return True

    def _search_bing(self, domain):
        """Scrape Bing result pages for emails at the domain.

        Returns (found, ok). ok is False only when every page request failed
        (non-200 / exception); a clean 200 with no emails is a genuine empty."""
        found = set()
        pat = self._email_pattern(domain)
        any_ok = False
        for first in (0, 10, 20):
            url = f"https://www.bing.com/search?q=%22%40{domain}%22&first={first}"
            try:
                resp = http.get(url, timeout=15)
            except Exception as exc:
                self._note_error(f"Bing request error: {exc}")
                continue
            if resp.status_code != 200:
                self._note_error(f"Bing HTTP {resp.status_code}")
                continue
            any_ok = True
            for m in pat.findall(resp.text):
                if self._is_real_email(m):
                    found.add(m.lower())
        return found, any_ok

    def _search_crtsh(self, domain):
        """Collect any emails present in crt.sh certificate transparency JSON.

        Returns (found, ok). ok is False only when crt.sh could not be reached
        (exception / non-200 / empty body); a 200 with '[]' is a genuine empty."""
        found = set()
        pat = self._email_pattern(domain)
        try:
            resp = http.get(
                f"https://crt.sh/?q={domain}&output=json",
                headers={"Accept": "application/json"},
                timeout=25,
            )
        except Exception as exc:
            self._note_error(f"crt.sh request error: {exc}")
            return found, False
        if resp.status_code != 200:
            self._note_error(f"crt.sh HTTP {resp.status_code}")
            return found, False
        if not resp.text:
            self._note_error("crt.sh returned an empty body")
            return found, False
        # Regex over the raw body is robust to crt.sh's occasional malformed JSON.
        for m in pat.findall(resp.text):
            if self._is_real_email(m):
                found.add(m.lower())
        return found, True

    def _has_mx(self, domain):
        if not HAS_DNS:
            return False
        try:
            answers = dns.resolver.resolve(domain, "MX")
            return len(list(answers)) > 0
        except Exception:
            return False

    def run(self):
        if not self.validate():
            return False

        domain = self.get_option("TARGET").strip().lower()
        domain = re.sub(r'^https?://', '', domain).strip("/").split("/")[0]

        if not DOMAIN_RE.match(domain):
            print_status(f"'{domain}' does not look like a valid domain", "error")
            return False

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Domain Email Harvest")
        print(f"  Target: {domain}")
        print(f"{'='*58}{Colors.RESET}\n")

        self._errors = []
        emails = set()
        sources_failed = []

        print_status("Scraping Bing search results...", "info")
        bing, bing_ok = self._search_bing(domain)
        if not bing_ok:
            sources_failed.append("bing")
            print_status("Bing search FAILED (blocked/unreachable) - NOT evidence "
                         "of no emails", "warning")
        if bing:
            print_status(f"Bing: {len(bing)} email(s)", "success")
        emails |= bing

        print_status("Querying crt.sh certificate transparency...", "info")
        crt, crt_ok = self._search_crtsh(domain)
        if not crt_ok:
            sources_failed.append("crt.sh")
            print_status("crt.sh FAILED (unreachable) - NOT evidence of no emails",
                         "warning")
        if crt:
            print_status(f"crt.sh: {len(crt)} email(s)", "success")
        emails |= crt

        print_status("Verifying MX records for role-address plausibility...", "info")
        mx_valid = self._has_mx(domain)
        if not HAS_DNS:
            print_status("dnspython not installed - skipping role addresses", "warning")
        elif mx_valid:
            print_status("MX records found - domain can receive mail", "success")
        else:
            print_status("No MX records - skipping role addresses", "info")

        role_addresses = []
        if mx_valid:
            role_addresses = [f"{p}@{domain}" for p in ROLE_PREFIXES]

        emails_found = sorted(emails)

        self.results = {
            "domain": domain,
            "emails_found": emails_found,
            "count": len(emails_found),
            "mx_valid": mx_valid,
            "role_addresses": role_addresses,
            "sources_failed": sources_failed,
            "fetch_errors": list(self._errors),
        }

        # Both scraped sources failed to fetch -> this is a FETCH FAILURE, never
        # a clean "no emails for this domain" (MX/role data stays in results).
        if not bing_ok and not crt_ok:
            return self._fail()

        for e in emails_found:
            print_status(f"Found: {e}", "success")
        if role_addresses:
            print_status(f"Plausible role addresses (MX-verified): {', '.join(role_addresses)}", "info")

        print_status(f"Done. {len(emails_found)} discovered email(s).", "info")
        print()
        return True
