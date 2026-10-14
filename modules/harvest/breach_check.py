import re
import hashlib
from urllib.parse import quote

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http


EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


class BreachCheck(BaseModule):
    """Check whether an email appears in known data breaches via XposedOrNot (free, no key)."""

    name = "harvest/breach_check"
    description = "Check if an email appears in known breaches (XposedOrNot, free, no API key)"
    category = "harvest"
    target_type = "email"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Email address to check against breach databases")
        self.add_option("PASSWORD", "", False,
                        "Optional candidate password to check against HaveIBeenPwned "
                        "Pwned Passwords (k-anonymity: only a 5-char hash prefix "
                        "ever leaves this machine - the password is never sent)")

    def _check_password(self, password):
        """HIBP Pwned Passwords via k-anonymity. Returns (times_seen, error).

        Only the first 5 chars of the SHA-1 are sent; the API returns all
        suffixes in that bucket and the match is done LOCALLY, so the password
        itself is never transmitted."""
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            resp = http.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                            headers={"Add-Padding": "true"}, timeout=20)
        except Exception as e:
            return None, f"request failed: {e}"
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        for line in (resp.text or "").splitlines():
            part, _, count = line.strip().partition(":")
            if part == suffix:
                try:
                    return int(count), None
                except ValueError:
                    return None, "bad count"
        return 0, None   # 200 + not in bucket = never seen

    def _check_email(self, email):
        """Quick check endpoint. Returns (breached_bool_or_None, [site_names]).

        breached is None only when the request/response could not be interpreted
        (network error / unexpected status) so callers never fabricate a verdict.
        """
        url = f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='@._+-')}"
        try:
            resp = http.get(url, headers={"Accept": "application/json"}, timeout=20)
        except Exception as e:
            print_status(f"check-email request failed: {e}", "warning")
            return None, []

        # 404 is the API's documented "not found / clean" response.
        if resp.status_code == 404:
            return False, []
        if resp.status_code != 200:
            print_status(f"check-email returned HTTP {resp.status_code}", "warning")
            return None, []

        try:
            data = resp.json()
        except Exception:
            print_status("check-email returned non-JSON body", "warning")
            return None, []

        breaches = data.get("breaches") if isinstance(data, dict) else None
        names = []
        if isinstance(breaches, list) and breaches:
            first = breaches[0]
            if isinstance(first, list):
                names = [str(b) for b in first if b]
            elif isinstance(first, str):
                names = [str(b) for b in breaches if b]
        return (len(names) > 0), names

    def _breach_analytics(self, email):
        """Rich detail endpoint. Returns (list_of_breach_dicts, classification_str)."""
        details = []
        classification = ""
        try:
            resp = http.get(
                "https://api.xposedornot.com/v1/breach-analytics",
                params={"email": email},
                headers={"Accept": "application/json"},
                timeout=25,
            )
        except Exception as e:
            print_status(f"breach-analytics request failed: {e}", "warning")
            return details, classification

        if resp.status_code == 404:
            return details, classification
        if resp.status_code != 200:
            print_status(f"breach-analytics returned HTTP {resp.status_code}", "warning")
            return details, classification

        try:
            data = resp.json()
        except Exception:
            print_status("breach-analytics returned non-JSON body", "warning")
            return details, classification

        if not isinstance(data, dict):
            return details, classification

        exposed = data.get("ExposedBreaches") or {}
        breaches_details = exposed.get("breaches_details") or []
        for b in breaches_details:
            if not isinstance(b, dict):
                continue
            raw_data = b.get("xposed_data") or ""
            exposed_data = [p.strip() for p in str(raw_data).split(";") if p.strip()]
            details.append({
                "name": b.get("breach", "") or "",
                "date": b.get("xposed_date", "") or "",
                "domain": b.get("domain", "") or "",
                "exposed_data": exposed_data,
                "details": (str(b.get("details") or ""))[:300],
            })

        try:
            risk = (data.get("BreachMetrics") or {}).get("risk") or []
            if isinstance(risk, list) and risk and isinstance(risk[0], dict):
                classification = risk[0].get("risk_label", "") or ""
        except Exception:
            classification = ""

        return details, classification

    def run(self):
        if not self.validate():
            return False

        email = self.get_option("TARGET").strip().lower()
        password = self.get_option("PASSWORD") or ""

        if not EMAIL_RE.match(email):
            print_status(f"'{email}' does not look like a valid email address", "error")
            return False

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Breach Check (XposedOrNot)")
        print(f"  Target: {email}")
        print(f"{'='*58}{Colors.RESET}\n")

        print_status("Querying check-email endpoint...", "info")
        breached_flag, names = self._check_email(email)

        print_status("Querying breach-analytics endpoint...", "info")
        details, classification = self._breach_analytics(email)

        # Prefer the detailed endpoint; fall back to the names from check-email.
        if not details and names:
            details = [
                {"name": n, "date": "", "domain": "", "exposed_data": [], "details": ""}
                for n in names
            ]

        breached = bool(details) or (breached_flag is True)

        # Optional credential-exposure check (k-anonymity, no key).
        pwned_password = None
        if password:
            print_status("Checking the candidate password against Pwned "
                         "Passwords (k-anonymity)...", "info")
            count, err = self._check_password(password)
            if err:
                print_status(f"Pwned Passwords unavailable: {err}", "warning")
                pwned_password = {"checked": True, "available": False}
            else:
                pwned_password = {"checked": True, "available": True,
                                  "times_seen": count, "pwned": count > 0}
                if count > 0:
                    print_status(f"PASSWORD EXPOSED - seen {count:,} time(s) in "
                                 f"breach corpora; do not use it", "warning")
                else:
                    print_status("Password not found in Pwned Passwords", "success")

        self.results = {
            "email": email,
            "breached": breached,
            "breach_count": len(details),
            "breaches": details,
            "classification": classification,
            "pwned_password": pwned_password,
        }

        if breached:
            print_status(f"BREACHED - appears in {len(details)} breach(es)", "warning")
            for b in details:
                line = b["name"] or "(unnamed)"
                if b["date"]:
                    line += f" [{b['date']}]"
                if b["domain"]:
                    line += f" - {b['domain']}"
                print_status(f"  {line}", "success")
                if b["exposed_data"]:
                    print_status(f"    exposed: {', '.join(b['exposed_data'])}", "info")
            if classification:
                print_status(f"Risk classification: {classification}", "info")
        elif breached_flag is False:
            print_status("No breaches found - email appears clean", "success")
        else:
            print_status("Could not determine breach status (API unavailable)", "warning")

        print()
        return True
