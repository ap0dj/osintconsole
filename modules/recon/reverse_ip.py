import socket
from core.base_module import BaseModule
from core.utils import print_status, is_valid_ip, is_valid_domain
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


# HackerTarget returns these as plain text with HTTP 200 when the free-tier
# quota is spent or the query is rejected -- they are failures, not "no data".
_HT_ERROR_MARKERS = (
    "api count exceeded",
    "api usage exceeded",
    "error check your",
)


class ReverseIp(FetchErrorsMixin, BaseModule):
    name = "recon/reverse_ip"
    description = "Reverse IP lookup - find other domains hosted on the same IP (HackerTarget)"
    category = "recon"
    target_type = "domain/ip"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain or IP address")

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()

        if is_valid_ip(target):
            ip = target
        else:
            try:
                ip = socket.gethostbyname(target)
                print_status(f"Resolved {target} -> {ip}", "info")
            except socket.gaierror:
                print_status(f"Cannot resolve {target}", "error")
                return False

        print_status(f"Reverse IP lookup for {ip} (HackerTarget)...", "info")

        self._errors = []
        domains = []
        try:
            resp = http.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                timeout=20,
            )
        except Exception as e:
            self._note_error(f"Reverse IP request failed: {e}")
            return self._fail({"target": target, "ip": ip,
                               "domains": [], "count": 0})

        if resp.status_code != 200:
            self._note_error(f"HackerTarget HTTP {resp.status_code}")
            return self._fail({"target": target, "ip": ip,
                               "domains": [], "count": 0})

        text = (resp.text or "").strip()
        low = text.lower()
        # A quota/rejection body is a FETCH FAILURE, not "0 domains on this IP".
        if low.startswith("error") or any(m in low for m in _HT_ERROR_MARKERS):
            self._note_error(f"HackerTarget quota/rejection: {text[:120]}")
            return self._fail({"target": target, "ip": ip,
                               "domains": [], "count": 0})

        # Parse every line through is_valid_domain; status lines simply aren't
        # valid domains, so nothing fake slips in.
        seen = set()
        for line in text.splitlines():
            candidate = line.strip().lower()
            if candidate and candidate not in seen and is_valid_domain(candidate):
                seen.add(candidate)
                domains.append(candidate)
        domains.sort()

        for d in domains:
            print_status(d, "success")

        self.results = {
            "target": target,
            "ip": ip,
            "domains": domains,
            "count": len(domains),
            "fetch_errors": [],
        }

        if not domains:
            # Reachable, no error marker: a genuine empty result.
            print_status(f"No other domains found on {ip}", "info")
        print_status(f"Found {len(domains)} domain(s) on {ip}", "info")
        return True
