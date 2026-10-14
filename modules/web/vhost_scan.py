import os
import socket
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_ip
from core import http


INTERNAL_NAMES = [
    "intranet", "internal", "dev", "staging", "stage", "test", "qa", "uat",
    "admin", "portal", "jenkins", "gitlab", "jira", "confluence", "grafana",
    "kibana", "prometheus", "vpn", "mail", "webmail", "api", "api-internal",
    "backend", "beta", "demo", "preprod", "corp", "git", "registry", "vault",
]


class VhostScan(BaseModule):
    name = "web/vhost_scan"
    description = "Virtual host discovery via Host-header brute-force (finds vhosts not in DNS)"
    category = "web"
    target_type = "domain/ip"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain or IP")
        self.add_option("BASE_DOMAIN", "", False, "Apex domain for candidate vhosts (default: TARGET)")
        self.add_option("THREADS", "20", False, "Concurrent requests")
        self.add_option("SCHEME", "https", False, "http or https")

    def _wordlist(self):
        words = list(INTERNAL_NAMES)
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), "wordlists", "subdomains.txt")
        try:
            with open(path, "r", encoding="utf-8") as f:
                words += [line.strip() for line in f if line.strip()
                          and not line.startswith("#")]
        except Exception:
            pass
        return list(dict.fromkeys(words))

    def _request(self, ip, host, scheme):
        url = f"{scheme}://{ip}"
        try:
            # verify=False intentional: virtual-host probing by IP almost always triggers a cert mismatch
            resp = http.get(url, headers={"Host": host}, verify=False,
                            allow_redirects=False, timeout=10)
            return resp.status_code, len(resp.content), self._title(resp.text)
        except Exception:
            return None, None, None

    def _title(self, body):
        if not body:
            return ""
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:80] if m else ""

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        base_domain = self.get_option("BASE_DOMAIN").strip() or (
            target if not is_valid_ip(target) else "")
        threads = max(1, int(self.get_option("THREADS") or 20))
        scheme = self.get_option("SCHEME").strip() or "https"

        if is_valid_ip(target):
            ip = target
        else:
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                print_status(f"Cannot resolve {target}", "error")
                return False

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Virtual Host Scan: {target} ({ip})")
        print(f"{'='*58}{Colors.RESET}\n")

        words = self._wordlist()
        candidates = []
        if base_domain:
            candidates += [f"{w}.{base_domain}" for w in words]
        candidates += words
        candidates = list(dict.fromkeys(candidates))

        # Baseline with a random host
        rand_host = "".join(random.choices(string.ascii_lowercase, k=16)) + ".com"
        base_status, base_len, base_title = self._request(ip, rand_host, scheme)
        print_status(f"Baseline (random host): status={base_status} len={base_len}", "info")

        # Without a baseline the whole differential technique is meaningless:
        # every responding host would "differ" and be flagged. Surface the
        # failure instead of emitting a wall of false positives.
        if base_status is None:
            print_status(f"Baseline request to {ip} failed - cannot run vhost "
                         f"differential; result is UNKNOWN, not 'no vhosts'", "error")
            self.results = {
                "target": target,
                "ip": ip,
                "baseline": {"status": None, "length": None},
                "candidates_tested": len(candidates),
                "vhosts_found": [],
                "vhosts_count": 0,
                "error": "fetch_failed",
            }
            print(f"\n{Colors.BOLD}{Colors.RED}{'='*58}")
            print(f"  Baseline unreachable - vhost scan FAILED")
            print(f"{'='*58}{Colors.RESET}\n")
            return False

        found = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._request, ip, host, scheme): host
                       for host in candidates}
            for future in as_completed(futures):
                host = futures[future]
                status, length, title = future.result()
                if status is None:
                    continue
                # Different response from baseline = candidate vhost
                differs = (status != base_status or
                           (base_len is not None and length is not None
                            and abs(length - base_len) > 200))
                if differs and status not in (0, None):
                    found.append({"vhost": host, "status": status,
                                  "length": length, "title": title})
                    print_status(f"{host} -> status={status} len={length} "
                                 f"{('| ' + title) if title else ''}", "success")

        found.sort(key=lambda x: x["vhost"])

        self.results = {
            "target": target,
            "ip": ip,
            "baseline": {"status": base_status, "length": base_len},
            "candidates_tested": len(candidates),
            "vhosts_found": found,
            "vhosts_count": len(found),
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  {len(found)} candidate vhost(s) found (differ from baseline)")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
