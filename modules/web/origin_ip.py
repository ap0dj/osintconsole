import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_domain
from core.config import Config
from core import http

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


CLOUDFLARE_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# Partial ranges for other CDNs/WAFs - used to flag (not exhaustive)
OTHER_CDN = {
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "Incapsula": ["199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21",
                  "103.28.248.0/22", "45.64.64.0/22", "185.11.124.0/22"],
    "Sucuri": ["192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22"],
    "Akamai": ["23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"],
}

ORIGIN_SUBS = [
    "direct", "origin", "direct-connect", "cpanel", "webmail", "mail", "ftp",
    "ns1", "ns2", "dev", "staging", "test", "vpn", "remote", "server", "web",
    "host", "mx", "email", "autodiscover", "portal", "admin", "old", "beta",
    "backup", "whm", "webdisk", "ssh", "db", "sql", "secure", "gateway", "cpanel",
    "www2", "direct1", "mailserver", "smtp", "pop", "imap",
]


class OriginIp(BaseModule):
    name = "web/origin_ip"
    description = "Find the real origin IP behind Cloudflare/CDN (MX/SPF/subdomains/crt.sh/Shodan + live verification)"
    category = "web"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Domain name")
        self.add_option("VERIFY", "true", False, "Verify candidates actually serve the site")
        self.add_option("THREADS", "20", False, "Concurrent lookups")

    # --- CDN classification ---
    def _cdn_name(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "invalid"
        for net in self._cf_nets:
            if addr in net:
                return "Cloudflare"
        for name, ranges in OTHER_CDN.items():
            for cidr in ranges:
                if addr in ipaddress.ip_network(cidr):
                    return name
        return None

    # --- DNS helpers ---
    def _resolve(self, host):
        ips = set()
        try:
            for info in socket.getaddrinfo(host, None, socket.AF_INET):
                ips.add(info[4][0])
        except Exception:
            pass
        return ips

    def _a_records(self, domain):
        return self._resolve(domain)

    def _mx_ips(self, domain):
        ips, hosts = set(), []
        if not HAS_DNS:
            return ips, hosts
        try:
            for r in dns.resolver.resolve(domain, "MX"):
                mx_host = str(r.exchange).rstrip(".")
                hosts.append(mx_host)
                ips |= self._resolve(mx_host)
        except Exception:
            pass
        return ips, hosts

    def _spf_ips(self, domain):
        ips = set()
        if not HAS_DNS:
            return ips
        try:
            for r in dns.resolver.resolve(domain, "TXT"):
                txt = str(r).strip('"')
                if "v=spf1" in txt.lower():
                    for m in re.findall(r"ip4:([0-9.]+)(?:/\d+)?", txt):
                        ips.add(m)
        except Exception:
            pass
        return ips

    def _subdomain_ips(self, domain, threads):
        found = {}

        def check(sub):
            host = f"{sub}.{domain}"
            return host, self._resolve(host)

        with ThreadPoolExecutor(max_workers=threads) as ex:
            for host, ips in ex.map(check, ORIGIN_SUBS):
                for ip in ips:
                    found.setdefault(ip, []).append(host)
        return found

    def _crtsh_ips(self, domain, threads):
        subs = set()
        try:
            resp = http.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and "@" not in name:
                            subs.add(name)
        except Exception:
            pass
        subs = list(subs)[:60]
        found = {}
        if not subs:
            return found
        with ThreadPoolExecutor(max_workers=threads) as ex:
            results = ex.map(lambda h: (h, self._resolve(h)), subs)
            for host, ips in results:
                for ip in ips:
                    found.setdefault(ip, []).append(host)
        return found

    def _securitytrails(self, domain, key):
        ips = set()
        try:
            resp = http.get(f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                            headers={"APIKEY": key}, timeout=15)
            if resp.status_code == 200:
                for rec in resp.json().get("records", []):
                    for v in rec.get("values", []):
                        if v.get("ip"):
                            ips.add(v["ip"])
        except Exception:
            pass
        return ips

    def _shodan(self, domain, key):
        ips = set()
        queries = [f'ssl.cert.subject.CN:"{domain}"', f'ssl:"{domain}"',
                   f'http.html:"{domain}"']
        for q in queries:
            try:
                resp = http.get("https://api.shodan.io/shodan/host/search",
                                params={"key": key, "query": q}, timeout=20)
                if resp.status_code == 200:
                    for m in resp.json().get("matches", []):
                        if m.get("ip_str"):
                            ips.add(m["ip_str"])
            except Exception:
                pass
        return ips

    # --- Verification ---
    def _title(self, body):
        if not body:
            return ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""

    def _baseline(self, domain):
        for scheme in ("https", "http"):
            try:
                # verify=False intentional: origin IPs intentionally serve mismatched certs
                resp = http.get(f"{scheme}://{domain}", verify=False,
                                allow_redirects=True, timeout=12)
                return {"status": resp.status_code, "title": self._title(resp.text),
                        "len": len(resp.content)}
            except Exception:
                continue
        return {}

    def _verify(self, ip, domain, baseline):
        for scheme in ("https", "http"):
            try:
                resp = http.get(f"{scheme}://{ip}", headers={"Host": domain},
                                verify=False, allow_redirects=False, timeout=12)
                title = self._title(resp.text)
                # Strong signal: same page title; fallback: 200 + similar size
                if baseline.get("title") and title and title == baseline["title"]:
                    return True, f"title match ('{title[:40]}')"
                if (resp.status_code == 200 and baseline.get("len")
                        and abs(len(resp.content) - baseline["len"]) < baseline["len"] * 0.1
                        and baseline["len"] > 0):
                    return True, f"content size match (~{len(resp.content)}b, HTTP 200)"
            except Exception:
                continue
        return False, None

    def run(self):
        if not self.validate():
            return False

        domain = self.get_option("TARGET").strip().lower().replace("https://", "").replace("http://", "").strip("/")
        verify = self.get_option("VERIFY").lower() == "true"
        threads = max(1, int(self.get_option("THREADS") or 20))
        config = Config()
        self._cf_nets = [ipaddress.ip_network(c) for c in CLOUDFLARE_V4]

        if not is_valid_domain(domain):
            print_status(f"Invalid domain: {domain}", "error")
            return False

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Origin IP Finder: {domain}")
        print(f"{'='*60}{Colors.RESET}\n")

        # 1. Front-facing A records + CDN detection
        a_ips = self._a_records(domain)
        fronting = None
        for ip in a_ips:
            cdn = self._cdn_name(ip)
            if cdn and cdn != "invalid":
                fronting = cdn
                break
        print_status(f"A records: {', '.join(sorted(a_ips)) or 'none'}", "info")
        if fronting:
            print_status(f"Domain is behind {fronting} - searching for origin...", "warning")
        else:
            print_status("No known CDN detected on A records (origin may be direct)", "info")

        # 2. Gather candidates from every technique
        candidates = {}   # ip -> list of sources

        def add(ip, source):
            if ip:
                candidates.setdefault(ip, [])
                if source not in candidates[ip]:
                    candidates[ip].append(source)

        print_status("[1] MX records...", "info")
        mx_ips, mx_hosts = self._mx_ips(domain)
        for ip in mx_ips:
            add(ip, "MX")

        print_status("[2] SPF / TXT records...", "info")
        for ip in self._spf_ips(domain):
            add(ip, "SPF")

        print_status("[3] Non-proxied subdomains...", "info")
        for ip, hosts in self._subdomain_ips(domain, threads).items():
            add(ip, f"subdomain:{hosts[0]}")

        print_status("[4] Certificate transparency (crt.sh)...", "info")
        for ip, hosts in self._crtsh_ips(domain, threads).items():
            add(ip, f"crtsh:{hosts[0]}")

        st_key = config.get("api_keys.securitytrails")
        if st_key:
            print_status("[5] SecurityTrails DNS history...", "info")
            for ip in self._securitytrails(domain, st_key):
                add(ip, "dns_history")

        sh_key = config.get("api_keys.shodan")
        if sh_key:
            print_status("[6] Shodan SSL/HTML search...", "info")
            for ip in self._shodan(domain, sh_key):
                add(ip, "shodan")

        # 3. Classify: drop CDN IPs, keep real-looking origins
        origins = {}
        cdn_ips = {}
        for ip, sources in candidates.items():
            cdn = self._cdn_name(ip)
            if cdn and cdn != "invalid":
                cdn_ips[ip] = cdn
            elif cdn != "invalid":
                origins[ip] = {"sources": sources}

        print_status(f"Collected {len(candidates)} candidate IP(s): "
                     f"{len(origins)} non-CDN, {len(cdn_ips)} CDN-owned", "info")

        # 4. Verify candidates actually serve the target site
        baseline = self._baseline(domain) if verify else {}
        confirmed = []
        if verify and origins:
            print_status("[verify] Checking which candidates serve the site "
                         f"(baseline title: '{baseline.get('title', '')[:40]}')...", "info")
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futs = {ex.submit(self._verify, ip, domain, baseline): ip for ip in origins}
                for fut in as_completed(futs):
                    ip = futs[fut]
                    ok, reason = fut.result()
                    origins[ip]["verified"] = ok
                    origins[ip]["verify_reason"] = reason
                    if ok:
                        confirmed.append(ip)
                        print_status(f"CONFIRMED ORIGIN: {ip} ({reason}) "
                                     f"[via {', '.join(origins[ip]['sources'])}]", "success")

        self.results = {
            "domain": domain,
            "a_records": sorted(a_ips),
            "fronting_cdn": fronting,
            "confirmed_origins": confirmed,
            "candidates": {ip: origins[ip] for ip in origins},
            "cdn_owned_ips": cdn_ips,
            "mx_hosts": mx_hosts,
        }

        # --- Summary ---
        color = Colors.RED if confirmed else Colors.YELLOW if origins else Colors.GREEN
        print(f"\n{Colors.BOLD}{color}{'='*60}")
        if confirmed:
            print(f"  REAL ORIGIN IP(S) FOUND for {domain}:")
            for ip in confirmed:
                print(f"    {Colors.GREEN}>>> {ip}{Colors.RESET}  "
                      f"[{', '.join(origins[ip]['sources'])}]")
            if fronting:
                print(f"  (bypasses {fronting})")
        elif origins:
            print(f"  {len(origins)} unverified candidate(s) "
                  f"(couldn't confirm they serve the site):")
            for ip in list(origins)[:10]:
                print(f"    ? {ip}  [{', '.join(origins[ip]['sources'])}]")
        else:
            print(f"  No origin IP found outside the CDN")
        print(f"{Colors.BOLD}{color}{'='*60}{Colors.RESET}\n")

        return True
