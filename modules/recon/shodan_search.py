import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_ip
from core.config import Config
from core import http


class ShodanSearch(BaseModule):
    name = "recon/shodan_search"
    description = (
        "IP recon - free aggregated sources (InternetDB, ipinfo.io, ipwho.is, "
        "ip-api, GreyNoise, OTX, AbuseIPDB web, crt.sh) + Shodan API when keyed"
    )
    category = "recon"
    target_type = "domain/ip"

    def _register_options(self):
        self.add_option("TARGET", "", True, "IP, domain, or Shodan search query")
        self.add_option("QUERY_MODE", "false", False,
                        "Treat TARGET as a Shodan search query (needs key)")

    # ------------------------------------------------------------------ #
    # Free sources (no API key required)                                 #
    # ------------------------------------------------------------------ #
    def _internetdb(self, ip):
        """Free Shodan InternetDB - no key required."""
        try:
            resp = http.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            return {"_error": str(e)}
        return {}

    def _ipinfo(self, ip):
        """ipinfo.io free tier - org, hostname, country, loc."""
        try:
            resp = http.get(f"https://ipinfo.io/{ip}/json")
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            return {"_error": str(e)}
        return {}

    def _ipwho(self, ip):
        """ipwho.is - ASN, ISP, connection type, timezone (no limits)."""
        try:
            resp = http.get(f"https://ipwho.is/{ip}")
            if resp.status_code == 200:
                d = resp.json()
                if d.get("success", True):
                    return d
        except Exception as e:
            return {"_error": str(e)}
        return {}

    def _ipapi(self, ip):
        """IP network/geo lookup (ip-api free tier over HTTP, ipwho.is fallback).

        The https:// ip-api endpoint is paid-only and returned 403 on every
        call, so this probe had been silently failing."""
        from core import geoip
        return geoip.lookup(ip) or {}

    def _greynoise(self, ip):
        """GreyNoise Community API - noise, riot, classification. 404 = unknown."""
        try:
            resp = http.get(f"https://api.greynoise.io/v3/community/{ip}",
                            headers={"Accept": "application/json"})
            if resp.status_code in (200, 404):
                return resp.json()
        except Exception as e:
            return {"_error": str(e)}
        return {}

    def _otx(self, ip):
        """AlienVault OTX general indicator - pulses, reputation, geo."""
        try:
            resp = http.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general")
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            return {"_error": str(e)}
        return {}

    def _abuseipdb_web(self, ip):
        """Scrape the public AbuseIPDB check page - no key needed."""
        try:
            resp = http.get(f"https://www.abuseipdb.com/check/{ip}",
                            headers={"Accept": "text/html"})
            if resp.status_code != 200:
                return {}
            html = resp.text
            result = {}
            m = re.search(
                r'(\d+)\s*reports?\s*from\s*(\d+)\s*distinct\s*users?',
                html, re.I)
            if m:
                result["reports"] = int(m.group(1))
                result["distinct_users"] = int(m.group(2))
            m = re.search(r'(\d+)%\s*(?:confidence|likely|abuse)', html, re.I)
            if m:
                result["abuse_confidence"] = int(m.group(1))
            m = re.search(r'<b>Usage Type:</b>\s*</td>\s*<td[^>]*>([^<]+)</td>',
                          html, re.I)
            if m:
                result["usage_type"] = m.group(1).strip()
            m = re.search(r'<b>ISP:</b>\s*</td>\s*<td[^>]*>([^<]+)</td>',
                          html, re.I)
            if m:
                result["isp"] = m.group(1).strip()
            m = re.search(
                r'<b>Domain Name:</b>\s*</td>\s*<td[^>]*>\s*<[^>]*>([^<]+)</',
                html, re.I)
            if m:
                result["domain"] = m.group(1).strip()
            return result
        except Exception as e:
            return {"_error": str(e)}

    def _crtsh_ip(self, ip):
        """Certificate transparency - domains with certs tying to this IP (SANs)."""
        try:
            resp = http.get(f"https://crt.sh/?q={ip}&output=json", timeout=25)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    return []
                sans = set()
                for entry in data[:400]:
                    for n in (entry.get("name_value") or "").split("\n"):
                        n = n.strip().lstrip("*.").lower()
                        if n:
                            sans.add(n)
                return sorted(sans)[:200]
        except Exception:
            return []
        return []

    # ------------------------------------------------------------------ #
    # Paid Shodan API (unchanged behaviour, only runs when key is set)   #
    # ------------------------------------------------------------------ #
    def _host_full(self, ip, key):
        try:
            resp = http.get(f"https://api.shodan.io/shodan/host/{ip}",
                            params={"key": key})
            if resp.status_code == 200:
                return resp.json()
            print_status(f"Shodan API returned {resp.status_code}", "warning")
        except Exception as e:
            print_status(f"Shodan host error: {e}", "warning")
        return {}

    def _search(self, query, key):
        try:
            resp = http.get("https://api.shodan.io/shodan/host/search",
                            params={"key": key, "query": query})
            if resp.status_code == 200:
                return resp.json()
            print_status(f"Shodan search returned {resp.status_code}", "warning")
        except Exception as e:
            print_status(f"Shodan search error: {e}", "warning")
        return {}

    # ------------------------------------------------------------------ #
    # Driver                                                              #
    # ------------------------------------------------------------------ #
    def _best(self, best, key, value):
        if value and best.get(key) in (None, "", 0):
            best[key] = value

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        query_mode = self.get_option("QUERY_MODE").lower() == "true"
        config = Config()
        key = config.get("api_keys.shodan")

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Shodan Search: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        # --- Shodan search-query mode (requires paid key) ---
        if query_mode:
            if not key:
                print_status("Search queries require a Shodan API key "
                             "(config set api_keys.shodan ...)", "error")
                return False
            print_status(f"Searching Shodan: {target}", "info")
            data = self._search(target, key)
            matches = data.get("matches", [])
            results = []
            for m in matches[:50]:
                entry = {
                    "ip": m.get("ip_str"),
                    "port": m.get("port"),
                    "org": m.get("org"),
                    "product": m.get("product"),
                    "location": f"{(m.get('location') or {}).get('city')}, "
                                f"{(m.get('location') or {}).get('country_name')}",
                }
                results.append(entry)
                print_status(f"{entry['ip']}:{entry['port']} - {entry['org']} "
                             f"({entry['product']})", "success")
            self.results = {"query": target, "total": data.get("total", 0),
                            "matches": results}
            print_status(f"Total results: {data.get('total', 0)}", "info")
            return True

        # --- Host mode ---
        if is_valid_ip(target):
            ip = target
        else:
            try:
                ip = socket.gethostbyname(target)
                print_status(f"Resolved {target} -> {ip}", "info")
            except socket.gaierror:
                print_status(f"Cannot resolve {target}", "error")
                return False

        if key:
            print_status("Shodan API key present - free sources run in "
                         "parallel for cross-reference", "info")
        else:
            print_status("No Shodan API key - aggregating 8 FREE sources", "info")

        probes = [
            ("InternetDB",     self._internetdb),
            ("ipinfo.io",      self._ipinfo),
            ("ipwho.is",       self._ipwho),
            ("ip-api.com",     self._ipapi),
            ("GreyNoise",      self._greynoise),
            ("AlienVault OTX", self._otx),
            ("AbuseIPDB web",  self._abuseipdb_web),
            ("crt.sh certs",   self._crtsh_ip),
        ]
        total = len(probes)
        collected = {}
        failures = []

        with ThreadPoolExecutor(max_workers=6) as executor:
            future_map = {executor.submit(fn, ip): label for label, fn in probes}
            idx = 0
            for future in as_completed(future_map):
                idx += 1
                label = future_map[future]
                try:
                    data = future.result()
                except Exception as e:
                    data = {"_error": str(e)}
                collected[label] = data

                err = isinstance(data, dict) and data.get("_error")
                empty = (not data) or (
                    isinstance(data, dict) and
                    not any(v for k, v in data.items() if not k.startswith("_")))
                if err or empty:
                    failures.append(label)
                    reason = err if err else "no data"
                    print_status(f"[{idx}/{total}] {label}: FAILED ({reason})",
                                 "warning")
                    continue

                if label == "InternetDB":
                    ports = data.get("ports", []) if isinstance(data, dict) else []
                    extra = f" {','.join(map(str, ports[:8]))}" if ports else ""
                    print_status(
                        f"[{idx}/{total}] InternetDB: {len(ports)} port(s){extra}",
                        "success")
                elif label == "ipinfo.io":
                    print_status(
                        f"[{idx}/{total}] ipinfo.io: {data.get('org', '?')} / "
                        f"{data.get('country', '?')}", "success")
                elif label == "ipwho.is":
                    conn = data.get("connection") or {}
                    print_status(
                        f"[{idx}/{total}] ipwho.is: AS{conn.get('asn', '?')} "
                        f"{conn.get('isp', '?')} / {data.get('country', '?')}",
                        "success")
                elif label == "ip-api.com":
                    flags = [f for f in ("proxy", "hosting", "mobile")
                             if data.get(f)]
                    print_status(
                        f"[{idx}/{total}] ip-api.com: {data.get('as', '?')} "
                        f"flags={','.join(flags) or 'none'}", "success")
                elif label == "GreyNoise":
                    print_status(
                        f"[{idx}/{total}] GreyNoise: noise={data.get('noise')} "
                        f"riot={data.get('riot')} "
                        f"class={data.get('classification', 'unknown')}",
                        "success")
                elif label == "AlienVault OTX":
                    pulses = (data.get("pulse_info") or {}).get("count", 0)
                    print_status(
                        f"[{idx}/{total}] AlienVault OTX: {pulses} pulse(s) "
                        f"geo={data.get('country_name', '?')}", "success")
                elif label == "AbuseIPDB web":
                    print_status(
                        f"[{idx}/{total}] AbuseIPDB web: "
                        f"{data.get('reports', 0)} reports "
                        f"confidence={data.get('abuse_confidence')}%",
                        "success")
                elif label == "crt.sh certs":
                    print_status(
                        f"[{idx}/{total}] crt.sh certs: {len(data)} SAN(s)",
                        "success")

        idb = collected.get("InternetDB") or {}
        ipinfo = collected.get("ipinfo.io") or {}
        ipwho = collected.get("ipwho.is") or {}
        ipapi = collected.get("ip-api.com") or {}
        gn = collected.get("GreyNoise") or {}
        otx = collected.get("AlienVault OTX") or {}
        abuse_web = collected.get("AbuseIPDB web") or {}
        certs = collected.get("crt.sh certs") or []

        # --- Paid Shodan API (unchanged) ---
        full = {}
        if key:
            print_status("Querying full Shodan API...", "info")
            full = self._host_full(ip, key)

        # --- Unified best-of-breed summary (free sources + Shodan if keyed) ---
        open_ports = set(idb.get("ports", []) or [])
        if full:
            for item in full.get("data", []):
                if item.get("port"):
                    open_ports.add(item["port"])
        open_ports = sorted(open_ports)
        known_vulns = sorted(set(idb.get("vulns", []) or []))

        best = {}
        for src in (full, ipapi, ipinfo, ipwho):
            if not isinstance(src, dict):
                continue
            self._best(best, "org", src.get("org") or src.get("as"))
            self._best(best, "isp", src.get("isp"))
            asn = src.get("as") or src.get("asn")
            if not asn and isinstance(src.get("connection"), dict):
                asn = src["connection"].get("asn")
            self._best(best, "asn", asn)
            self._best(best, "country",
                       src.get("country") or src.get("country_name"))
            self._best(best, "city", src.get("city"))
            host = None
            if isinstance(src.get("hostnames"), list) and src["hostnames"]:
                host = src["hostnames"][0]
            elif src.get("hostname"):
                host = src.get("hostname")
            self._best(best, "hostname", host)

        threat_signals = {
            "greynoise_noise": gn.get("noise"),
            "greynoise_riot": gn.get("riot"),
            "greynoise_classification": gn.get("classification"),
            "otx_pulses": (otx.get("pulse_info") or {}).get("count", 0)
                          if isinstance(otx, dict) else 0,
            "abuseipdb_reports": abuse_web.get("reports"),
            "abuseipdb_confidence": abuse_web.get("abuse_confidence"),
            "ip_api_proxy": ipapi.get("proxy"),
            "ip_api_hosting": ipapi.get("hosting"),
            "ip_api_mobile": ipapi.get("mobile"),
            "internetdb_tags": idb.get("tags", []),
            "internetdb_vulns": idb.get("vulns", []),
        }

        self.results = {
            "target": target,
            "ip": ip,
            "internetdb": {
                "ports": idb.get("ports", []),
                "hostnames": idb.get("hostnames", []),
                "vulns": idb.get("vulns", []),
                "tags": idb.get("tags", []),
                "cpes": idb.get("cpes", []),
            } if idb else {},
            "ipinfo": ipinfo,
            "ipwho": ipwho,
            "ip_api": ipapi,
            "greynoise": gn,
            "otx": otx,
            "abuseipdb_web": abuse_web,
            "crt_certs": certs,
            "free_summary": {
                "open_ports": open_ports,
                "known_vulns": known_vulns,
                "org": best.get("org"),
                "isp": best.get("isp"),
                "asn": best.get("asn"),
                "country": best.get("country"),
                "city": best.get("city"),
                "hostname": best.get("hostname"),
                "threat_signals": threat_signals,
                "sources_hit": total - len(failures),
                "sources_failed": failures,
            },
        }

        if full:
            services = []
            for item in full.get("data", []):
                services.append({
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "banner": (item.get("data", "") or "")[:200],
                })
            self.results["shodan"] = {
                "org": full.get("org"),
                "isp": full.get("isp"),
                "os": full.get("os"),
                "country": full.get("country_name"),
                "city": full.get("city"),
                "last_update": full.get("last_update"),
                "services": services,
            }
            print_status(
                f"Shodan: Org={full.get('org')} | ISP={full.get('isp')}",
                "success")
            for s in services:
                print_status(f"  Port {s['port']}/{s['transport']}: "
                             f"{s['product']} {s['version'] or ''}", "success")

        # --- Threat / vuln callouts ---
        if known_vulns:
            print_status(f"VULNS: {', '.join(known_vulns[:10])}", "warning")
        if idb.get("tags"):
            print_status(f"Tags: {', '.join(idb['tags'])}", "warning")
        if gn.get("classification") == "malicious":
            print_status("GreyNoise classification: MALICIOUS", "warning")
        otx_pulses = threat_signals["otx_pulses"]
        if otx_pulses:
            print_status(f"OTX pulses: {otx_pulses} (threat-intel hits)",
                         "warning")
        if abuse_web.get("abuse_confidence") and \
                abuse_web["abuse_confidence"] >= 25:
            print_status(
                f"AbuseIPDB confidence: {abuse_web['abuse_confidence']}% "
                f"({abuse_web.get('reports')} reports)", "warning")

        got_any = any(
            bool(v) and not (isinstance(v, dict) and "_error" in v)
            for v in collected.values()) or bool(full)
        if not got_any:
            print_status("No data from any source for this host", "warning")
            return False

        key_note = "configured" if key else "NOT configured (free sources only)"
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Free sources: {total - len(failures)}/{total} worked"
              + (f", failed: {', '.join(failures)}" if failures else ""))
        print(f"  Open ports (unified): "
              f"{', '.join(map(str, open_ports)) or 'none'}")
        print(f"  Shodan paid API: {key_note}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")
        return True
