import re
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


class DnsHistory(BaseModule):
    name = "recon/dns_history"
    description = (
        "DNS history - crt.sh + Wayback + OTX passive DNS + "
        "ViewDNS + HackerTarget (free), SecurityTrails when keyed"
    )
    category = "recon"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Domain name")

    # ------------------------------------------------------------------ #
    # Current records                                                     #
    # ------------------------------------------------------------------ #
    def _current_records(self, domain):
        records = {}
        if not HAS_DNS:
            return records
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r).strip() for r in answers]
            except Exception:
                pass
        return records

    # ------------------------------------------------------------------ #
    # Free historical sources                                             #
    # ------------------------------------------------------------------ #
    def _crtsh(self, domain):
        """Certificate transparency - historical subdomain issuance."""
        subs = {}
        try:
            resp = http.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                            timeout=25)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    return {"subdomains": {}}
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.").lower()
                        if sub and domain in sub:
                            nb = entry.get("not_before", "")
                            na = entry.get("not_after", "")
                            cur = subs.get(sub)
                            if not cur:
                                subs[sub] = {"first_seen": nb, "last_seen": na}
                            else:
                                if nb and (not cur["first_seen"]
                                           or nb < cur["first_seen"]):
                                    cur["first_seen"] = nb
                                if na and (not cur["last_seen"]
                                           or na > cur["last_seen"]):
                                    cur["last_seen"] = na
        except Exception as e:
            return {"_error": str(e), "subdomains": {}}
        return {"subdomains": subs}

    def _wayback(self, domain):
        """Wayback CDX - archived URLs reveal hostnames + timestamps."""
        try:
            resp = http.get(
                "http://web.archive.org/cdx/search/cdx",
                params={"url": f"*.{domain}/*", "output": "json",
                        "fl": "original,timestamp",
                        "collapse": "urlkey", "limit": "500"},
                timeout=25)
            if resp.status_code != 200:
                return {"hostnames": {}}
            try:
                rows = resp.json()
            except Exception:
                return {"hostnames": {}}
            host_times = {}
            host_re = re.compile(r'https?://([^/]+)')
            for row in rows[1:]:  # row[0] is the header
                if len(row) < 2:
                    continue
                url, ts = row[0], row[1]
                m = host_re.match(url)
                if not m:
                    continue
                host = m.group(1).split(":")[0].lower()
                if domain not in host:
                    continue
                existing = host_times.get(host)
                if not existing:
                    host_times[host] = {"first_seen": ts, "last_seen": ts}
                else:
                    if ts < existing["first_seen"]:
                        existing["first_seen"] = ts
                    if ts > existing["last_seen"]:
                        existing["last_seen"] = ts
            return {"hostnames": host_times}
        except Exception as e:
            return {"_error": str(e), "hostnames": {}}

    def _otx_passive(self, domain):
        """AlienVault OTX passive DNS."""
        try:
            resp = http.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/"
                f"{domain}/passive_dns",
                timeout=20)
            if resp.status_code == 200:
                try:
                    d = resp.json()
                except Exception:
                    return {"resolutions": []}
                res = []
                for r in d.get("passive_dns", []):
                    res.append({"ip": r.get("address") or r.get("hostname"),
                                "first_seen": r.get("first"),
                                "last_seen": r.get("last"),
                                "record_type": r.get("record_type"),
                                "source": "otx"})
                return {"resolutions": res}
        except Exception as e:
            return {"_error": str(e), "resolutions": []}
        return {"resolutions": []}

    def _viewdns(self, domain):
        """Scrape ViewDNS.info /iphistory/ page HTML table."""
        try:
            resp = http.get("https://viewdns.info/iphistory/",
                            params={"domain": domain},
                            headers={"Accept": "text/html"}, timeout=20)
            if resp.status_code != 200:
                return {"resolutions": []}
            html = resp.text
            rows = re.findall(
                r'<tr>\s*<td[^>]*>\s*(\d+\.\d+\.\d+\.\d+)\s*</td>\s*'
                r'<td[^>]*>([^<]*)</td>\s*<td[^>]*>([^<]*)</td>\s*'
                r'<td[^>]*>([^<]*)</td>\s*</tr>',
                html, re.I)
            res = []
            for ip, loc, owner, date in rows:
                res.append({"ip": ip,
                            "location": loc.strip(),
                            "owner": owner.strip(),
                            "first_seen": date.strip(),
                            "last_seen": date.strip(),
                            "source": "viewdns"})
            return {"resolutions": res}
        except Exception as e:
            return {"_error": str(e), "resolutions": []}

    def _hackertarget(self, domain):
        """HackerTarget - DNS lookup + reverse host search (50/day quota)."""
        out = {"records": [], "hosts": []}
        try:
            resp = http.get("https://api.hackertarget.com/dnslookup/",
                            params={"q": domain}, timeout=15)
            text = resp.text if resp.status_code == 200 else ""
            if text and "API count exceeded" not in text \
                    and not text.lower().startswith("error"):
                for line in text.splitlines():
                    line = line.strip()
                    if ":" not in line:
                        continue
                    rtype, _, value = line.partition(":")
                    out["records"].append({"type": rtype.strip(),
                                           "value": value.strip()})
            else:
                out["_error"] = (text or "").strip()[:120]
        except Exception as e:
            out["_error"] = str(e)

        try:
            r2 = http.get("https://api.hackertarget.com/hostsearch/",
                          params={"q": domain}, timeout=15)
            if r2.status_code == 200 and "API count exceeded" not in r2.text:
                for line in r2.text.splitlines():
                    if "," in line:
                        host, ip = line.split(",", 1)
                        out["hosts"].append({"ip": ip.strip(),
                                             "hostname": host.strip(),
                                             "source": "hackertarget"})
        except Exception:
            pass
        return out

    # ------------------------------------------------------------------ #
    # Paid API (unchanged, only when keyed)                               #
    # ------------------------------------------------------------------ #
    def _securitytrails_history(self, domain, key):
        history = {}
        headers = {"APIKEY": key, "Accept": "application/json"}
        for rtype in ("a", "mx", "ns", "txt"):
            try:
                resp = http.get(
                    f"https://api.securitytrails.com/v1/history/"
                    f"{domain}/dns/{rtype}",
                    headers=headers, timeout=15)
                if resp.status_code == 200:
                    records = resp.json().get("records", [])
                    entries = []
                    for rec in records:
                        values = rec.get("values", [])
                        vals = [v.get("ip") or v.get("value")
                                or v.get("nameserver") or v.get("host")
                                for v in values]
                        entries.append({
                            "first_seen": rec.get("first_seen"),
                            "last_seen": rec.get("last_seen"),
                            "values": [v for v in vals if v],
                        })
                    history[rtype.upper()] = entries
                elif resp.status_code == 429:
                    print_status("SecurityTrails rate limit hit", "warning")
            except Exception:
                pass
        return history

    # ------------------------------------------------------------------ #
    def run(self):
        if not self.validate():
            return False

        domain = self.get_option("TARGET").strip().lower()
        if not is_valid_domain(domain):
            print_status(f"Invalid domain: {domain}", "error")
            return False

        config = Config()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  DNS History: {domain}")
        print(f"{'='*58}{Colors.RESET}\n")

        # --- Current live DNS ---
        print_status("Fetching current DNS records...", "info")
        current = self._current_records(domain)
        for rtype, values in current.items():
            for v in values:
                print_status(f"{rtype}: {v}", "success")

        # --- Free historical probes in parallel ---
        probes = [
            ("crt.sh",         self._crtsh),
            ("Wayback CDX",    self._wayback),
            ("AlienVault OTX", self._otx_passive),
            ("ViewDNS.info",   self._viewdns),
            ("HackerTarget",   self._hackertarget),
        ]
        total = len(probes)
        print_status(f"Querying {total} free historical sources in parallel...",
                     "info")
        collected = {}
        failures = []
        with ThreadPoolExecutor(max_workers=6) as executor:
            future_map = {executor.submit(fn, domain): label
                          for label, fn in probes}
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
                has_payload = (
                    isinstance(data, dict)
                    and any(bool(v) for k, v in data.items()
                            if not k.startswith("_"))
                )
                if err or not has_payload:
                    failures.append(label)
                    note = f" ({err})" if err else ""
                    print_status(f"[{idx}/{total}] {label}: no data{note}",
                                 "warning")
                    continue

                if label == "crt.sh":
                    print_status(
                        f"[{idx}/{total}] crt.sh: "
                        f"{len(data.get('subdomains', {}))} subdomain(s)",
                        "success")
                elif label == "Wayback CDX":
                    print_status(
                        f"[{idx}/{total}] Wayback CDX: "
                        f"{len(data.get('hostnames', {}))} host(s) in archive",
                        "success")
                elif label == "AlienVault OTX":
                    print_status(
                        f"[{idx}/{total}] OTX passive DNS: "
                        f"{len(data.get('resolutions', []))} record(s)",
                        "success")
                elif label == "ViewDNS.info":
                    print_status(
                        f"[{idx}/{total}] ViewDNS: "
                        f"{len(data.get('resolutions', []))} IP history row(s)",
                        "success")
                elif label == "HackerTarget":
                    print_status(
                        f"[{idx}/{total}] HackerTarget: "
                        f"{len(data.get('records', []))} records, "
                        f"{len(data.get('hosts', []))} subdomains",
                        "success")

        crtsh = collected.get("crt.sh") or {}
        wayback = collected.get("Wayback CDX") or {}
        otx = collected.get("AlienVault OTX") or {}
        viewdns = collected.get("ViewDNS.info") or {}
        hackertarget = collected.get("HackerTarget") or {}

        # --- Paid API (unchanged) ---
        st_history = {}
        key = config.get("api_keys.securitytrails")
        if key:
            print_status("Fetching SecurityTrails DNS history (paid)...", "info")
            st_history = self._securitytrails_history(domain, key)
            for rtype, entries in st_history.items():
                print_status(f"{rtype} history: {len(entries)} record change(s)",
                             "success")
        else:
            print_status(
                "SecurityTrails key not set - free sources above provide the "
                "historical signal", "info")

        # --- Unified historical_resolutions list ---
        unified_raw = []
        for r in otx.get("resolutions", []):
            if r.get("ip"):
                unified_raw.append({"ip": r["ip"],
                                    "first_seen": r.get("first_seen"),
                                    "last_seen": r.get("last_seen"),
                                    "source": "otx"})
        for r in viewdns.get("resolutions", []):
            if r.get("ip"):
                unified_raw.append({"ip": r["ip"],
                                    "first_seen": r.get("first_seen"),
                                    "last_seen": r.get("last_seen"),
                                    "source": "viewdns"})
        for r in hackertarget.get("hosts", []):
            if r.get("ip") and (r.get("hostname") == domain
                                or r.get("hostname") == f"www.{domain}"):
                unified_raw.append({"ip": r["ip"],
                                    "first_seen": None, "last_seen": None,
                                    "source": "hackertarget"})
        for entry in st_history.get("A", []):
            for v in entry.get("values", []):
                unified_raw.append({"ip": v,
                                    "first_seen": entry.get("first_seen"),
                                    "last_seen": entry.get("last_seen"),
                                    "source": "securitytrails"})

        # Dedupe (ip, source), widen window on dup
        dedup = {}
        for u in unified_raw:
            k = (u["ip"], u["source"])
            if k not in dedup:
                dedup[k] = u
            else:
                prev = dedup[k]
                if u["first_seen"] and (not prev["first_seen"]
                                        or u["first_seen"] < prev["first_seen"]):
                    prev["first_seen"] = u["first_seen"]
                if u["last_seen"] and (not prev["last_seen"]
                                       or u["last_seen"] > prev["last_seen"]):
                    prev["last_seen"] = u["last_seen"]
        unified = list(dedup.values())

        # --- Unified subdomain list across all sources ---
        all_subs = set()
        for s in (crtsh.get("subdomains") or {}).keys():
            all_subs.add(s)
        for s in wayback.get("hostnames", {}).keys():
            all_subs.add(s)
        for r in hackertarget.get("hosts", []):
            if r.get("hostname"):
                all_subs.add(r["hostname"].lower())
        subs_sorted = sorted(all_subs)

        ct_subs = crtsh.get("subdomains") or {}

        self.results = {
            "domain": domain,
            "current_records": current,
            "securitytrails_history": st_history,
            "ct_subdomains": [
                {"subdomain": s,
                 "first_seen": ct_subs[s].get("first_seen"),
                 "last_seen": ct_subs[s].get("last_seen")}
                for s in sorted(ct_subs.keys())
            ],
            "ct_subdomain_count": len(ct_subs),
            "wayback": wayback,
            "otx_passive_dns": otx,
            "viewdns": viewdns,
            "hackertarget": hackertarget,
            "all_subdomains": subs_sorted,
            "all_subdomain_count": len(subs_sorted),
            "historical_resolutions": unified,
            "historical_resolution_count": len(unified),
            "free_sources_hit": total - len(failures),
            "free_sources_failed": failures,
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Current record types: {len(current)}")
        print(f"  Total subdomains (all free sources): {len(subs_sorted)}")
        print(f"  Historical IP resolutions: {len(unified)}")
        print(f"  Free sources: {total - len(failures)}/{total} worked"
              + (f", failed: {', '.join(failures)}" if failures else ""))
        if st_history:
            print(f"  SecurityTrails history: "
                  f"{sum(len(v) for v in st_history.values())} changes")
        else:
            print("  Paid API (SecurityTrails): not configured")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return True
