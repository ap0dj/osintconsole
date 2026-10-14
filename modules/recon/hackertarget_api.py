"""HackerTarget.com free API aggregator.

Fuses ten of HackerTarget's plain-text endpoints (subdomains, DNS, whois, zone
transfer, reverse DNS, GeoIP, ASN, HTTP headers, page links, reverse IP) into a
single passive-recon suite. Free tier allows ~50 queries/day per IP.
"""
import csv
import io
import re
import socket
import time
from urllib.parse import urlparse

from core.base_module import BaseModule
from core.utils import (
    Colors,
    is_valid_domain,
    is_valid_ip,
    is_valid_url,
    print_status,
)
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


RATE_LIMIT_MARKERS = (
    "API count exceeded",
    "error check your search parameter",
    "API usage exceeded",
)

ALL_MODES = [
    "subdomains",
    "dns",
    "whois",
    "zone_transfer",
    "reverse",
    "geoip",
    "asn",
    "headers",
    "pagelinks",
    "reverse_ip",
]


class HackertargetApi(FetchErrorsMixin, BaseModule):
    name = "recon/hackertarget_api"
    description = (
        "HackerTarget.com free API suite - subdomains, DNS, whois, zone transfer, "
        "reverse DNS, GeoIP, ASN, HTTP headers, page links, reverse IP"
    )
    category = "recon"
    target_type = "domain/ip/url"

    BASE = "https://api.hackertarget.com"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain, IP, or URL")
        self.add_option(
            "MODES",
            "auto",
            False,
            "Comma-separated: " + ",".join(ALL_MODES) + " | all | auto",
        )
        self.add_option("TIMEOUT", "15", False, "Per-request timeout in seconds")

    # ---------- helpers ----------

    def _detect_type(self, target):
        if is_valid_ip(target):
            return "ip"
        if is_valid_url(target) or target.startswith(("http://", "https://")):
            return "url"
        if is_valid_domain(target):
            return "domain"
        return None

    def _auto_modes(self, target_type):
        if target_type == "ip":
            return ["reverse", "geoip", "asn", "reverse_ip"]
        if target_type == "url":
            return ["headers", "pagelinks"]
        # domain
        return ["subdomains", "dns", "whois", "zone_transfer", "geoip", "asn"]

    def _parse_modes(self, raw, target_type):
        raw = (raw or "").strip().lower()
        if not raw or raw == "auto":
            return self._auto_modes(target_type)
        if raw == "all":
            return list(ALL_MODES)
        requested = [m.strip() for m in raw.split(",") if m.strip()]
        valid, unknown = [], []
        for m in requested:
            # tolerate common aliases
            m = {"rdns": "reverse", "revdns": "reverse",
                 "revip": "reverse_ip", "links": "pagelinks",
                 "hdrs": "headers", "ztransfer": "zone_transfer",
                 "zone": "zone_transfer", "sub": "subdomains",
                 "subs": "subdomains"}.get(m, m)
            if m in ALL_MODES:
                valid.append(m)
            else:
                unknown.append(m)
        for m in unknown:
            print_status(f"Unknown mode '{m}' - skipping", "warning")
        # preserve ordering but dedupe
        seen = set()
        ordered = []
        for m in valid:
            if m not in seen:
                seen.add(m)
                ordered.append(m)
        return ordered

    def _note_fetch_error(self, msg):
        """Record a fetch failure both in the shared mixin list (for the
        fetch_failed contract) and the module's own warnings list."""
        self._note_error(msg)
        self.results["warnings"].append(msg)

    def _fetch(self, path, query, timeout):
        """GET a HackerTarget endpoint, bump the query counter, surface rate-limit
        hits as warnings. Returns the raw stripped text or None on error.

        Every failure (exception / HTTP>=400 / quota marker / error body) is
        routed through _note_error so run() can tell 'all endpoints failed' apart
        from 'the target genuinely had no data'."""
        self.results["stats"]["queries_made"] += 1
        try:
            resp = http.get(
                f"{self.BASE}/{path}/",
                params={"q": query},
                timeout=timeout,
            )
        except Exception as e:
            self._note_fetch_error(f"{path}: HTTP error {e}")
            return None

        text = (resp.text or "").strip()
        low = text.lower()
        for marker in RATE_LIMIT_MARKERS:
            if marker.lower() in low:
                self._note_fetch_error(
                    f"{path}: rate limited or rejected ({text[:120]})")
                return None
        if resp.status_code >= 400:
            self._note_fetch_error(f"{path}: HTTP {resp.status_code} - {text[:120]}")
            return None
        if not text or text.lower().startswith("error"):
            self._note_fetch_error(
                f"{path}: empty/error response - {text[:120] or '(empty)'}")
            return None
        self.results["stats"]["queries_ok"] += 1
        return text

    def _resolve(self, domain, timeout):
        """Best-effort resolve a domain to an IPv4 using HackerTarget's dnslookup
        first (hits our rate-limit budget consistently), then local DNS as a
        fallback. Returns an IP string or None."""
        try:
            return socket.gethostbyname(domain)
        except Exception:
            pass
        text = self._fetch("dnslookup", domain, timeout)
        if text:
            m = re.search(r"\bA\s*:\s*((?:\d{1,3}\.){3}\d{1,3})", text)
            if m:
                return m.group(1)
        return None

    # ---------- endpoint handlers ----------

    def _run_subdomains(self, target, timeout, idx, total):
        print_status(f"[{idx}/{total}] subdomains (hostsearch)...", "info")
        text = self._fetch("hostsearch", target, timeout)
        if not text:
            return
        hosts, mapping, seen = [], {}, set()
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if len(row) < 1:
                continue
            host = (row[0] or "").strip().lower()
            ip = (row[1].strip() if len(row) > 1 else "") or ""
            if not host or host in seen:
                continue
            if not is_valid_domain(host):
                continue
            seen.add(host)
            hosts.append(host)
            if ip:
                mapping[host] = ip
        hosts.sort()
        self.results["subdomains"] = hosts
        self.results["subdomain_ips"] = mapping
        for h in hosts[:25]:
            ip = mapping.get(h, "")
            print_status(f"  {h}{(' -> ' + ip) if ip else ''}", "success")
        if len(hosts) > 25:
            print_status(f"  ... +{len(hosts) - 25} more", "info")
        print_status(f"Found {len(hosts)} subdomain(s)", "info")

    def _run_dns(self, target, timeout, idx, total):
        print_status(f"[{idx}/{total}] DNS lookup...", "info")
        text = self._fetch("dnslookup", target, timeout)
        if not text:
            return
        records = {"A": [], "AAAA": [], "MX": [], "NS": [],
                   "TXT": [], "SOA": [], "CNAME": []}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(";"):
                continue
            # Expected format: "domain. TTL IN TYPE value" OR "TYPE : value"
            m = re.match(r"^\S+\s+\d+\s+IN\s+(\w+)\s+(.+)$", line)
            if m:
                rtype, value = m.group(1).upper(), m.group(2).strip()
            else:
                m = re.match(r"^([A-Za-z]+)\s*:\s*(.+)$", line)
                if not m:
                    continue
                rtype, value = m.group(1).upper(), m.group(2).strip()
            records.setdefault(rtype, []).append(value)
        # drop empty buckets, dedupe each
        records = {k: sorted(set(v)) for k, v in records.items() if v}
        self.results["dns_records"] = records
        for rtype, vals in records.items():
            for v in vals[:6]:
                print_status(f"  {rtype:5} {v}", "success")
            if len(vals) > 6:
                print_status(f"  {rtype:5} +{len(vals) - 6} more", "info")
        total_rec = sum(len(v) for v in records.values())
        print_status(f"Parsed {total_rec} DNS record(s)", "info")

    def _run_whois(self, target, timeout, idx, total):
        print_status(f"[{idx}/{total}] whois...", "info")
        text = self._fetch("whois", target, timeout)
        if not text:
            return
        self.results["whois_raw"] = text
        # Extract a few high-signal fields for the summary
        fields = {}
        for key in ("Registrar", "Creation Date", "Registry Expiry Date",
                    "Updated Date", "Registrant Country", "Name Server"):
            m = re.search(rf"^\s*{re.escape(key)}:\s*(.+)$",
                          text, re.MULTILINE | re.IGNORECASE)
            if m:
                fields[key] = m.group(1).strip()
        if fields:
            self.results["whois_fields"] = fields
            for k, v in fields.items():
                print_status(f"  {k}: {v}", "success")
        else:
            # show a short teaser of raw whois
            preview = "\n".join(text.splitlines()[:6])
            print(f"{Colors.DIM}{preview}{Colors.RESET}")
        print_status(f"whois body: {len(text)} bytes", "info")

    def _run_zone_transfer(self, target, timeout, idx, total):
        print_status(f"[{idx}/{total}] zone transfer attempt...", "info")
        text = self._fetch("zonetransfer", target, timeout)
        if not text:
            self.results["zone_transfer"] = None
            return
        allowed = ("failed" not in text.lower()
                   and "not allowed" not in text.lower()
                   and "not successful" not in text.lower())
        if allowed and len(text.splitlines()) > 2:
            self.results["zone_transfer"] = text
            print_status(f"Zone transfer SUCCEEDED - {len(text.splitlines())} line(s)", "success")
        else:
            self.results["zone_transfer"] = None
            print_status("Zone transfer not allowed (expected)", "info")

    def _run_reverse(self, ip, timeout, idx, total):
        print_status(f"[{idx}/{total}] reverse DNS of {ip}...", "info")
        text = self._fetch("reversedns", ip, timeout)
        if not text:
            return
        # Response is typically "ip ptr" on one line
        parts = text.split()
        ptr = parts[-1].rstrip(".") if parts else text
        self.results["reverse_dns"] = ptr
        print_status(f"  PTR: {ptr}", "success")

    def _run_geoip(self, ip, timeout, idx, total):
        print_status(f"[{idx}/{total}] GeoIP for {ip}...", "info")
        text = self._fetch("geoip", ip, timeout)
        if not text:
            return
        geo = {}
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                geo[k.strip().lower()] = v.strip()
        normalized = {
            "ip": geo.get("ip address") or geo.get("ip"),
            "country": geo.get("country"),
            "state": geo.get("state") or geo.get("region"),
            "city": geo.get("city"),
            "lat": geo.get("latitude"),
            "lng": geo.get("longitude"),
        }
        self.results["geoip"] = {k: v for k, v in normalized.items() if v}
        for k, v in self.results["geoip"].items():
            print_status(f"  {k}: {v}", "success")

    def _run_asn(self, ip, timeout, idx, total):
        print_status(f"[{idx}/{total}] ASN lookup for {ip}...", "info")
        text = self._fetch("aslookup", ip, timeout)
        if not text:
            return
        # Response format: "ip","ASN","prefix","country","name"
        try:
            row = next(csv.reader(io.StringIO(text)))
        except StopIteration:
            row = []
        asn = {}
        if len(row) >= 5:
            asn = {
                "ip": row[0].strip(),
                "number": row[1].strip(),
                "prefix": row[2].strip(),
                "country": row[3].strip(),
                "name": row[4].strip(),
            }
        else:
            # Fallback: hunt for ASNNNN and the trailing description
            m = re.search(r"AS\s*(\d+)\s*[-,]?\s*(.*)", text)
            if m:
                asn = {"number": f"AS{m.group(1)}", "name": m.group(2).strip()}
        if asn:
            self.results["asn"] = asn
            for k, v in asn.items():
                if v:
                    print_status(f"  {k}: {v}", "success")

    def _run_headers(self, url, timeout, idx, total):
        print_status(f"[{idx}/{total}] HTTP headers of {url}...", "info")
        text = self._fetch("httpheaders", url, timeout)
        if not text:
            return
        headers = {}
        status_line = None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.upper().startswith(("HTTP/1.", "HTTP/2", "HTTP/3")) and status_line is None:
                status_line = line
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        self.results["http_headers"] = headers
        if status_line:
            self.results["http_status_line"] = status_line
            print_status(f"  {status_line}", "success")
        for k in ("Server", "X-Powered-By", "Content-Type",
                  "Strict-Transport-Security", "Content-Security-Policy",
                  "X-Frame-Options", "Set-Cookie"):
            if k in headers:
                v = headers[k]
                print_status(f"  {k}: {v[:120]}", "success")
        print_status(f"Captured {len(headers)} header(s)", "info")

    def _run_pagelinks(self, url, timeout, idx, total):
        print_status(f"[{idx}/{total}] page links of {url}...", "info")
        text = self._fetch("pagelinks", url, timeout)
        if not text:
            return
        links, seen = [], set()
        for line in text.splitlines():
            link = line.strip()
            if link and link not in seen and link.startswith(("http://", "https://")):
                seen.add(link)
                links.append(link)
        self.results["page_links"] = links
        for link in links[:15]:
            print_status(f"  {link}", "success")
        if len(links) > 15:
            print_status(f"  ... +{len(links) - 15} more", "info")
        print_status(f"Found {len(links)} link(s)", "info")

    def _run_reverse_ip(self, ip, timeout, idx, total):
        print_status(f"[{idx}/{total}] reverse IP (hosts on {ip})...", "info")
        text = self._fetch("reverseiplookup", ip, timeout)
        if not text:
            return
        hosts, seen = [], set()
        for line in text.splitlines():
            host = line.strip().lower()
            if host and host not in seen and is_valid_domain(host):
                seen.add(host)
                hosts.append(host)
        hosts.sort()
        self.results["reverse_ip_hosts"] = hosts
        for h in hosts[:20]:
            print_status(f"  {h}", "success")
        if len(hosts) > 20:
            print_status(f"  ... +{len(hosts) - 20} more", "info")
        print_status(f"Found {len(hosts)} host(s) on {ip}", "info")

    # ---------- orchestration ----------

    def run(self):
        if not self.validate():
            return False

        target = (self.get_option("TARGET") or "").strip()
        try:
            timeout = int(self.get_option("TIMEOUT") or 15)
        except (TypeError, ValueError):
            timeout = 15

        target_type = self._detect_type(target)
        if not target_type:
            print_status(f"TARGET must be a domain, IP, or URL: '{target}'", "error")
            return False

        modes = self._parse_modes(self.get_option("MODES"), target_type)
        if not modes:
            print_status("No valid MODES selected", "error")
            return False

        # Initialize results container
        start = time.time()
        self._errors = []
        self.results = {
            "target": target,
            "target_type": target_type,
            "modes_run": [],
            "subdomains": [],
            "subdomain_ips": {},
            "dns_records": {},
            "reverse_dns": None,
            "whois_raw": None,
            "zone_transfer": None,
            "geoip": {},
            "asn": {},
            "http_headers": {},
            "page_links": [],
            "reverse_ip_hosts": [],
            "warnings": [],
            "stats": {"queries_made": 0, "queries_ok": 0, "duration_sec": 0},
        }

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*62}")
        print(f"  HackerTarget Suite: {target}  [{target_type}]")
        print(f"  Modes: {', '.join(modes)}")
        print(f"{'='*62}{Colors.RESET}\n")

        # If the target is a domain and we need IP-only endpoints, resolve once
        host_for_url = None
        resolved_ip = None
        if target_type == "url":
            host_for_url = urlparse(target).hostname

        needs_ip = {"reverse", "geoip", "asn", "reverse_ip"}
        if needs_ip & set(modes):
            if target_type == "ip":
                resolved_ip = target
            elif target_type == "domain":
                resolved_ip = self._resolve(target, timeout)
                if resolved_ip:
                    print_status(f"Resolved {target} -> {resolved_ip}", "info")
                else:
                    print_status(
                        f"Cannot resolve {target}; IP-based endpoints will be skipped",
                        "warning",
                    )
            elif target_type == "url" and host_for_url:
                try:
                    resolved_ip = socket.gethostbyname(host_for_url)
                    print_status(f"Resolved {host_for_url} -> {resolved_ip}", "info")
                except Exception:
                    print_status(f"Cannot resolve {host_for_url}", "warning")

        total_steps = len(modes)
        for idx, mode in enumerate(modes, start=1):
            try:
                if mode == "subdomains":
                    if target_type != "domain":
                        print_status(f"[{idx}/{total_steps}] subdomains needs a domain - skipping", "warning")
                        continue
                    self._run_subdomains(target, timeout, idx, total_steps)
                elif mode == "dns":
                    if target_type != "domain":
                        print_status(f"[{idx}/{total_steps}] DNS lookup needs a domain - skipping", "warning")
                        continue
                    self._run_dns(target, timeout, idx, total_steps)
                elif mode == "whois":
                    whois_q = target if target_type != "url" else (host_for_url or target)
                    self._run_whois(whois_q, timeout, idx, total_steps)
                elif mode == "zone_transfer":
                    if target_type != "domain":
                        print_status(f"[{idx}/{total_steps}] zone transfer needs a domain - skipping", "warning")
                        continue
                    self._run_zone_transfer(target, timeout, idx, total_steps)
                elif mode == "reverse":
                    if not resolved_ip:
                        print_status(f"[{idx}/{total_steps}] reverse DNS needs an IP - skipping", "warning")
                        continue
                    self._run_reverse(resolved_ip, timeout, idx, total_steps)
                elif mode == "geoip":
                    if not resolved_ip:
                        print_status(f"[{idx}/{total_steps}] GeoIP needs an IP - skipping", "warning")
                        continue
                    self._run_geoip(resolved_ip, timeout, idx, total_steps)
                elif mode == "asn":
                    if not resolved_ip:
                        print_status(f"[{idx}/{total_steps}] ASN lookup needs an IP - skipping", "warning")
                        continue
                    self._run_asn(resolved_ip, timeout, idx, total_steps)
                elif mode == "headers":
                    url_q = target if target_type == "url" else f"http://{target}"
                    self._run_headers(url_q, timeout, idx, total_steps)
                elif mode == "pagelinks":
                    url_q = target if target_type == "url" else f"http://{target}"
                    self._run_pagelinks(url_q, timeout, idx, total_steps)
                elif mode == "reverse_ip":
                    if not resolved_ip:
                        print_status(f"[{idx}/{total_steps}] reverse IP needs an IP - skipping", "warning")
                        continue
                    self._run_reverse_ip(resolved_ip, timeout, idx, total_steps)
                self.results["modes_run"].append(mode)
            except Exception as e:
                msg = f"{mode}: unhandled error - {e}"
                print_status(msg, "error")
                self.results["warnings"].append(msg)

        self.results["stats"]["duration_sec"] = round(time.time() - start, 2)
        if resolved_ip:
            self.results["resolved_ip"] = resolved_ip
        self.results["fetch_errors"] = list(getattr(self, "_errors", []))

        self._print_summary(target, target_type)

        # Every endpoint that ran failed (quota / HTTP error) and none returned
        # data -> this is a fetch failure, NOT "the target has no data". Only
        # when at least one endpoint succeeded (or nothing was attempted) do we
        # report success.
        if self.results["stats"]["queries_ok"] == 0 and self.results["fetch_errors"]:
            self.results["error"] = "fetch_failed"
            print_status(
                "HackerTarget suite FAILED - every endpoint errored or hit the "
                "free-tier quota; this is NOT evidence the target has no data",
                "error")
            return False
        return True

    def _print_summary(self, target, target_type):
        r = self.results
        bits = []
        if r["subdomains"]:
            bits.append(f"{len(r['subdomains'])} subdomains")
        if r["dns_records"]:
            mx = len(r["dns_records"].get("MX", []))
            a = len(r["dns_records"].get("A", []))
            ns = len(r["dns_records"].get("NS", []))
            bits.append(f"DNS: {a}A/{mx}MX/{ns}NS")
        if r["reverse_dns"]:
            bits.append(f"PTR: {r['reverse_dns']}")
        if r["whois_raw"]:
            bits.append("whois ok")
        if r["zone_transfer"]:
            bits.append("ZONE XFER!")
        if r["geoip"]:
            geo_s = "/".join(x for x in (r["geoip"].get("country"),
                                         r["geoip"].get("city")) if x)
            if geo_s:
                bits.append(f"GeoIP: {geo_s}")
        if r["asn"]:
            bits.append(f"{r['asn'].get('number', 'ASN')} {r['asn'].get('name', '')}".strip())
        if r["http_headers"]:
            bits.append(f"{len(r['http_headers'])} headers")
        if r["page_links"]:
            bits.append(f"{len(r['page_links'])} links")
        if r["reverse_ip_hosts"]:
            bits.append(f"{len(r['reverse_ip_hosts'])} co-hosted")

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*62}{Colors.RESET}")
        print(f"{Colors.BOLD}  Summary ({target} [{target_type}]):{Colors.RESET}")
        if bits:
            for b in bits:
                print(f"   {Colors.GREEN}-{Colors.RESET} {b}")
        else:
            print(f"   {Colors.YELLOW}(no data gathered){Colors.RESET}")
        s = r["stats"]
        print(f"   {Colors.DIM}queries: {s['queries_made']} | "
              f"duration: {s['duration_sec']}s | "
              f"warnings: {len(r['warnings'])}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*62}{Colors.RESET}\n")
