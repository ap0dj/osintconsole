"""Comprehensive web recon on a domain.

Orchestrates 13 sub-modules in order (DNS -> subdomain discovery -> CT logs ->
HackerTarget -> resolve -> live check -> tech fingerprint -> ASN -> WHOIS ->
headers/security.txt -> wayback -> emails -> robots/sitemap) and writes
organised plain-text artefacts plus a master markdown + JSON report into
`results/<target>/recon_full_<timestamp>/`.

Every phase is wrapped in try/except: one broken sub-module never aborts the
whole run. Lazy imports keep startup cheap when the module is just listed.
"""
import json
import os
import re
import socket
import time
import datetime
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_module import BaseModule
from core.utils import Colors, print_status, is_valid_domain, timestamp
from core import http


PHASE_NAMES = [
    "dns", "subdomain", "ssl", "hackertarget", "resolve", "live", "tech",
    "asn", "whois", "headers", "wayback", "emails", "robots",
]
TOTAL_PHASES = len(PHASE_NAMES)


class ReconFull(BaseModule):
    name = "web/recon_full"
    description = (
        "Comprehensive web recon: subdomains, live hosts, tech, ASN, WHOIS, "
        "emails, wayback, robots - organised per-topic text files + master report"
    )
    category = "web"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain")
        self.add_option(
            "OUTPUT_DIR", "", False,
            "Output directory (default: results/<target>/recon_full_<timestamp>)",
        )
        self.add_option(
            "LIVE_CHECK_WORKERS", "20", False,
            "Thread pool size for the HTTP live-check phase",
        )
        self.add_option(
            "TECH_PER_HOST", "true", False,
            "Run web/wappalyzer_full for each live host (slower when true)",
        )
        self.add_option(
            "STRICT_LIVE", "true", False,
            "true: only 2xx/3xx count as live. false: also accept 4xx/5xx",
        )
        self.add_option(
            "SKIP", "", False,
            "Comma-separated phase names to skip: " + ",".join(PHASE_NAMES),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _sanitize(self, value):
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in (value or ""))
        return safe.lstrip(".") or "_"

    def _ensure_dirs(self, target):
        base = (self.get_option("OUTPUT_DIR") or "").strip()
        if not base:
            root = os.path.join("results", self._sanitize(target))
            base = os.path.join(root, f"recon_full_{timestamp()}")
        os.makedirs(base, exist_ok=True)
        os.makedirs(os.path.join(base, "screenshots"), exist_ok=True)
        return os.path.abspath(base)

    def _header(self, idx, phase, target):
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{'-' * 58}")
        print(f"  [{idx}/{TOTAL_PHASES}] phase={phase} target={target}")
        print(f"{'-' * 58}{Colors.RESET}")

    def _run_submodule(self, dotted, cls, target, extra_opts=None):
        """Instantiate a sub-module, run it, return its results dict or None."""
        try:
            mod = cls()
            mod.set_option("TARGET", target)
            if extra_opts:
                for k, v in extra_opts.items():
                    mod.set_option(k, v)
            if mod.run():
                return mod.get_results() or {}
            return {}
        except Exception as exc:
            print_status(f"{dotted}: {type(exc).__name__}: {exc}", "error")
            return None

    # ------------------------------------------------------------------
    # Phases
    # ------------------------------------------------------------------
    def _phase_dns(self, target, data):
        from modules.recon.dns_enum import DnsEnum
        res = self._run_submodule("recon/dns_enum", DnsEnum, target) or {}
        records = res.get("records") or {}
        data["dns_records"] = {target: records}
        # Harvest A / AAAA IPs into the global IP pool
        for rtype in ("A", "AAAA"):
            for v in records.get(rtype, []) or []:
                m = re.search(r"((?:\d{1,3}\.){3}\d{1,3})", str(v))
                if m:
                    data["ips"].add(m.group(1))
        data["raw"]["dns_enum"] = res

    def _phase_subdomain(self, target, data):
        from modules.recon.subdomain import SubdomainEnum
        res = self._run_submodule(
            "recon/subdomain", SubdomainEnum, target,
            extra_opts={"USE_CRTSH": "true", "USE_BRUTEFORCE": "true"},
        ) or {}
        for sub in res.get("subdomains") or []:
            data["subdomains"].add(sub.lower().strip())
        for sub, ip in (res.get("resolved") or {}).items():
            if ip and ip != "unresolved" and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
                data["sub_to_ip"][sub.lower()] = ip
                data["ips"].add(ip)
        data["raw"]["subdomain"] = res

    def _phase_ssl(self, target, data):
        from modules.recon.ssl_cert_search import SslCertSearch
        res = self._run_submodule("recon/ssl_cert_search", SslCertSearch, target) or {}
        for sub in res.get("subdomains") or []:
            data["subdomains"].add(sub.lower().strip())
            data["certs"].add(sub.lower().strip())
        for issuer in res.get("issuers") or []:
            data["cert_issuers"].add(str(issuer))
        data["raw"]["ssl_cert_search"] = res

    def _phase_hackertarget(self, target, data):
        from modules.recon.hackertarget_api import HackertargetApi
        res = self._run_submodule(
            "recon/hackertarget_api", HackertargetApi, target,
            extra_opts={"MODES": "subdomains,dns,whois,geoip,asn"},
        ) or {}
        for sub in res.get("subdomains") or []:
            data["subdomains"].add(sub.lower().strip())
        for sub, ip in (res.get("subdomain_ips") or {}).items():
            data["sub_to_ip"][sub.lower()] = ip
            data["ips"].add(ip)
        asn = res.get("asn") or {}
        if asn.get("number"):
            data["asns"][str(asn["number"])] = asn.get("name") or ""
        data["raw"]["hackertarget"] = res

    def _phase_resolve(self, target, data):
        # Make sure the apex target itself is in the subdomain pool
        data["subdomains"].add(target.lower())

        unresolved = [s for s in data["subdomains"] if s not in data["sub_to_ip"]]
        if not unresolved:
            print_status("All subdomains already resolved", "info")
            return

        print_status(f"Resolving {len(unresolved)} subdomain(s) to IPs", "info")
        workers = max(1, min(50, self._as_int("LIVE_CHECK_WORKERS", 20)))

        def _resolve(host):
            try:
                return host, socket.gethostbyname(host)
            except Exception:
                return host, None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for fut in as_completed(pool.submit(_resolve, h) for h in unresolved):
                host, ip = fut.result()
                if ip:
                    data["sub_to_ip"][host] = ip
                    data["ips"].add(ip)
        print_status(
            f"Resolved {sum(1 for h in unresolved if data['sub_to_ip'].get(h))}"
            f"/{len(unresolved)}", "success",
        )

    def _phase_live(self, target, data):
        strict = (self.get_option("STRICT_LIVE") or "true").lower() != "false"
        workers = max(1, min(100, self._as_int("LIVE_CHECK_WORKERS", 20)))
        candidates = sorted(h for h in data["subdomains"] if h)
        if not candidates:
            print_status("No subdomains to live-check", "warning")
            return

        print_status(
            f"Live-check: {len(candidates)} host(s) x 2 ports, {workers} workers",
            "info",
        )

        def _probe(host):
            # Try HTTPS first (443), fall back to HTTP (80)
            for scheme, port in (("https", 443), ("http", 80)):
                url = f"{scheme}://{host}"
                try:
                    resp = http.get(url, timeout=5, allow_redirects=True, verify=False)
                except Exception:
                    continue
                status = getattr(resp, "status_code", 0)
                alive = (200 <= status < 400) if strict else (200 <= status < 600)
                if alive:
                    title = ""
                    try:
                        body = resp.text or ""
                        m = re.search(r"<title[^>]*>(.*?)</title>", body,
                                      re.IGNORECASE | re.DOTALL)
                        if m:
                            title = re.sub(r"\s+", " ", m.group(1)).strip()[:140]
                    except Exception:
                        pass
                    return host, {
                        "status": status, "scheme": scheme, "port": port,
                        "url": resp.url if hasattr(resp, "url") else url,
                        "title": title,
                    }
            return host, None

        found = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_probe, h): h for h in candidates}
            for fut in as_completed(futures):
                try:
                    host, info = fut.result()
                except Exception:
                    continue
                if info:
                    data["live"][host] = info
                    data["urls"].add(info["url"])
                    found += 1
        print_status(f"Live hosts: {found}/{len(candidates)}", "success")

    def _phase_tech(self, target, data):
        if (self.get_option("TECH_PER_HOST") or "true").lower() != "true":
            print_status("TECH_PER_HOST=false, skipping per-host fingerprint", "info")
            return
        if not data["live"]:
            print_status("No live hosts to fingerprint", "warning")
            return
        from modules.web.wappalyzer_full import WappalyzerFull
        hosts = list(data["live"].keys())[:20]
        print_status(f"Fingerprinting {len(hosts)} live host(s) (cap 20)", "info")

        def _one(host):
            try:
                mod = WappalyzerFull()
                mod.set_option("TARGET", host)
                if mod.run():
                    return host, mod.get_results() or {}
            except Exception as exc:
                return host, {"__error__": f"{type(exc).__name__}: {exc}"}
            return host, {}

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(_one, h): h for h in hosts}
            for fut in as_completed(futures):
                try:
                    host, res = fut.result()
                except Exception:
                    continue
                detections = res.get("detected") or []
                data["tech"][host] = [
                    {
                        "name": d.get("name"),
                        "version": d.get("version") or "",
                        "category": d.get("category") or "",
                        "confidence": d.get("confidence") or 0,
                    }
                    for d in detections
                ]

    def _phase_asn(self, target, data):
        from modules.recon.asn_lookup import AsnLookup
        ips = sorted(data["ips"])[:10]
        if not ips:
            print_status("No IPs to look up", "warning")
            return
        for ip in ips:
            res = self._run_submodule("recon/asn_lookup", AsnLookup, ip) or {}
            for a in res.get("associated_asns", []) or []:
                num = a.get("asn")
                if num:
                    data["asns"][f"AS{num}"] = a.get("name") or a.get("description") or ""
            data["raw"].setdefault("asn_lookup", {})[ip] = res

    def _phase_whois(self, target, data):
        from modules.recon.whois_lookup import WhoisLookup
        res = self._run_submodule("recon/whois_lookup", WhoisLookup, target) or {}
        data["whois"] = res
        for e in res.get("emails") or []:
            if isinstance(e, str) and "@" in e:
                data["emails"].add(e.lower())
        data["raw"]["whois"] = res

    def _phase_headers(self, target, data):
        from modules.web.headers import HeadersAnalysis
        from modules.web.security_txt import SecurityTxt
        hosts = list(data["live"].keys())[:15] or [target]
        for host in hosts:
            hres = self._run_submodule("web/headers", HeadersAnalysis, host) or {}
            data["headers"][host] = hres
            sres = self._run_submodule("web/security_txt", SecurityTxt, host) or {}
            data["security_txt"][host] = sres
        data["raw"]["headers"] = data["headers"]
        data["raw"]["security_txt"] = data["security_txt"]

    def _phase_wayback(self, target, data):
        from modules.web.wayback import Wayback
        res = self._run_submodule("web/wayback", Wayback, target) or {}
        for u in res.get("unique_urls") or []:
            if isinstance(u, str):
                data["urls"].add(u)
        data["raw"]["wayback"] = res

    def _phase_emails(self, target, data):
        from modules.harvest.domain_emails import DomainEmails
        res = self._run_submodule("harvest/domain_emails", DomainEmails, target) or {}
        for e in res.get("emails_found") or []:
            if isinstance(e, str) and "@" in e:
                data["emails"].add(e.lower())
        data["raw"]["domain_emails"] = res

    def _phase_robots(self, target, data):
        from modules.web.robots_sitemap import RobotsSitemap
        hosts = list(data["live"].keys())[:10] or [target]
        for host in hosts:
            res = self._run_submodule("web/robots_sitemap", RobotsSitemap, host) or {}
            data["robots"][host] = res
            for item in res.get("sitemap_urls") or []:
                if isinstance(item, dict) and item.get("url"):
                    data["urls"].add(item["url"])
                elif isinstance(item, str):
                    data["urls"].add(item)
        data["raw"]["robots_sitemap"] = data["robots"]

    # ------------------------------------------------------------------
    # Dispatch table
    # ------------------------------------------------------------------
    def _phase_methods(self):
        return {
            "dns": self._phase_dns,
            "subdomain": self._phase_subdomain,
            "ssl": self._phase_ssl,
            "hackertarget": self._phase_hackertarget,
            "resolve": self._phase_resolve,
            "live": self._phase_live,
            "tech": self._phase_tech,
            "asn": self._phase_asn,
            "whois": self._phase_whois,
            "headers": self._phase_headers,
            "wayback": self._phase_wayback,
            "emails": self._phase_emails,
            "robots": self._phase_robots,
        }

    def _as_int(self, option, default):
        try:
            return int(self.get_option(option) or default)
        except (TypeError, ValueError):
            return default

    # ------------------------------------------------------------------
    # Output writers
    # ------------------------------------------------------------------
    def _w(self, out_dir, name, text):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def _write_text_files(self, out_dir, target, data):
        """Dump each slice of the collected data into its own text file."""
        files = []

        subs = sorted(data["subdomains"], key=str.lower)
        files.append(self._w(out_dir, "subdomains.txt",
                             "\n".join(subs) + ("\n" if subs else "")))

        live_subs = sorted(data["live"].keys(), key=str.lower)
        files.append(self._w(out_dir, "live_subdomains.txt",
                             "\n".join(live_subs) + ("\n" if live_subs else "")))

        ips = sorted(data["ips"], key=lambda s: tuple(int(x) for x in s.split(".")))
        files.append(self._w(out_dir, "ips.txt",
                             "\n".join(ips) + ("\n" if ips else "")))

        asn_lines = [f"{num}\t{name}".rstrip()
                     for num, name in sorted(data["asns"].items())]
        files.append(self._w(out_dir, "asn.txt",
                             "\n".join(asn_lines) + ("\n" if asn_lines else "")))

        live_lines = []
        for host in live_subs:
            info = data["live"][host]
            live_lines.append(
                f"{host}\t{info.get('status', '')}\t{info.get('title', '')}"
            )
        files.append(self._w(out_dir, "live_hosts.txt",
                             "\n".join(live_lines) + ("\n" if live_lines else "")))

        ports_lines = []
        for host in live_subs:
            info = data["live"][host]
            ip = data["sub_to_ip"].get(host, "")
            if ip:
                ports_lines.append(f"{ip}:{info.get('port', '')}\t{info.get('scheme', '')}")
        files.append(self._w(out_dir, "ports_open.txt",
                             "\n".join(sorted(set(ports_lines))) +
                             ("\n" if ports_lines else "")))

        tech_blocks = []
        for host in sorted(data["tech"].keys(), key=str.lower):
            tech_blocks.append(f"=== {host} ===")
            for t in data["tech"][host]:
                line = t.get("name") or ""
                if t.get("version"):
                    line += f" {t['version']}"
                if t.get("category"):
                    line += f"  [{t['category']}]"
                tech_blocks.append(line)
            tech_blocks.append("")
        files.append(self._w(out_dir, "tech_stack.txt", "\n".join(tech_blocks)))

        emails = sorted(data["emails"])
        files.append(self._w(out_dir, "emails.txt",
                             "\n".join(emails) + ("\n" if emails else "")))

        urls = sorted(data["urls"])
        files.append(self._w(out_dir, "urls.txt",
                             "\n".join(urls) + ("\n" if urls else "")))

        certs = sorted(data["certs"])
        files.append(self._w(out_dir, "certs.txt",
                             "\n".join(certs) + ("\n" if certs else "")))

        dns_blocks = []
        for dom, records in data["dns_records"].items():
            dns_blocks.append(f"=== {dom} ===")
            for rtype, values in (records or {}).items():
                for v in values:
                    dns_blocks.append(f"{rtype}: {v}")
            dns_blocks.append("")
        files.append(self._w(out_dir, "dns_records.txt", "\n".join(dns_blocks)))

        return files

    def _write_markdown(self, out_dir, target, data, phase_status, duration):
        lines = []
        lines.append(f"# Recon Full Report - {target}")
        lines.append("")
        lines.append(f"- Generated: {datetime.datetime.now().isoformat(timespec='seconds')}")
        lines.append(f"- Duration:  {duration}s")
        lines.append(f"- Output:    `{out_dir}`")
        lines.append("")

        lines.append("## Phase status")
        lines.append("")
        lines.append("| # | Phase | Status | Note |")
        lines.append("|---|-------|--------|------|")
        for i, ph in enumerate(PHASE_NAMES, 1):
            st = phase_status.get(ph, {"status": "skipped", "note": ""})
            lines.append(f"| {i} | {ph} | {st['status']} | {st.get('note', '')} |")
        lines.append("")

        counts = {
            "subdomains": len(data["subdomains"]),
            "live": len(data["live"]),
            "ips": len(data["ips"]),
            "asns": len(data["asns"]),
            "tech_hosts": len(data["tech"]),
            "emails": len(data["emails"]),
            "urls": len(data["urls"]),
            "certs": len(data["certs"]),
        }
        lines.append("## Counts")
        lines.append("")
        for k, v in counts.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")

        if data["whois"]:
            lines.append("## WHOIS")
            lines.append("")
            for k in ("registrar", "creation_date", "expiration_date",
                      "updated_date", "org", "country"):
                v = data["whois"].get(k)
                if v:
                    lines.append(f"- {k}: {v}")
            lines.append("")

        if data["asns"]:
            lines.append("## ASNs")
            lines.append("")
            for num, name in sorted(data["asns"].items()):
                lines.append(f"- {num}  {name}")
            lines.append("")

        if data["live"]:
            lines.append("## Live hosts")
            lines.append("")
            lines.append("| Host | Status | Title |")
            lines.append("|------|--------|-------|")
            for host in sorted(data["live"].keys(), key=str.lower):
                info = data["live"][host]
                title = (info.get("title") or "").replace("|", "/")
                lines.append(f"| {host} | {info.get('status', '')} | {title} |")
            lines.append("")

        if data["tech"]:
            lines.append("## Tech stack (per live host)")
            lines.append("")
            for host, techs in sorted(data["tech"].items()):
                lines.append(f"### {host}")
                for t in techs:
                    line = f"- {t.get('name', '')}"
                    if t.get("version"):
                        line += f" {t['version']}"
                    if t.get("category"):
                        line += f"  _({t['category']})_"
                    lines.append(line)
                lines.append("")

        if data["emails"]:
            lines.append("## Emails")
            lines.append("")
            for e in sorted(data["emails"]):
                lines.append(f"- {e}")
            lines.append("")

        md_path = os.path.join(out_dir, "full_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return md_path

    def _write_json(self, out_dir, target, data, phase_status, duration):
        payload = {
            "target": target,
            "generated": datetime.datetime.now().isoformat(timespec="seconds"),
            "duration_sec": duration,
            "phase_status": phase_status,
            "counts": {
                "subdomains": len(data["subdomains"]),
                "live": len(data["live"]),
                "ips": len(data["ips"]),
                "asns": len(data["asns"]),
                "tech_hosts": len(data["tech"]),
                "emails": len(data["emails"]),
                "urls": len(data["urls"]),
                "certs": len(data["certs"]),
            },
            "subdomains": sorted(data["subdomains"]),
            "live_hosts": data["live"],
            "sub_to_ip": data["sub_to_ip"],
            "ips": sorted(data["ips"]),
            "asns": data["asns"],
            "cert_subjects": sorted(data["certs"]),
            "cert_issuers": sorted(data["cert_issuers"]),
            "emails": sorted(data["emails"]),
            "urls": sorted(data["urls"]),
            "whois": data["whois"],
            "dns_records": data["dns_records"],
            "headers": data["headers"],
            "security_txt": data["security_txt"],
            "robots": data["robots"],
            "tech": data["tech"],
            "raw": data["raw"],
        }
        path = os.path.join(out_dir, "full_report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
        return path

    def _write_summary(self, out_dir, target, data, phase_status, duration):
        counts = {
            "subdomains": len(data["subdomains"]),
            "live": len(data["live"]),
            "ips": len(data["ips"]),
            "asns": len(data["asns"]),
            "tech_hosts": len(data["tech"]),
            "emails": len(data["emails"]),
            "urls": len(data["urls"]),
            "certs": len(data["certs"]),
        }
        ran = sum(1 for v in phase_status.values() if v["status"] == "ok")
        failed = sum(1 for v in phase_status.values() if v["status"] == "error")
        skipped = sum(1 for v in phase_status.values() if v["status"] == "skipped")
        lines = [
            "=" * 58,
            "  Recon Full - executive summary",
            "=" * 58,
            f"Target:        {target}",
            f"Generated:     {datetime.datetime.now().isoformat(timespec='seconds')}",
            f"Duration:      {duration}s",
            f"Phases:        {ran} ok / {failed} error / {skipped} skipped "
            f"of {TOTAL_PHASES}",
            "-" * 58,
            f"Subdomains:    {counts['subdomains']}",
            f"Live hosts:    {counts['live']}",
            f"Unique IPs:    {counts['ips']}",
            f"ASNs:          {counts['asns']}",
            f"Tech hosts:    {counts['tech_hosts']}",
            f"Emails:        {counts['emails']}",
            f"URLs:          {counts['urls']}",
            f"CT subjects:   {counts['certs']}",
            "=" * 58,
        ]
        path = os.path.join(out_dir, "summary.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return path

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        target = (self.get_option("TARGET") or "").strip().lower()
        if not is_valid_domain(target):
            print_status(f"TARGET must be a valid domain: '{target}'", "error")
            return False

        skip = {s.strip().lower()
                for s in (self.get_option("SKIP") or "").split(",") if s.strip()}

        out_dir = self._ensure_dirs(target)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 58}")
        print("  RECON FULL - comprehensive web recon")
        print(f"  Target:  {target}")
        print(f"  Output:  {out_dir}")
        print(f"  Phases:  {TOTAL_PHASES} ({', '.join(PHASE_NAMES)})")
        if skip:
            print(f"  Skip:    {', '.join(sorted(skip))}")
        print(f"{'=' * 58}{Colors.RESET}")

        # Aggregated state carried across phases.
        data = {
            "subdomains": set(),
            "live": {},
            "sub_to_ip": {},
            "ips": set(),
            "asns": {},
            "certs": set(),
            "cert_issuers": set(),
            "emails": set(),
            "urls": set(),
            "tech": {},
            "whois": {},
            "dns_records": {},
            "headers": {},
            "security_txt": {},
            "robots": {},
            "raw": {},
        }

        phase_status = {}
        methods = self._phase_methods()
        start = time.time()

        for idx, phase in enumerate(PHASE_NAMES, 1):
            if phase in skip:
                print_status(f"[{idx}/{TOTAL_PHASES}] skipping '{phase}' (SKIP)", "warning")
                phase_status[phase] = {"status": "skipped", "note": "user SKIP"}
                continue
            self._header(idx, phase, target)
            try:
                methods[phase](target, data)
                phase_status[phase] = {"status": "ok", "note": ""}
                print_status(f"phase '{phase}' done", "success")
            except Exception as exc:
                phase_status[phase] = {
                    "status": "error",
                    "note": f"{type(exc).__name__}: {exc}",
                }
                print_status(f"phase '{phase}' error: {exc}", "error")
                traceback.print_exc()

        duration = round(time.time() - start, 2)

        # Write all outputs
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'-' * 58}")
        print("  Writing output files")
        print(f"{'-' * 58}{Colors.RESET}")
        files_written = []
        try:
            files_written.extend(self._write_text_files(out_dir, target, data))
            files_written.append(self._write_markdown(out_dir, target, data,
                                                     phase_status, duration))
            files_written.append(self._write_json(out_dir, target, data,
                                                  phase_status, duration))
            files_written.append(self._write_summary(out_dir, target, data,
                                                     phase_status, duration))
            for p in files_written:
                print_status(f"wrote {p}", "info")
        except Exception as exc:
            print_status(f"output writing failed: {exc}", "error")
            traceback.print_exc()

        counts = {
            "subdomains": len(data["subdomains"]),
            "live": len(data["live"]),
            "ips": len(data["ips"]),
            "asns": len(data["asns"]),
            "tech_hosts": len(data["tech"]),
            "emails": len(data["emails"]),
            "urls": len(data["urls"]),
            "certs": len(data["certs"]),
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'=' * 58}")
        print("  RECON FULL COMPLETE")
        print(f"{'=' * 58}{Colors.RESET}")
        print(f"  Target:      {target}")
        print(f"  Duration:    {duration}s")
        print(f"  Subdomains:  {counts['subdomains']}  (live {counts['live']})")
        print(f"  IPs:         {counts['ips']}")
        print(f"  ASNs:        {counts['asns']}")
        print(f"  Tech hosts:  {counts['tech_hosts']}")
        print(f"  Emails:      {counts['emails']}")
        print(f"  Output:      {out_dir}\n")

        self.results = {
            "target": target,
            "output_dir": out_dir,
            "counts": counts,
            "phase_status": phase_status,
            "duration_sec": duration,
            "files_written": files_written,
        }
        return True
