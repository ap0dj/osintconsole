"""Subdomain enumeration — the strongest passive+brute recon in the project.

Collects hostnames from many free, no-API-key sources in parallel, merges them
with an optional DNS brute-force (plus common permutations), and can optionally
resolve each host to IPs and HTTP-probe it for liveness.

Sources (all free, keyless):
  * crt.sh                 — Certificate Transparency JSON feed
  * HackerTarget           — hostsearch CSV
  * AlienVault OTX         — passive DNS indicators
  * RapidDNS               — HTML table scrape
  * URLScan.io             — public scan search
  * AnubisDB (jldc.me)     — community aggregator
  * Wayback Machine        — CDX archive hostnames
  * SubDomainCenter        — api.subdomain.center aggregator
  * Certspotter            — SSLMate CT issuances
"""
import os
import re
import csv
import json
import socket
import io
import concurrent.futures
from html.parser import HTMLParser

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Valid hostname chars: letters, digits, dot, dash, underscore (used by some CDNs).
_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]*[a-z0-9]$")


def _clean_host(raw, domain):
    """Normalize a raw string into a hostname belonging to `domain`.

    Returns the lowercased host, or None if it is invalid, wildcarded, or
    outside the target domain.
    """
    if not raw:
        return None
    host = raw.strip().lower()
    # Strip URL schemes / paths / ports if a source hands them to us.
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    host = host.split("?", 1)[0]
    host = host.split("#", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    if ":" in host:
        host = host.split(":", 1)[0]
    host = host.strip(". ").strip()
    if not host:
        return None
    # Reject wildcards and anything with whitespace/control chars.
    if host.startswith("*.") or host.startswith("*"):
        return None
    if any(c.isspace() for c in host):
        return None
    if not _HOST_RE.match(host):
        return None
    if host == domain or host.endswith("." + domain):
        return host
    return None


def _extract_hosts(blob, domain):
    """Scan arbitrary text/JSON-ish text for hostnames inside `domain`."""
    found = set()
    if not blob:
        return found
    needle = re.escape(domain)
    pattern = re.compile(r"([a-zA-Z0-9_\-\.]+\." + needle + r")", re.I)
    for m in pattern.findall(blob):
        host = _clean_host(m, domain)
        if host:
            found.add(host)
    return found


# ---------------------------------------------------------------------------
# Source functions — each takes (domain) -> set[str] of hostnames
# ---------------------------------------------------------------------------

def _source_crt_sh(domain):
    out = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = http.get(url, timeout=25)
    if resp.status_code != 200 or not resp.text.strip():
        return out
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return _extract_hosts(resp.text, domain)
    for entry in data:
        for key in ("name_value", "common_name"):
            val = entry.get(key, "") or ""
            for line in val.split("\n"):
                host = _clean_host(line, domain)
                if host:
                    out.add(host)
    return out


def _source_hackertarget(domain):
    out = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = http.get(url, timeout=20)
    if resp.status_code != 200:
        return out
    text = resp.text or ""
    if "error" in text.lower() and "api count" in text.lower():
        return out
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        host = _clean_host(row[0], domain)
        if host:
            out.add(host)
    return out


def _source_otx(domain):
    out = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    resp = http.get(url, timeout=25)
    if resp.status_code != 200:
        return out
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return out
    for entry in data.get("passive_dns", []) or []:
        host = _clean_host(entry.get("hostname", ""), domain)
        if host:
            out.add(host)
    return out


class _RapidDNSParser(HTMLParser):
    """Scrape <td> cells from RapidDNS results."""

    def __init__(self):
        super().__init__()
        self.in_td = False
        self.cells = []
        self._buf = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "td":
            self.in_td = True
            self._buf = []

    def handle_endtag(self, tag):
        if tag.lower() == "td":
            self.in_td = False
            text = "".join(self._buf).strip()
            if text:
                self.cells.append(text)

    def handle_data(self, data):
        if self.in_td:
            self._buf.append(data)


def _source_rapiddns(domain):
    out = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
    resp = http.get(url, timeout=25)
    if resp.status_code != 200:
        return out
    try:
        parser = _RapidDNSParser()
        parser.feed(resp.text or "")
    except Exception:
        return _extract_hosts(resp.text, domain)
    for cell in parser.cells:
        host = _clean_host(cell, domain)
        if host:
            out.add(host)
    # Fallback regex sweep in case the table markup changes.
    out |= _extract_hosts(resp.text, domain)
    return out


def _source_urlscan(domain):
    out = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    resp = http.get(url, timeout=25)
    if resp.status_code != 200:
        return out
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return out
    for hit in data.get("results", []) or []:
        page = hit.get("page", {}) or {}
        for key in ("domain", "apexDomain"):
            host = _clean_host(page.get(key, ""), domain)
            if host:
                out.add(host)
        task = hit.get("task", {}) or {}
        host = _clean_host(task.get("domain", ""), domain)
        if host:
            out.add(host)
    return out


def _source_anubis(domain):
    out = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    resp = http.get(url, timeout=20)
    if resp.status_code != 200:
        return out
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return out
    if isinstance(data, list):
        for sub in data:
            host = _clean_host(sub, domain)
            if host:
                out.add(host)
    return out


def _source_wayback(domain):
    out = set()
    url = (
        "http://web.archive.org/cdx/search/cdx?"
        f"url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&limit=1000"
    )
    resp = http.get(url, timeout=30)
    if resp.status_code != 200:
        return out
    for line in (resp.text or "").splitlines():
        host = _clean_host(line, domain)
        if host:
            out.add(host)
    return out


def _source_subdomain_center(domain):
    out = set()
    url = f"https://api.subdomain.center/?domain={domain}"
    resp = http.get(url, timeout=25)
    if resp.status_code != 200:
        return out
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return out
    if isinstance(data, list):
        for sub in data:
            host = _clean_host(sub, domain)
            if host:
                out.add(host)
    return out


def _source_certspotter(domain):
    out = set()
    url = (
        "https://api.certspotter.com/v1/issuances?"
        f"domain={domain}&include_subdomains=true&expand=dns_names"
    )
    resp = http.get(url, timeout=25)
    if resp.status_code != 200:
        return out
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return out
    if not isinstance(data, list):
        return out
    for issuance in data:
        for name in issuance.get("dns_names", []) or []:
            host = _clean_host(name, domain)
            if host:
                out.add(host)
    return out


# Registry of passive sources — order is used for display, not execution.
SOURCES = {
    "crt_sh": _source_crt_sh,
    "hackertarget": _source_hackertarget,
    "otx": _source_otx,
    "rapiddns": _source_rapiddns,
    "urlscan": _source_urlscan,
    "anubis": _source_anubis,
    "wayback": _source_wayback,
    "subdomain_center": _source_subdomain_center,
    "certspotter": _source_certspotter,
}


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class SubdomainEnum(BaseModule):
    name = "recon/subdomain"
    description = (
        "Passive subdomain discovery across 9 free sources, plus DNS "
        "brute-force with permutations, optional resolve and HTTP liveness."
    )
    category = "recon"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain")
        self.add_option("THREADS", "20", False, "Threads for brute-force / probing")
        self.add_option("WORDLIST", "", False, "Custom wordlist path (optional)")
        self.add_option(
            "SOURCES",
            "all",
            False,
            "Comma-separated passive sources, or 'all' / 'none'",
        )
        self.add_option("USE_BRUTEFORCE", "true", False, "DNS brute-force subdomains")
        self.add_option(
            "PERMUTATIONS",
            "true",
            False,
            "Expand found subs with common permutations (api -> api-dev, api2, ...)",
        )
        self.add_option("LIVE_CHECK", "false", False, "HTTP HEAD on 80/443 to find live hosts")
        self.add_option("RESOLVE", "false", False, "Resolve each subdomain to IPs")

    # --- option parsing ---------------------------------------------------

    def _bool_opt(self, name, default=False):
        val = (self.get_option(name) or "").strip().lower()
        if val in ("true", "yes", "y", "1", "on"):
            return True
        if val in ("false", "no", "n", "0", "off", ""):
            return False
        return default

    def _selected_sources(self):
        raw = (self.get_option("SOURCES") or "all").strip().lower()
        if raw in ("", "all", "*"):
            return list(SOURCES.keys())
        if raw == "none":
            return []
        picks = []
        for part in raw.split(","):
            key = part.strip().lower()
            if key and key in SOURCES and key not in picks:
                picks.append(key)
            elif key and key not in SOURCES:
                print_status(f"Unknown source '{key}' ignored", "warning")
        return picks

    # --- passive gathering ------------------------------------------------

    def _run_passive(self, domain, sources):
        """Fan out source queries in parallel and collect per-source results."""
        by_source = {}
        failed = {}
        if not sources:
            return by_source, failed

        total = len(sources)
        print_status(
            f"Querying {total} passive source(s) in parallel: "
            f"{Colors.DIM}{', '.join(sources)}{Colors.RESET}",
            "info",
        )
        workers = min(8, total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(SOURCES[name], domain): name for name in sources}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                done += 1
                try:
                    hosts = future.result() or set()
                    cleaned = {h for h in hosts if h}
                    by_source[name] = sorted(cleaned)
                    color = Colors.GREEN if cleaned else Colors.DIM
                    print_status(
                        f"[source {done}/{total}] {color}{name}{Colors.RESET}: "
                        f"found {len(cleaned)} subdomain(s)",
                        "success" if cleaned else "info",
                    )
                except Exception as exc:  # one source must not kill the run
                    failed[name] = str(exc)
                    by_source[name] = []
                    print_status(
                        f"[source {done}/{total}] {name}: failed — {exc}",
                        "warning",
                    )
        return by_source, failed

    # --- brute-force ------------------------------------------------------

    def _default_wordlist(self):
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "wordlists",
            "subdomains.txt",
        )

    def _check_subdomain(self, sub):
        try:
            socket.gethostbyname(sub)
            return sub
        except (socket.gaierror, socket.herror, UnicodeError):
            return None

    def _brute_force(self, domain, wordlist_path, threads):
        found = set()
        wl = wordlist_path if wordlist_path and os.path.exists(wordlist_path) else self._default_wordlist()
        if not os.path.exists(wl):
            print_status("No wordlist found, skipping brute-force", "warning")
            return found
        try:
            with open(wl, "r", encoding="utf-8", errors="ignore") as f:
                words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            print_status(f"Could not read wordlist: {e}", "warning")
            return found

        candidates = [f"{w.lower()}.{domain}" for w in words]
        print_status(
            f"Brute-forcing {len(candidates)} candidate(s) with {threads} thread(s)",
            "info",
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(self._check_subdomain, c): c for c in candidates}
            for fut in concurrent.futures.as_completed(futs):
                res = fut.result()
                if res:
                    found.add(res)
                    print_status(f"[brute] {res}", "success")
        return found

    # --- permutation expansion -------------------------------------------

    _PERM_SUFFIXES = ("-dev", "-staging", "-stage", "-prod", "-qa",
                       "-test", "-uat", "-internal", "-admin", "2", "3")

    def _permute(self, hosts, domain, threads):
        """Given seed hosts like api.example.com, probe api-dev.example.com etc."""
        if not hosts:
            return set()
        candidates = set()
        for host in hosts:
            if host == domain:
                continue
            if not host.endswith("." + domain):
                continue
            label = host[: -(len(domain) + 1)]
            # Only permute the left-most label to keep the fan-out sane.
            left = label.split(".", 1)[0]
            rest = label[len(left):]  # includes the leading dot if any
            for suf in self._PERM_SUFFIXES:
                candidates.add(f"{left}{suf}{rest}.{domain}")
            # Try the www.-prefix variant for each sub.
            if not label.startswith("www."):
                candidates.add(f"www.{label}.{domain}")

        candidates -= set(hosts)
        if not candidates:
            return set()
        print_status(
            f"Testing {len(candidates)} permutation candidate(s)",
            "info",
        )
        found = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(self._check_subdomain, c): c for c in candidates}
            for fut in concurrent.futures.as_completed(futs):
                res = fut.result()
                if res:
                    found.add(res)
                    print_status(f"[perm] {res}", "success")
        return found

    # --- resolve + live probe --------------------------------------------

    def _resolve_all(self, hosts, threads):
        resolved = {}

        def _resolve(h):
            try:
                _, _, ips = socket.gethostbyname_ex(h)
                return h, sorted(set(ips)) if ips else []
            except (socket.gaierror, socket.herror, UnicodeError):
                return h, []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for host, ips in pool.map(_resolve, hosts):
                if ips:
                    resolved[host] = ips
        return resolved

    def _live_probe(self, hosts, threads):
        live = []

        def _probe(h):
            for scheme in ("https", "http"):
                try:
                    resp = http.head(f"{scheme}://{h}", allow_redirects=True, timeout=8)
                    if resp.status_code < 500:
                        return h
                except Exception:
                    continue
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for h in pool.map(_probe, hosts):
                if h:
                    live.append(h)
        return sorted(live)

    # --- main -------------------------------------------------------------

    def run(self):
        if not self.validate():
            return False

        target = (self.get_option("TARGET") or "").strip().lower().lstrip(".")
        if not target:
            print_status("TARGET is empty", "error")
            return False

        try:
            threads = max(1, int(self.get_option("THREADS") or 20))
        except (TypeError, ValueError):
            threads = 20

        print_status(
            f"Starting subdomain enumeration on {Colors.BOLD}{target}{Colors.RESET}",
            "info",
        )

        sources = self._selected_sources()
        by_source, failed = self._run_passive(target, sources)

        all_subs = set()
        for name, hosts in by_source.items():
            all_subs.update(hosts)

        if self._bool_opt("USE_BRUTEFORCE", default=True):
            bf = self._brute_force(target, self.get_option("WORDLIST"), threads)
            by_source["bruteforce"] = sorted(bf)
            all_subs.update(bf)

        if self._bool_opt("PERMUTATIONS", default=True):
            perms = self._permute(all_subs, target, threads)
            if perms:
                by_source["permutations"] = sorted(perms)
                all_subs.update(perms)

        final = sorted(h for h in all_subs if h)
        counts = {name: len(hosts) for name, hosts in by_source.items()}

        resolved = {}
        if self._bool_opt("RESOLVE", default=False) and final:
            print_status(f"Resolving {len(final)} host(s) to IPs", "info")
            resolved = self._resolve_all(final, threads)

        live = []
        if self._bool_opt("LIVE_CHECK", default=False) and final:
            print_status(f"HTTP-probing {len(final)} host(s) for liveness", "info")
            live = self._live_probe(final, threads)

        # --- summary ------------------------------------------------------
        top = sorted(
            ((n, c) for n, c in counts.items() if c > 0),
            key=lambda kv: kv[1],
            reverse=True,
        )[:10]
        print()
        print_status(
            f"{Colors.BOLD}Enumeration complete.{Colors.RESET} "
            f"{Colors.GREEN}{len(final)}{Colors.RESET} unique subdomain(s)",
            "success",
        )
        if top:
            print_status("Top sources:", "info")
            for name, count in top:
                print(f"      {Colors.CYAN}{name:<18}{Colors.RESET} {count}")
        if failed:
            print_status(
                f"{len(failed)} source(s) failed: {', '.join(sorted(failed))}",
                "warning",
            )

        self.results = {
            "target": target,
            "total_found": len(final),
            "sources_queried": sources,
            "sources_failed": failed,
            "by_source": by_source,
            "subdomain_count_by_source": counts,
            "subdomains": final,
            "live_subdomains": live,
            "resolved_ips": resolved,
        }
        return True
