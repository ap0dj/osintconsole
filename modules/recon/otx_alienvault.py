import re
from collections import Counter
from time import monotonic
from urllib.parse import quote
from core.base_module import BaseModule
from core.utils import (print_status, Colors, is_valid_ip, is_valid_domain,
                        is_valid_url)
from core.config import Config
from core import http


OTX_BASE = "https://otx.alienvault.com/api/v1"

IP_MODES = ("general", "malware", "url_list", "passive_dns")
DOMAIN_MODES = ("general", "malware", "url_list", "whois")
URL_MODES = ("general",)

HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


class OtxAlienvault(BaseModule):
    name = "recon/otx_alienvault"
    description = ("AlienVault OTX - pulses, reputation, passive DNS, malware "
                   "(free open-community threat intel)")
    category = "recon"
    target_type = "ip/domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "IP / domain / URL / file hash / CVE-ID / pulse query")
        self.add_option("MODES", "auto", False,
                        "auto, all, or csv "
                        "(general,malware,url_list,passive_dns,whois)")
        self.add_option("MAX_PULSES", "20", False, "Max pulses to collect")

    # ---------- HTTP ---------------------------------------------------
    def _headers(self):
        headers = {"Accept": "application/json"}
        key = Config().get("api_keys.otx")
        if key:
            headers["X-OTX-API-KEY"] = key
        return headers

    def _get(self, path, params=None):
        """GET helper. Returns (data, err). err in {None,'no_data','rate_limited',
        'forbidden','bad_json','error:...','http_NNN'}."""
        try:
            resp = http.get(f"{OTX_BASE}{path}",
                            headers=self._headers(),
                            params=params or {}, timeout=20)
        except Exception as e:
            return {}, f"error: {e}"
        sc = resp.status_code
        if sc == 200:
            try:
                return resp.json(), None
            except ValueError:
                return {}, "bad_json"
        if sc == 404:
            return {}, "no_data"
        if sc == 429:
            return {}, "rate_limited"
        if sc == 403:
            return {}, "forbidden"
        return {}, f"http_{sc}"

    # ---------- target detection --------------------------------------
    def _detect(self, target):
        t = (target or "").strip()
        if is_valid_ip(t):
            return "ip", t
        if CVE_RE.match(t):
            return "cve", t.upper()
        if HASH_RE.match(t) and len(t) in (32, 40, 64):
            return "hash", t.lower()
        if t.startswith(("http://", "https://")) or is_valid_url(t):
            return "url", t
        if is_valid_domain(t):
            return "domain", t.lower()
        return "search", t

    def _resolve_modes(self, raw, kind):
        avail = {"ip": IP_MODES, "domain": DOMAIN_MODES,
                 "url": URL_MODES}.get(kind)
        if not avail:
            return []
        avail_set = set(avail)
        raw = (raw or "").strip().lower()
        if raw == "all":
            return list(avail)
        if raw in ("", "auto"):
            if kind == "ip":
                return ["general", "malware", "passive_dns"]
            if kind == "domain":
                return ["general", "malware", "url_list", "whois"]
            return ["general"]
        picked = []
        for m in raw.split(","):
            m = m.strip()
            if m in avail_set and m not in picked:
                picked.append(m)
        return picked

    # ---------- pulse normalization -----------------------------------
    @staticmethod
    def _author_of(p):
        a = p.get("author")
        if isinstance(a, dict):
            return a.get("username") or a.get("name")
        return a or p.get("author_name")

    def _parse_pulse(self, p):
        return {
            "id": p.get("id"),
            "name": p.get("name"),
            "author": self._author_of(p),
            "created": p.get("created"),
            "description": (p.get("description") or "")[:300],
            "tags": list(p.get("tags") or []),
            "malware_families": [
                (m.get("display_name") or m.get("name"))
                if isinstance(m, dict) else m
                for m in (p.get("malware_families") or [])
            ],
            "attack_ids": [
                (a.get("display_name") or a.get("name") or a.get("id"))
                if isinstance(a, dict) else a
                for a in (p.get("attack_ids") or [])
            ],
            "country": list(p.get("targeted_countries") or []),
            "references": list(p.get("references") or []),
        }

    def _pulses_from_general(self, data, max_pulses):
        info = data.get("pulse_info") or {}
        return [self._parse_pulse(p)
                for p in (info.get("pulses") or [])[:max_pulses]]

    # ---------- endpoint helpers --------------------------------------
    def _ip_section(self, ip, section):
        return self._get(f"/indicators/IPv4/{ip}/{section}")

    def _domain_section(self, domain, section):
        if section == "whois":
            return self._get(f"/indicators/hostname/{domain}/whois")
        return self._get(f"/indicators/domain/{domain}/{section}")

    def _url_general(self, url_target):
        return self._get(f"/indicators/url/{quote(url_target, safe='')}/general")

    def _file_analysis(self, h):
        return self._get(f"/indicators/file/{h}/analysis")

    def _cve_record(self, cve_id):
        return self._get(f"/indicators/cve/{cve_id}/general")

    def _pulse_search(self, query, max_pulses):
        return self._get("/search/pulses",
                         params={"q": query, "limit": min(max_pulses, 50)})

    # ---------- UI helpers --------------------------------------------
    def _banner(self, text):
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  {text}")
        print(f"{Colors.CYAN}{'='*58}{Colors.RESET}\n")

    def _print_pulses_preview(self, pulses):
        for p in pulses[:10]:
            name = (p.get("name") or "<untitled>")[:60]
            author = p.get("author") or "?"
            fams = (p.get("malware_families") or [])
            tag = (f" {Colors.YELLOW}malware={', '.join(str(f) for f in fams)[:40]}"
                   f"{Colors.RESET}") if fams else ""
            print(f"  {Colors.MAGENTA}[pulse]{Colors.RESET} "
                  f"{Colors.BOLD}{name}{Colors.RESET} "
                  f"{Colors.DIM}by {author}{Colors.RESET}{tag}")

    # ---------- main --------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        modes_raw = self.get_option("MODES") or "auto"
        try:
            max_pulses = max(1, int(self.get_option("MAX_PULSES") or 20))
        except (TypeError, ValueError):
            max_pulses = 20

        kind, normalized = self._detect(target)
        self._banner(f"AlienVault OTX: {normalized}  ({kind})")

        if not Config().get("api_keys.otx"):
            print_status("No OTX key set - using public read access", "info")

        results = {
            "target": normalized,
            "target_type_detected": kind,
            "pulse_count": 0,
            "pulses": [],
            "reputation": {},
            "geo": {},
            "malware_hashes": [],
            "urls_seen": [],
            "passive_dns": [],
            "whois": {},
            "file_analysis": {},
            "cve_info": {},
            "warnings": [],
            "stats": {"endpoints_hit": 0, "duration_sec": 0.0},
        }

        t0 = monotonic()
        pulses_bag = []
        seen_pulse_ids = set()

        def _add_pulses(ps):
            for p in ps:
                pid = p.get("id")
                if pid and pid in seen_pulse_ids:
                    continue
                if pid:
                    seen_pulse_ids.add(pid)
                pulses_bag.append(p)

        def _handle_err(label, err):
            if err == "no_data":
                print_status(f"{label}: no data (404)", "info")
            elif err == "rate_limited":
                print_status(f"{label}: rate limited (429) - skipping", "warning")
                results["warnings"].append(f"{label}: rate_limited")
            elif err == "forbidden":
                print_status(f"{label}: forbidden (403) - key may be required",
                             "warning")
                results["warnings"].append(f"{label}: forbidden")
            elif err:
                print_status(f"{label}: {err}", "warning")
                results["warnings"].append(f"{label}: {err}")

        # ---------- IP / DOMAIN / URL branch --------------------------
        if kind in ("ip", "domain", "url"):
            modes = self._resolve_modes(modes_raw, kind)
            if not modes:
                print_status("No valid modes resolved for this target type",
                             "error")
                return False
            print_status(f"Modes: {', '.join(modes)}", "info")

            for section in modes:
                print_status(f"Fetching {section}...", "info")
                if kind == "ip":
                    data, err = self._ip_section(normalized, section)
                elif kind == "domain":
                    data, err = self._domain_section(normalized, section)
                else:
                    data, err = self._url_general(normalized)
                results["stats"]["endpoints_hit"] += 1
                _handle_err(section, err)
                if not data:
                    continue

                if section == "general":
                    _add_pulses(self._pulses_from_general(data, max_pulses))
                    if kind == "ip":
                        results["reputation"] = {
                            "reputation": data.get("reputation"),
                            "sections": data.get("sections") or [],
                        }
                        results["geo"] = {
                            "country_name": data.get("country_name"),
                            "country_code": data.get("country_code"),
                            "city": data.get("city"),
                            "region": data.get("region"),
                            "asn": data.get("asn"),
                            "latitude": data.get("latitude"),
                            "longitude": data.get("longitude"),
                        }
                        rep = results["reputation"].get("reputation")
                        if rep is not None:
                            print_status(
                                f"Reputation: {rep}  |  {results['geo'].get('country_name')}"
                                f" / ASN {results['geo'].get('asn')}",
                                "warning" if rep else "success")
                    elif kind == "domain":
                        results["whois"].setdefault("type", data.get("type"))
                        results["whois"].setdefault("alexa", data.get("alexa"))

                elif section == "malware":
                    hashes = []
                    for item in (data.get("data") or [])[:200]:
                        hashes.append({
                            "hash": item.get("hash"),
                            "detections": item.get("detections"),
                            "date": item.get("date"),
                        })
                    results["malware_hashes"] = hashes
                    if hashes:
                        print_status(f"Linked malware samples: {len(hashes)}",
                                     "warning")

                elif section == "url_list":
                    urls = []
                    for item in (data.get("url_list") or [])[:200]:
                        urls.append({
                            "url": item.get("url"),
                            "date": item.get("date"),
                            "httpcode": item.get("httpcode"),
                        })
                    results["urls_seen"] = urls
                    if urls:
                        print_status(f"Observed URLs: {len(urls)}", "warning")

                elif section == "passive_dns":
                    pdns = []
                    for item in (data.get("passive_dns") or [])[:300]:
                        pdns.append({
                            "hostname": item.get("hostname"),
                            "address": item.get("address"),
                            "first": item.get("first"),
                            "last": item.get("last"),
                            "record_type": item.get("record_type"),
                        })
                    results["passive_dns"] = pdns
                    if pdns:
                        print_status(f"Passive DNS rows: {len(pdns)}",
                                     "success")

                elif section == "whois":
                    rows = {}
                    for row in (data.get("data") or []):
                        k = row.get("key")
                        if k:
                            rows[k] = row.get("value")
                    related = data.get("related") or {}
                    results["whois"].update({
                        "fields": rows,
                        "related_domains": related.get("domains") or [],
                        "related_emails": related.get("emails") or [],
                    })
                    if rows:
                        print_status(f"WHOIS fields: {len(rows)}", "success")

        # ---------- HASH branch --------------------------------------
        elif kind == "hash":
            print_status("Fetching file analysis...", "info")
            data, err = self._file_analysis(normalized)
            results["stats"]["endpoints_hit"] += 1
            _handle_err("file", err)
            if data:
                analysis = data.get("analysis") or {}
                info_results = ((analysis.get("info") or {}).get("results")) or {}
                results["file_analysis"] = {
                    "md5": info_results.get("md5"),
                    "sha1": info_results.get("sha1"),
                    "sha256": info_results.get("sha256"),
                    "filename": info_results.get("filename")
                               or info_results.get("file_name"),
                    "filesize": info_results.get("file_size")
                               or info_results.get("filesize"),
                    "filetype": info_results.get("file_type"),
                    "plugins": list((analysis.get("plugins") or {}).keys()),
                }
                _add_pulses(self._pulses_from_general(data, max_pulses))
                fa = results["file_analysis"]
                print_status(
                    f"File: type={fa.get('filetype') or '?'}, "
                    f"size={fa.get('filesize') or '?'}", "info")

        # ---------- CVE branch ---------------------------------------
        elif kind == "cve":
            print_status(f"Fetching CVE record: {normalized}", "info")
            data, err = self._cve_record(normalized)
            results["stats"]["endpoints_hit"] += 1
            _handle_err("cve", err)
            if data:
                results["cve_info"] = {
                    "id": data.get("indicator") or normalized,
                    "cvss": data.get("cvss") or {},
                    "description": (data.get("description") or "")[:400],
                    "date_created": data.get("date_created"),
                    "date_modified": data.get("date_modified"),
                }
                _add_pulses(self._pulses_from_general(data, max_pulses))
                cvss = results["cve_info"]["cvss"] or {}
                print_status(
                    f"CVSS: {cvss.get('Score') or cvss.get('score') or '?'}  "
                    f"({cvss.get('Severity') or cvss.get('severity') or '?'})",
                    "warning")
                # Soft cross-reference with cve_lookup module
                try:
                    from modules.recon.cve_lookup import CveLookup  # noqa: F401
                    results["cve_info"]["cross_reference_available"] = True
                except Exception:
                    results["cve_info"]["cross_reference_available"] = False

        # ---------- SEARCH branch ------------------------------------
        else:
            print_status(f"Pulse search: {normalized}", "info")
            data, err = self._pulse_search(normalized, max_pulses)
            results["stats"]["endpoints_hit"] += 1
            _handle_err("search", err)
            if data:
                raw_pulses = data.get("results") or []
                _add_pulses([self._parse_pulse(p)
                             for p in raw_pulses[:max_pulses]])
                total = data.get("count") or len(raw_pulses)
                print_status(f"Search total: {total}", "info")

        # ---------- finalize + summary -------------------------------
        results["pulses"] = pulses_bag[:max_pulses]
        results["pulse_count"] = len(results["pulses"])
        results["stats"]["duration_sec"] = round(monotonic() - t0, 2)

        families, countries, authors = Counter(), Counter(), Counter()
        for p in results["pulses"]:
            for m in p.get("malware_families") or []:
                if m:
                    families[str(m)] += 1
            for c in p.get("country") or []:
                if c:
                    countries[str(c)] += 1
            if p.get("author"):
                authors[str(p["author"])] += 1

        if results["pulses"]:
            print()
            self._print_pulses_preview(results["pulses"])

        pc = results["pulse_count"]
        color = (Colors.RED if pc >= 5 else
                 Colors.YELLOW if pc else Colors.GREEN)
        print(f"\n{Colors.BOLD}{color}{'='*58}")
        print(f"  Target: {normalized}  ({kind})")
        print(f"  Pulses: {pc}")
        if families:
            top_m = ", ".join(f"{k}({v})" for k, v in families.most_common(5))
            print(f"  Top malware families: {top_m}")
        if countries:
            top_c = ", ".join(f"{k}({v})" for k, v in countries.most_common(5))
            print(f"  Top countries: {top_c}")
        if authors:
            top_a = ", ".join(f"{k}({v})" for k, v in authors.most_common(5))
            print(f"  Top authors: {top_a}")
        if results["warnings"]:
            print(f"  Warnings: {len(results['warnings'])}")
        print(f"  Endpoints hit: {results['stats']['endpoints_hit']}  "
              f"({results['stats']['duration_sec']}s)")
        print(f"{color}{'='*58}{Colors.RESET}\n")

        self.results = results
        return True
