import re
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.config import Config
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CveLookup(FetchErrorsMixin, BaseModule):
    name = "recon/cve_lookup"
    description = "Look up CVEs by keyword, product, or CVE-ID via the NVD database"
    category = "recon"
    target_type = "keyword"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Keyword/product (e.g. 'apache 2.4') or CVE-ID")
        self.add_option("MAX_RESULTS", "20", False, "Max CVEs to return")
        self.add_option("MIN_SCORE", "0", False, "Minimum CVSS score filter (0-10)")

    def _headers(self):
        headers = {}
        nvd_key = Config().get("api_keys.nvd")
        if nvd_key:
            headers["apiKey"] = nvd_key
        return headers

    def _query(self, params):
        """Return the parsed NVD JSON, or None when the fetch itself failed
        (exception / non-200 / bad JSON). None is distinct from a valid 200
        response that simply lists no vulnerabilities."""
        try:
            resp = http.get(NVD_API, params=params, headers=self._headers(), timeout=20)
        except Exception as e:
            self._note_error(f"NVD query failed: {e}")
            return None
        if resp.status_code != 200:
            self._note_error(f"NVD returned HTTP {resp.status_code}")
            return None
        try:
            return resp.json()
        except Exception as e:
            self._note_error(f"NVD JSON parse error: {e}")
            return None

    def _parse_cve(self, item):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descs = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        score, severity, vector = None, None, None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                data = metrics[key][0].get("cvssData", {})
                score = data.get("baseScore")
                severity = (data.get("baseSeverity")
                            or metrics[key][0].get("baseSeverity"))
                vector = data.get("vectorString")
                break

        refs = [r.get("url") for r in cve.get("references", [])][:5]
        return {
            "id": cve_id,
            "score": score,
            "severity": severity,
            "vector": vector,
            "published": cve.get("published"),
            "description": description[:300],
            "references": refs,
        }

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        max_results = int(self.get_option("MAX_RESULTS") or 20)
        min_score = float(self.get_option("MIN_SCORE") or 0)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  CVE Lookup: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        self._errors = []
        is_cve_id = bool(re.match(r"^CVE-\d{4}-\d+$", target, re.IGNORECASE))
        if is_cve_id:
            print_status(f"Looking up {target.upper()}...", "info")
            data = self._query({"cveId": target.upper()})
        else:
            print_status(f"Searching NVD for '{target}'...", "info")
            data = self._query({"keywordSearch": target,
                                 "resultsPerPage": max_results})

        # NVD unreachable / throttled (403/429 are common without a key): a fetch
        # failure must NOT be reported as "no CVEs found".
        if data is None:
            self.results = {"query": target, "total": 0, "cves": []}
            return self._fail()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print_status("No CVEs found", "warning")
            self.results = {"query": target, "total": 0, "cves": [],
                            "fetch_errors": []}
            return True

        cves = [self._parse_cve(v) for v in vulns[:max_results]]
        if min_score > 0:
            cves = [c for c in cves if (c["score"] or 0) >= min_score]
        cves.sort(key=lambda c: c["score"] or 0, reverse=True)

        for c in cves:
            score = c["score"]
            sev = (c["severity"] or "").upper()
            color = (Colors.RED if score and score >= 7 else
                     Colors.YELLOW if score and score >= 4 else Colors.GREEN)
            print(f" {color}[{c['id']}]{Colors.RESET} "
                  f"CVSS {score if score is not None else '?'} {sev}")
            print(f"   {c['description'][:140]}")

        self.results = {
            "query": target,
            "total_available": data.get("totalResults", len(cves)),
            "returned": len(cves),
            "cves": cves,
            "fetch_errors": list(getattr(self, "_errors", [])),
        }

        high = [c for c in cves if (c["score"] or 0) >= 7]
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  {len(cves)} CVE(s) shown | {len(high)} high/critical")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return True
