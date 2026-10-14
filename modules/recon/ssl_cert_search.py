import json
from core.base_module import BaseModule
from core.utils import print_status
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


class SslCertSearch(FetchErrorsMixin, BaseModule):
    name = "recon/ssl_cert_search"
    description = ("Certificate transparency search (crt.sh + CertSpotter "
                   "fallback) - subdomains, issuers, validity windows")
    category = "recon"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain (e.g. example.com)")

    # ------------------------------------------------------------------
    def _crtsh(self, domain, suffix, subdomains, issuers, certs):
        """crt.sh JSON. Returns the record count, or None on failure."""
        try:
            resp = http.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        except Exception as e:
            self._note_error(f"crt.sh request failed: {e}")
            return None
        if resp.status_code != 200:
            self._note_error(f"crt.sh HTTP {resp.status_code}")
            return None
        text = (resp.text or "").strip()
        if not text:
            return 0           # reachable, just no data
        try:
            data = resp.json()
        except Exception:
            try:
                data = json.loads(text)
            except Exception as e:
                self._note_error(f"crt.sh JSON parse error: {e}")
                return None
        if not isinstance(data, list):
            self._note_error("crt.sh: unexpected response format")
            return None
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for nm in (entry.get("name_value") or "").splitlines():
                self._add_name(nm, domain, suffix, subdomains)
            issuer = (entry.get("issuer_name") or "").strip()
            if issuer:
                issuers.add(issuer)
        return len(data)

    def _certspotter(self, domain, suffix, subdomains, issuers, certs):
        """CertSpotter issuances (free, no key). Adds dns_names + validity.
        Returns the issuance count, or None on failure."""
        try:
            resp = http.get("https://api.certspotter.com/v1/issuances",
                            params={"domain": domain, "include_subdomains": "true",
                                    "expand": "dns_names"}, timeout=25)
        except Exception as e:
            self._note_error(f"CertSpotter request failed: {e}")
            return None
        if resp.status_code != 200:
            self._note_error(f"CertSpotter HTTP {resp.status_code}")
            return None
        try:
            data = resp.json()
        except Exception as e:
            self._note_error(f"CertSpotter JSON parse error: {e}")
            return None
        if not isinstance(data, list):
            return None
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for nm in (entry.get("dns_names") or []):
                self._add_name(nm, domain, suffix, subdomains)
            nb, na = entry.get("not_before"), entry.get("not_after")
            if nb or na:
                certs.append({"not_before": nb, "not_after": na,
                              "revoked": entry.get("revoked")})
        return len(data)

    @staticmethod
    def _add_name(nm, domain, suffix, out):
        nm = (nm or "").strip().lower()
        if not nm or "@" in nm:
            return
        if nm.startswith("*."):
            nm = nm[2:]
        # Base domain itself or a true sub-label (not "notexample.com").
        if nm == domain or nm.endswith(suffix):
            out.add(nm)

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        domain = self.get_option("TARGET").strip().lower().lstrip("*.")
        suffix = "." + domain
        self._errors = []
        subdomains, issuers, certs = set(), set(), []

        print_status(f"Certificate transparency search for {domain} "
                     f"(crt.sh + CertSpotter)...", "info")
        crt_n = self._crtsh(domain, suffix, subdomains, issuers, certs)
        # CertSpotter is both a fallback (when crt.sh fails) and a merge source.
        cs_n = self._certspotter(domain, suffix, subdomains, issuers, certs)

        sources = []
        if crt_n is not None:
            sources.append(f"crt.sh ({crt_n} records)")
        if cs_n is not None:
            sources.append(f"CertSpotter ({cs_n} issuances)")

        sub_list = sorted(subdomains)
        for s in sub_list:
            print_status(s, "success")

        self.results = {
            "domain": domain,
            "subdomains": sub_list,
            "subdomain_count": len(sub_list),
            "issuers": sorted(issuers),
            "validity_windows": certs[:200],
            "certificates_seen": (crt_n or 0) + (cs_n or 0),
            "sources_used": sources,
            "fetch_errors": list(self._errors),
        }

        # Both sources down (neither returned a count) AND nothing found = failure,
        # not an empty "domain has no certs".
        if crt_n is None and cs_n is None:
            return self._fail()

        print_status(f"{len(sub_list)} unique subdomains, {len(issuers)} issuers "
                     f"via {', '.join(sources) or 'no source'}", "info")
        if self._errors:
            print_status(f"({len(self._errors)} source(s) failed - results may be "
                         f"partial)", "warning")
        return True
