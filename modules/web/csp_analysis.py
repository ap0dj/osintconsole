import re

from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core import http


class CspAnalysis(BaseModule):
    name = "web/csp_analysis"
    description = "Analyze Content-Security-Policy weaknesses + clickjacking protection"
    category = "web"
    target_type = "domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    def _parse_csp(self, csp):
        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            directives[tokens[0].lower()] = tokens[1:]
        return directives

    def _script_src_is_modernized(self, script_src_value):
        """CSP3: unsafe-inline is ignored by the browser when strict-dynamic,
        a nonce token, or a hash is present in script-src."""
        low = script_src_value.lower()
        if "'strict-dynamic'" in low:
            return True
        if "'nonce-" in low:
            return True
        if re.search(r"'(?:sha256|sha384|sha512)-[A-Za-z0-9+/=]+'", low):
            return True
        return False

    def _analyze_csp(self, directives):
        weaknesses = []
        notes = []
        if "default-src" not in directives and "script-src" not in directives:
            weaknesses.append("No default-src or script-src (CSP largely ineffective)")

        script = directives.get("script-src", directives.get("default-src", []))
        script_vals = [s.lower() for s in script]
        script_joined = " ".join(script_vals)

        # Check script-src for CSP3 modernization. If script-src is absent,
        # the same suppression applies when default-src carries strict-dynamic/nonce/hash.
        default_joined = " ".join(s.lower() for s in directives.get("default-src", []))
        modernized = self._script_src_is_modernized(script_joined) or (
            "script-src" not in directives
            and self._script_src_is_modernized(default_joined)
        )

        if "'unsafe-inline'" in script_vals:
            if modernized:
                # CSP3 explicitly ignores 'unsafe-inline' when strict-dynamic / nonce / hash is present.
                notes.append(
                    "script-src 'unsafe-inline' (ignored by browser due to strict-dynamic/nonce/hash - CSP3)"
                )
            else:
                weaknesses.append("script-src allows 'unsafe-inline' (XSS via inline scripts)")
        if "'unsafe-eval'" in script_vals:
            weaknesses.append("script-src allows 'unsafe-eval'")
        if "*" in script_vals:
            weaknesses.append("script-src allows wildcard * (any host)")
        if any(s.startswith("http:") for s in script_vals):
            weaknesses.append("script-src allows insecure http: sources")
        if "data:" in script_vals:
            weaknesses.append("script-src allows data: URIs (XSS vector)")

        if "object-src" not in directives:
            weaknesses.append("Missing object-src (should be 'none')")
        elif "'none'" not in [s.lower() for s in directives.get("object-src", [])]:
            weaknesses.append("object-src is not 'none'")

        if "base-uri" not in directives:
            weaknesses.append("Missing base-uri (base-tag injection risk)")

        if "frame-ancestors" not in directives:
            weaknesses.append("Missing frame-ancestors (clickjacking not blocked via CSP)")

        return weaknesses, notes

    def run(self):
        if not self.validate():
            return False

        url = normalize_url(self.get_option("TARGET"))
        verify_tls = self.get_option("VERIFY_TLS").lower() != "false"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  CSP & Clickjacking Analysis: {url}")
        print(f"{'='*58}{Colors.RESET}\n")

        try:
            resp = http.get(url, verify=verify_tls, allow_redirects=True, timeout=12)
        except Exception as e:
            print_status(f"Request failed: {e}", "error")
            return False

        csp = (resp.headers.get("Content-Security-Policy")
               or resp.headers.get("Content-Security-Policy-Report-Only") or "")
        report_only = (not resp.headers.get("Content-Security-Policy")
                       and bool(resp.headers.get("Content-Security-Policy-Report-Only")))
        xfo = resp.headers.get("X-Frame-Options", "")

        directives = {}
        csp_weaknesses = []
        csp_notes = []
        if csp:
            directives = self._parse_csp(csp)
            csp_weaknesses, csp_notes = self._analyze_csp(directives)
            print_status(f"CSP present ({len(directives)} directives)"
                         + (" [report-only]" if report_only else ""), "success")
            for w in csp_weaknesses:
                print_status(f"  WEAK: {w}", "warning")
            for n in csp_notes:
                print_status(f"  INFO: {n}", "info")
        else:
            print_status("No Content-Security-Policy header", "warning")
            csp_weaknesses.append("No CSP header at all")

        # Clickjacking analysis
        frame_ancestors = directives.get("frame-ancestors")
        clickjacking_protected = False
        cj_reason = ""
        if xfo:
            if xfo.upper() in ("DENY", "SAMEORIGIN"):
                clickjacking_protected = True
                cj_reason = f"X-Frame-Options: {xfo}"
        if frame_ancestors and not report_only:
            fa = [f.lower() for f in frame_ancestors]
            if "'none'" in fa or "'self'" in fa:
                clickjacking_protected = True
                cj_reason = f"CSP frame-ancestors: {' '.join(frame_ancestors)}"

        if clickjacking_protected:
            print_status(f"Clickjacking: protected ({cj_reason})", "success")
        else:
            print_status("Clickjacking: NOT protected (no XFO / frame-ancestors)", "warning")

        self.results = {
            "target": url,
            "csp_present": bool(csp),
            "csp_report_only": report_only,
            "csp_raw": csp,
            "csp_directives": {k: v for k, v in directives.items()},
            "csp_weaknesses": csp_weaknesses,
            "csp_notes": csp_notes,
            "x_frame_options": xfo,
            "clickjacking_protected": clickjacking_protected,
        }

        color = Colors.GREEN if (not csp_weaknesses and clickjacking_protected) else Colors.YELLOW
        print(f"\n{Colors.BOLD}{color}{'='*58}")
        print(f"  CSP weaknesses: {len(csp_weaknesses)} | "
              f"Clickjacking protected: {clickjacking_protected}")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
