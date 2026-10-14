from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core import http


WELL_KNOWN = [
    ("security.txt", ".well-known/security.txt"),
    ("security.txt (root)", "security.txt"),
    ("change-password", ".well-known/change-password"),
    ("dnt-policy", ".well-known/dnt-policy.txt"),
    ("mta-sts", ".well-known/mta-sts.txt"),
    ("gpc", ".well-known/gpc.json"),
    ("openid-config", ".well-known/openid-configuration"),
    ("assetlinks", ".well-known/assetlinks.json"),
    ("apple-app-site", ".well-known/apple-app-site-association"),
    ("nodeinfo", ".well-known/nodeinfo"),
    ("host-meta", ".well-known/host-meta"),
]

SECURITY_TXT_FIELDS = [
    "Contact", "Expires", "Encryption", "Acknowledgments", "Preferred-Languages",
    "Canonical", "Policy", "Hiring", "CSAF",
]


class SecurityTxt(BaseModule):
    name = "web/security_txt"
    description = "Fetch & parse security.txt + enumerate .well-known endpoints"
    category = "web"
    target_type = "domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")

    def _parse_security_txt(self, text):
        fields = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                matched = next((f for f in SECURITY_TXT_FIELDS
                                if f.lower() == key.lower()), None)
                if matched:
                    fields.setdefault(matched, []).append(value)
        return fields

    def run(self):
        if not self.validate():
            return False

        base = normalize_url(self.get_option("TARGET"))

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  security.txt & .well-known: {base}")
        print(f"{'='*58}{Colors.RESET}\n")

        found = []
        security_txt_data = {}
        errors = 0
        responded = 0

        for label, path in WELL_KNOWN:
            url = f"{base}/{path}"
            try:
                resp = http.get(url, allow_redirects=True, timeout=10)
                responded += 1
                ctype = resp.headers.get("Content-Type", "")
                # Treat HTML 200 as "not really there" for text endpoints
                is_html = "text/html" in ctype.lower()
                if resp.status_code == 200 and resp.text.strip() and not (
                        is_html and "security.txt" in path):
                    found.append({"name": label, "url": url,
                                  "status": resp.status_code,
                                  "content_type": ctype})
                    print_status(f"[FOUND] {label}: {url}", "success")
                    if "security.txt" in path and not is_html:
                        parsed = self._parse_security_txt(resp.text)
                        if parsed:
                            security_txt_data = parsed
                            for field, values in parsed.items():
                                for v in values:
                                    print_status(f"    {field}: {v}", "info")
            except Exception:
                errors += 1

        # Host unreachable: every probe errored. Not a clean "nothing found".
        if WELL_KNOWN and responded == 0:
            self.results = {
                "target": base,
                "well_known_found": [],
                "well_known_count": 0,
                "security_txt": {},
                "has_security_txt": False,
                "error": "fetch_failed",
                "connect_errors": errors,
            }
            print_status(f"All {len(WELL_KNOWN)} probes to {base} failed - "
                         f"status UNKNOWN, not 'nothing found'", "error")
            return False

        self.results = {
            "target": base,
            "well_known_found": found,
            "well_known_count": len(found),
            "security_txt": security_txt_data,
            "has_security_txt": bool(security_txt_data),
            "connect_errors": errors,
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Found {len(found)} .well-known endpoint(s)")
        if security_txt_data:
            print(f"  security.txt present with {len(security_txt_data)} field(s)")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
