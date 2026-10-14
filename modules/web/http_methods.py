from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core import http


METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

RISKY = {
    "PUT": "May allow arbitrary file upload",
    "DELETE": "May allow arbitrary file deletion",
    "TRACE": "Cross-Site Tracing (XST) - can leak headers/cookies",
    "CONNECT": "May allow proxying through the server",
    "PATCH": "May allow resource modification",
}


class HttpMethods(BaseModule):
    name = "web/http_methods"
    description = "Test allowed HTTP methods and flag risky ones (PUT/DELETE/TRACE/CONNECT)"
    category = "web"
    target_type = "domain/url"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    def run(self):
        if not self.validate():
            return False

        url = normalize_url(self.get_option("TARGET"))
        verify_tls = self.get_option("VERIFY_TLS").lower() != "false"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  HTTP Methods Test: {url}")
        print(f"{'='*58}{Colors.RESET}\n")

        # OPTIONS advertised methods
        advertised = []
        try:
            resp = http.request("OPTIONS", url, verify=verify_tls, allow_redirects=False)
            allow = resp.headers.get("Allow", "")
            if allow:
                advertised = [m.strip() for m in allow.split(",") if m.strip()]
                print_status(f"OPTIONS Allow header: {allow}", "success")
        except Exception as e:
            print_status(f"OPTIONS request failed: {e}", "warning")

        # Actively test each method
        allowed = {}
        method_support = {}  # method -> True / False / None (ambiguous)
        risky_found = []
        for method in METHODS:
            try:
                resp = http.request(method, url, verify=verify_tls, allow_redirects=False,
                                    timeout=10)
                code = resp.status_code
                allowed[method] = code
                if code in (405, 501):
                    supported = False
                elif code in (200, 201, 202, 204, 206, 301, 302, 303, 307, 308, 401, 403):
                    supported = True
                else:
                    supported = None  # ambiguous (404/400/500/etc.) - don't call it supported
                method_support[method] = supported
                if supported is True:
                    note = RISKY.get(method, "")
                    status = "warning" if note else "success"
                    print_status(f"{method}: HTTP {code}" + (f"  [{note}]" if note else ""),
                                 status)
                    if note:
                        risky_found.append({"method": method, "status_code": code,
                                            "risk": note})
                    # XST check for TRACE
                    if method == "TRACE" and "TRACE" in (resp.text or "").upper():
                        print_status("  TRACE reflects request (XST confirmed)", "warning")
                elif supported is None:
                    print_status(f"{method}: HTTP {code} [ambiguous - not treated as supported]",
                                 "info")
            except Exception:
                allowed[method] = None
                method_support[method] = None

        supported_methods = [m for m, s in method_support.items() if s is True]

        self.results = {
            "target": url,
            "advertised_methods": advertised,
            "tested_methods": allowed,
            "method_support": method_support,
            "supported_methods": supported_methods,
            "risky_methods": risky_found,
        }

        color = Colors.YELLOW if risky_found else Colors.GREEN
        print(f"\n{Colors.BOLD}{color}{'='*58}")
        print(f"  Supported: {', '.join(supported_methods) or 'none'}")
        if risky_found:
            print(f"  Risky methods: {', '.join(r['method'] for r in risky_found)}")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
