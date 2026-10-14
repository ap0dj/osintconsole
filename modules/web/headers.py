import requests
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

INFO_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
    "X-Cache", "CF-RAY", "X-Amz-Cf-Id",
]


class HeadersAnalysis(BaseModule):
    name = "web/headers"
    description = "HTTP headers analysis - security headers, server info, cookies"
    category = "web"
    target_type = "domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("FOLLOW_REDIRECTS", "true", False, "Follow HTTP redirects")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        config = Config()
        follow = self.get_option("FOLLOW_REDIRECTS").lower() == "true"
        verify_tls = self.get_option("VERIFY_TLS").lower() != "false"

        print_status(f"Analyzing HTTP headers for {target}", "info")

        try:
            resp = requests.get(
                target,
                timeout=config.get("timeout", 10),
                headers={"User-Agent": config.get("user_agent")},
                allow_redirects=follow,
                verify=verify_tls,
            )

            headers = dict(resp.headers)
            security = {}
            for h in SECURITY_HEADERS:
                val = resp.headers.get(h)
                if val:
                    security[h] = val
                    print_status(f"[PRESENT] {h}: {val}", "success")
                else:
                    security[h] = "MISSING"
                    print_status(f"[MISSING] {h}", "warning")

            info_leak = {}
            for h in INFO_HEADERS:
                val = resp.headers.get(h)
                if val:
                    info_leak[h] = val
                    print_status(f"[INFO LEAK] {h}: {val}", "warning")

            cookies_info = []
            for cookie in resp.cookies:
                c = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": any(k.lower() == "httponly" for k in getattr(cookie, "_rest", {})),
                    "domain": cookie.domain,
                    "path": cookie.path,
                }
                cookies_info.append(c)

            self.results = {
                "target": target,
                "status_code": resp.status_code,
                "all_headers": headers,
                "security_headers": security,
                "info_leakage": info_leak,
                "cookies": cookies_info,
                "missing_security_headers": [h for h, v in security.items() if v == "MISSING"],
            }

            missing = len([v for v in security.values() if v == "MISSING"])
            print_status(f"Analysis complete. {missing}/{len(SECURITY_HEADERS)} security headers missing", "info")
            return True

        except Exception as e:
            print_status(f"Header analysis failed: {e}", "error")
            return False
