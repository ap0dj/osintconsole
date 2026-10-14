from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core import http


COMMON_PARAMS = [
    "id", "page", "p", "q", "query", "search", "s", "keyword", "lang", "locale",
    "file", "filename", "path", "dir", "folder", "url", "uri", "link", "redirect",
    "redirect_url", "return", "returnurl", "return_url", "next", "continue", "dest",
    "destination", "callback", "jsonp", "format", "type", "view", "action", "do",
    "cmd", "exec", "command", "func", "function", "method", "op", "option", "mode",
    "debug", "test", "admin", "user", "username", "uid", "userid", "account",
    "email", "password", "pass", "pwd", "token", "key", "api_key", "apikey",
    "access_token", "auth", "session", "sid", "sort", "order", "orderby", "filter",
    "category", "cat", "tag", "item", "product", "pid", "ref", "source", "utm_source",
    "limit", "offset", "start", "end", "from", "to", "date", "year", "month", "day",
    "name", "title", "content", "body", "message", "msg", "text", "data", "value",
    "include", "template", "theme", "style", "css", "js", "img", "image", "doc",
]

CANARY = "cnryv9x7"


class ParamFinder(BaseModule):
    name = "web/param_finder"
    description = "Discover hidden GET parameters via reflection (canary-based, chunked)"
    category = "web"
    target_type = "url"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL")
        self.add_option("CHUNK_SIZE", "20", False, "Params per request")
        self.add_option("EXTRA_PARAMS", "", False, "Extra param names to test (comma-separated)")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    def _baseline(self, url):
        try:
            resp = http.get(url, verify=self._verify_tls, allow_redirects=True, timeout=10)
            return resp.status_code, len(resp.content)
        except Exception:
            return None, None

    def run(self):
        if not self.validate():
            return False

        url = normalize_url(self.get_option("TARGET"))
        chunk_size = max(1, int(self.get_option("CHUNK_SIZE") or 20))
        extra = [p.strip() for p in self.get_option("EXTRA_PARAMS").split(",") if p.strip()]
        params = list(dict.fromkeys(COMMON_PARAMS + extra))
        self._verify_tls = self.get_option("VERIFY_TLS").lower() != "false"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Parameter Finder: {url}")
        print(f"  Testing {len(params)} candidate parameters")
        print(f"{'='*58}{Colors.RESET}\n")

        base_status, base_len = self._baseline(url)
        print_status(f"Baseline: status={base_status} len={base_len}", "info")

        sep = "&" if "?" in url else "?"
        reflected = []
        length_changing = []

        for i in range(0, len(params), chunk_size):
            chunk = params[i:i + chunk_size]
            # unique canary per param so we know which reflected
            query = "&".join(f"{p}={p}{CANARY}" for p in chunk)
            test_url = f"{url}{sep}{query}"
            try:
                resp = http.get(test_url, verify=self._verify_tls, allow_redirects=True, timeout=12)
                body = resp.text or ""
                for p in chunk:
                    token = f"{p}{CANARY}"
                    if token in body:
                        reflected.append(p)
                        print_status(f"[REFLECTED] {p}", "success")
                if (base_len is not None
                        and abs(len(resp.content) - base_len) > 300):
                    length_changing.append({"chunk_start": i,
                                            "params": chunk,
                                            "new_len": len(resp.content)})
            except Exception:
                pass

        self.results = {
            "target": url,
            "baseline": {"status": base_status, "length": base_len},
            "params_tested": len(params),
            "reflected_params": reflected,
            "reflected_count": len(reflected),
            "length_changing_chunks": length_changing,
        }

        color = Colors.YELLOW if reflected else Colors.GREEN
        print(f"\n{Colors.BOLD}{color}{'='*58}")
        print(f"  {len(reflected)} reflected parameter(s) found")
        if reflected:
            print(f"  -> {', '.join(reflected)}")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
