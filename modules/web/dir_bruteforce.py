import concurrent.futures
import random
import string
from core.base_module import BaseModule
from core.utils import print_status
from core import http

DEFAULT_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "panel", "dashboard", "cpanel", "phpmyadmin", "adminer",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui",
    "docs", "api-docs", "redoc",
    ".git", ".git/HEAD", ".git/config", ".svn", ".svn/entries",
    ".env", ".env.local", ".env.production", ".env.backup",
    "config.php", "config.yml", "config.json", "configuration.php",
    "wp-config.php", "web.config", "database.yml",
    "backup", "backups", "bak", "old", "temp", "tmp", "test",
    "debug", "trace", "info.php", "phpinfo.php", "server-status",
    "server-info", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "security.txt", ".well-known/security.txt",
    "humans.txt", "readme.html", "readme.txt", "README.md",
    "CHANGELOG.md", "LICENSE", "package.json", "composer.json",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    "Makefile", "Gruntfile.js", "Gulpfile.js", "webpack.config.js",
    "upload", "uploads", "files", "media", "images", "assets",
    "static", "public", "private", "internal", "secret",
    "cgi-bin", "scripts", "includes", "vendor", "node_modules",
    "console", "shell", "cmd", "terminal", "webshell",
    "manager", "manage", "management", "monitor", "monitoring",
    "status", "health", "healthcheck", "ping", "version",
    "register", "signup", "signin", "auth", "oauth", "sso",
    "forgot", "reset", "password", "account", "profile", "user",
    "users", "members", "customer", "clients",
    "download", "downloads", "export", "import", "report", "reports",
    "log", "logs", "error_log", "access_log", "debug.log",
    "blog", "news", "forum", "wiki", "help", "support", "faq",
    "search", "sitemap", "feed", "rss", "atom",
    "install", "setup", "update", "upgrade", "maintenance",
    "db", "database", "sql", "mysql", "pgsql", "redis",
    "cache", "session", "sessions", "cookies",
    "xmlrpc.php", "wp-cron.php", "cron", "cron.php",
    "proxy", "gateway", "socket", "websocket", "ws",
    "metrics", "prometheus", "grafana", "kibana", "elasticsearch",
]


class DirBruteforce(BaseModule):
    name = "web/dir_bruteforce"
    description = "Directory and file brute-force discovery with status code analysis"
    category = "web"
    target_type = "domain/url"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("WORDLIST", "", False, "Custom wordlist path (uses built-in if empty)")
        self.add_option("THREADS", "20", False, "Number of threads")
        self.add_option("EXTENSIONS", "", False, "File extensions to append (e.g., php,html,txt)")
        self.add_option("STATUS_CODES", "200,201,301,302,401,403,405,500", False, "Status codes to report")
        self.add_option("TIMEOUT", "5", False, "Request timeout in seconds")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    def _check_path(self, base_url, path, timeout):
        url = f"{base_url}/{path}"
        try:
            resp = http.get(url, timeout=timeout, verify=self._verify_tls, allow_redirects=False)
            return path, resp.status_code, len(resp.content), resp.headers.get("Location", "")
        except Exception:
            # None status = connection error (distinct from any real HTTP code),
            # so a down host is surfaced instead of silently dropped.
            return path, None, 0, ""

    def _wildcard_baseline(self, target, timeout):
        """Probe random non-existent paths to detect a catch-all 200 host.

        Returns (is_wildcard, baseline_sizes). If random junk paths return 200,
        the server answers 200 for everything and a plain status match would
        flag all ~150 wordlist paths as 'found'.
        """
        sizes = set()
        wildcard = False
        for _ in range(3):
            rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
            _p, status, size, _r = self._check_path(target, f"{rnd}_zzz404", timeout)
            if status == 200:
                wildcard = True
                sizes.add(size)
        return wildcard, sizes

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        target = target.rstrip("/")

        threads = max(1, int(self.get_option("THREADS") or 20))
        timeout = float(self.get_option("TIMEOUT") or 5)
        self._verify_tls = self.get_option("VERIFY_TLS").lower() != "false"
        extensions = [e.strip() for e in (self.get_option("EXTENSIONS") or "").split(",") if e.strip()]
        valid_codes = []
        for c in self.get_option("STATUS_CODES").split(","):
            c = c.strip()
            if c.isdigit():
                valid_codes.append(int(c))
        if not valid_codes:
            valid_codes = [200, 201, 301, 302, 401, 403, 405, 500]

        wordlist_path = self.get_option("WORDLIST")
        if wordlist_path and __import__("os").path.exists(wordlist_path):
            with open(wordlist_path, "r") as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            paths = list(DEFAULT_DIRS)

        all_paths = list(paths)
        for ext in extensions:
            for p in paths:
                if "." not in p:
                    all_paths.append(f"{p}.{ext}")

        # Catch-all / soft-200 detection: probe random non-existent paths first.
        wildcard, wildcard_sizes = self._wildcard_baseline(target, timeout)
        if wildcard:
            print_status("Catch-all 200 detected (server answers 200 for random "
                         "paths) - 200s matching the wildcard body are suppressed "
                         "to avoid flagging every path", "warning")

        def _is_wildcard_200(status, size):
            if not wildcard or status != 200:
                return False
            # Treat a 200 whose body size matches the wildcard baseline as noise.
            return any(abs(size - bs) <= max(64, int(bs * 0.05))
                       for bs in wildcard_sizes)

        print_status(f"Brute-forcing {len(all_paths)} paths on {target} with {threads} threads", "info")

        found = []
        interesting = []
        errors = 0
        responded = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._check_path, target, p, timeout): p
                       for p in all_paths}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                path, status, size, redirect = future.result()
                done += 1
                if done % 50 == 0:
                    print_status(f"Progress: {done}/{len(all_paths)}", "info")

                if status is None:
                    errors += 1
                    continue
                responded += 1

                if status in valid_codes and not _is_wildcard_200(status, size):
                    entry = {
                        "path": f"/{path}",
                        "status": status,
                        "size": size,
                        "redirect": redirect,
                        "url": f"{target}/{path}",
                    }
                    found.append(entry)

                    color_map = {200: "success", 301: "info", 302: "info",
                                 401: "warning", 403: "warning", 500: "error"}
                    level = color_map.get(status, "info")
                    extra = f" -> {redirect}" if redirect else f" ({size} bytes)"
                    print_status(f"[{status}] /{path}{extra}", level)

                    sensitive = [".git", ".env", ".svn", "config", "backup",
                                 "phpinfo", "server-status", "debug", ".htpasswd"]
                    if any(s in path.lower() for s in sensitive):
                        interesting.append(entry)

        # Host unreachable: nothing responded. Not a clean "0 found" result.
        if all_paths and responded == 0:
            self.results = {
                "target": target,
                "paths_tested": len(all_paths),
                "found": [],
                "interesting": [],
                "total_found": 0,
                "connect_errors": errors,
                "error": "fetch_failed",
            }
            print_status(f"Brute-force FAILED - all {len(all_paths)} request(s) "
                         f"errored (host unreachable). Result is UNKNOWN, not "
                         f"'0 found'.", "error")
            return False

        found.sort(key=lambda x: x["status"])

        self.results = {
            "target": target,
            "paths_tested": len(all_paths),
            "found": found,
            "interesting": interesting,
            "total_found": len(found),
            "connect_errors": errors,
            "wildcard_200": wildcard,
        }

        suffix = f", {errors} connection error(s)" if errors else ""
        print_status(f"Brute-force complete. {len(found)} paths found, "
                     f"{len(interesting)} potentially interesting{suffix}", "info")
        return True
