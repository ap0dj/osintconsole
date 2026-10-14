import re as _re
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


def _looks_like_env_file(body_text):
    """True when the body reads like a dotenv file (>=2 KEY=VALUE lines, >=30% density)."""
    lines = [l for l in body_text.splitlines()
             if l.strip() and not l.strip().startswith('#')]
    if len(lines) < 2:
        return False
    envish = sum(1 for l in lines
                 if _re.match(r'^[A-Z_][A-Z0-9_]{2,}\s*=\s*\S', l))
    return envish >= 2 and envish / max(len(lines), 1) >= 0.3


# path -> (severity, validation marker in body or None for any-200)
SENSITIVE_FILES = {
    ".git/config": ("critical", "[core]"),
    ".git/HEAD": ("critical", "ref:"),
    ".svn/entries": ("high", None),
    ".hg/requires": ("high", None),
    ".env": ("critical", "="),
    ".env.local": ("critical", "="),
    ".env.production": ("critical", "="),
    ".env.backup": ("critical", "="),
    "wp-config.php.bak": ("critical", None),
    "wp-config.php~": ("critical", None),
    "config.php.bak": ("critical", None),
    "configuration.php.bak": ("critical", None),
    "web.config.bak": ("high", None),
    "web.config.old": ("high", None),
    "backup.zip": ("high", None),
    "backup.tar.gz": ("high", None),
    "backup.sql": ("critical", None),
    "db.sql": ("critical", None),
    "dump.sql": ("critical", None),
    "database.sql": ("critical", None),
    "site.zip": ("high", None),
    "www.zip": ("high", None),
    ".DS_Store": ("medium", None),
    "Thumbs.db": ("low", None),
    "index.php.bak": ("medium", None),
    "index.php~": ("medium", None),
    "index.php.old": ("medium", None),
    "index.php.save": ("medium", None),
    ".htaccess": ("medium", None),
    ".htpasswd": ("critical", None),
    "composer.json": ("low", "require"),
    "package.json": ("low", None),
    ".npmrc": ("medium", None),
    "Dockerfile": ("low", "FROM"),
    "docker-compose.yml": ("medium", None),
    "phpinfo.php": ("high", "phpinfo"),
    "info.php": ("high", "phpinfo"),
    "server-status": ("medium", "Apache Server Status"),
    "server-info": ("medium", "Apache Server Information"),
    ".vscode/settings.json": ("low", None),
    ".idea/workspace.xml": ("low", None),
    "id_rsa": ("critical", "PRIVATE KEY"),
    ".aws/credentials": ("critical", None),
    "credentials": ("high", None),
}


class BackupFinder(FetchErrorsMixin, BaseModule):
    name = "web/backup_finder"
    description = "Find exposed backup/config/VCS files (.git, .env, *.sql, *.bak) + dir listing"
    category = "web"
    target_type = "domain/url"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("THREADS", "15", False, "Concurrent requests")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    @staticmethod
    def _markerless_is_real(path, body, raw, ctype):
        """Positive-evidence check for files that have no body marker.

        A bare "HTTP 200" is not enough: a soft-404 / catch-all / login page
        returns 200 for everything, which used to flag .htpasswd, credentials,
        backup.zip, *.sql etc. as critical exposures. Demand that the body
        actually looks like the file we asked for.
        """
        if not raw:
            return False  # empty body = nothing exposed
        head = (body[:400].lower() if body else "")
        # Reject HTML whether declared via Content-Type or sniffed from the body
        # (SPA shells / error pages / login forms are the #1 false positive).
        if "text/html" in ctype:
            return False
        if any(tag in head for tag in ("<html", "<!doctype", "<head", "<body", "<title")):
            return False
        p = path.lower()
        # Archives / DB dumps: require the real magic/signature.
        if p.endswith(".zip"):
            return raw[:2] == b"PK"
        if p.endswith((".gz", ".tgz", ".tar.gz")):
            return raw[:2] == b"\x1f\x8b"
        if p.endswith(".sql"):
            low = body.lower()
            return any(tok in low for tok in ("create table", "insert into",
                                              "drop table", "alter table",
                                              "-- mysql dump",
                                              "-- postgresql database dump"))
        if p.endswith(".ds_store"):
            return raw[:8] == b"\x00\x00\x00\x01Bud1"
        if p == "thumbs.db":
            return raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        if p.endswith(".htpasswd"):
            return bool(_re.search(r"^[^:\s]+:\S+", body, _re.M))
        if p.endswith("credentials"):  # covers credentials and .aws/credentials
            low = body.lower()
            return any(k in low for k in ("aws_access_key_id", "password",
                                          "secret", "token", "[default]"))
        # Remaining text configs (.svn/entries, .hg/requires, *.bak/.old,
        # .htaccess, .npmrc, docker-compose.yml, index.php.*): a non-empty,
        # non-HTML body is acceptable evidence.
        return True

    def _check(self, base, path, marker):
        url = f"{base}/{path}"
        try:
            resp = http.get(url, verify=self._verify_tls, allow_redirects=False, timeout=10)
        except Exception as exc:
            # A connection failure is NOT "file absent" - surface it so a down
            # host cannot read as "0 exposed files / clean".
            return {"status": "error", "path": path, "error": str(exc)}
        if resp.status_code != 200:
            return {"status": "absent", "path": path}
        body = resp.text or ""
        raw = resp.content or b""
        ctype = resp.headers.get("Content-Type", "").lower()
        # .env* files: require real dotenv-style content and non-HTML Content-Type
        if path.startswith(".env"):
            if "text/html" in ctype or not _looks_like_env_file(body):
                return {"status": "absent", "path": path}
            return {"status": "found", "url": url, "size": len(raw),
                    "content_type": ctype}
        if marker is not None:
            # Require the validation marker in the body (rejects soft-404s).
            if marker not in body:
                return {"status": "absent", "path": path}
            return {"status": "found", "url": url, "size": len(raw),
                    "content_type": ctype}
        # marker is None: demand positive evidence this is the real file.
        if not self._markerless_is_real(path, body, raw, ctype):
            return {"status": "absent", "path": path}
        return {"status": "found", "url": url, "size": len(raw),
                "content_type": ctype}

    def _check_dir_listing(self, base):
        listings = []
        for d in ("", "backup", "backups", "uploads", "files", "admin", "images",
                  "assets", "old", "tmp", "temp", "data"):
            url = f"{base}/{d}" if d else base
            try:
                resp = http.get(url + "/", verify=self._verify_tls, allow_redirects=False, timeout=10)
                body = resp.text or ""
                if resp.status_code == 200 and ("Index of /" in body
                                                or "<title>Directory listing for" in body):
                    listings.append(url)
                    print_status(f"[DIR LISTING] {url}/", "warning")
            except Exception:
                pass
        return listings

    def run(self):
        if not self.validate():
            return False

        base = normalize_url(self.get_option("TARGET"))
        threads = max(1, int(self.get_option("THREADS") or 15))
        self._verify_tls = self.get_option("VERIFY_TLS").lower() != "false"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Backup / Sensitive File Finder: {base}")
        print(f"  Probing {len(SENSITIVE_FILES)} paths")
        print(f"{'='*58}{Colors.RESET}\n")

        self._errors = []
        found = []
        errors = []
        responded = 0
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._check, base, path, marker): (path, sev)
                       for path, (sev, marker) in SENSITIVE_FILES.items()}
            for future in as_completed(futures):
                path, sev = futures[future]
                result = future.result()
                status = result.get("status")
                if status == "error":
                    errors.append(result)
                    continue
                responded += 1
                if status == "found":
                    result["path"] = path
                    result["severity"] = sev
                    found.append(result)
                    color = {"critical": Colors.RED, "high": Colors.YELLOW,
                             "medium": Colors.MAGENTA}.get(sev, Colors.DIM)
                    print(f" {color}[{sev.upper()}]{Colors.RESET} {result['url']} "
                          f"({result['size']} bytes)")

        for e in errors[:20]:
            self._note_error(f"{e['path']}: {e.get('error') or 'request failed'}")

        # Host unreachable: every probe errored. This is a FAILED scan, not a
        # clean "no exposed files" result.
        if SENSITIVE_FILES and responded == 0:
            self.results = {"target": base}
            self._fail()
            print(f"\n{Colors.BOLD}{Colors.RED}{'='*58}")
            print(f"  Scan FAILED - {base}: all {len(SENSITIVE_FILES)} probe(s) "
                  f"errored (host unreachable). Status UNKNOWN, not 'clean'.")
            print(f"{'='*58}{Colors.RESET}\n")
            return False

        print_status("Checking for directory listings...", "info")
        listings = self._check_dir_listing(base)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        found.sort(key=lambda x: severity_order.get(x["severity"], 9))

        self.results = {
            "target": base,
            "files_found": found,
            "files_count": len(found),
            "critical_count": len([f for f in found if f["severity"] == "critical"]),
            "directory_listings": listings,
            "connect_errors": len(errors),
            "fetch_errors": list(self._errors),
        }

        crit = self.results["critical_count"]
        color = Colors.RED if crit else (Colors.YELLOW if found else Colors.GREEN)
        print(f"\n{Colors.BOLD}{color}{'='*58}")
        err_suffix = f", {len(errors)} unreachable" if errors else ""
        print(f"  {len(found)} exposed file(s), {crit} critical, "
              f"{len(listings)} open director(ies){err_suffix}")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
