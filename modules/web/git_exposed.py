"""VCS + backup + config leak detector.

Expanded from the original /.git prober into a broad "exposed-files" scanner
that probes a target web root for leaked version-control metadata, editor /
IDE files, OS droppings, backup copies, database dumps, framework configs,
log files and plaintext secrets.

Each probe is paired with a content signature so a 200 with the right status
code but the wrong body (custom 200 error page, SPA shell, WAF challenge) is
filtered out. The classic deep /.git analysis (remote URL, author emails,
commit log) is preserved as a sub-phase whenever any .git/ artefact is found.
"""
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


# ---------------------------------------------------------------------------
# Content signature functions
# ---------------------------------------------------------------------------
# Each takes (raw_bytes, text_lowered_or_none) and returns True if the body
# looks like the expected file-type (so we trust the 200), False otherwise.
# `text` may be None if the body wasn't decodable as text (binary file).

def _sig_git_head(b, t):
    s = (t or "").strip()
    return s.startswith("ref: refs/") or bool(re.match(r"^[0-9a-f]{40}$", s))


def _sig_git_config(b, t):
    return bool(t) and ("[core]" in t or "[remote" in t or "[branch" in t)


def _sig_git_index(b, t):
    return bool(b) and b[:4] == b"DIRC"


def _sig_git_packed_refs(b, t):
    return bool(t) and ("# pack-refs" in t or bool(re.search(r"[0-9a-f]{40}\s+refs/", t)))


def _sig_git_logs(b, t):
    return bool(t) and bool(re.search(r"[0-9a-f]{40}\s+[0-9a-f]{40}\s+", t))


def _sig_svn_entries(b, t):
    if not t:
        return False
    first = t.strip().splitlines()[0:1]
    return bool(first) and (first[0].strip().isdigit() or "svn:" in t[:200])


def _sig_sqlite(b, t):
    return bool(b) and b[:16].startswith(b"SQLite format 3")


def _sig_svn_format(b, t):
    return bool(t) and t.strip().isdigit()


def _sig_hg_binary(b, t):
    # mercurial revlog / dirstate — just reject obvious HTML
    if not b:
        return False
    head = b[:200].lower()
    return b"<html" not in head and b"<!doctype" not in head


def _sig_hgrc(b, t):
    return bool(t) and bool(re.search(r"^\s*\[[a-z_]+\]", t, re.M))


def _sig_bzr(b, t):
    return bool(t) and "bazaar" in (t or "").lower()


def _sig_cvs_entries(b, t):
    return bool(t) and any(line.startswith("/") or line.startswith("D/")
                           for line in t.splitlines())


def _sig_cvs_root(b, t):
    return bool(t) and (":pserver:" in t or ":ext:" in t or ":local:" in t or "/" in t)


def _sig_darcs(b, t):
    return bool(t) and ("darcs" in t.lower() or "hashed" in t.lower())


def _sig_json(b, t):
    if not t:
        return False
    s = t.strip()
    if not (s.startswith("{") or s.startswith("[")):
        return False
    try:
        json.loads(s)
        return True
    except Exception:
        return False


def _sig_sftp_json(b, t):
    if not _sig_json(b, t):
        return False
    low = t.lower()
    return any(k in low for k in ('"host"', '"username"', '"password"',
                                   '"privatekeypath"', '"remotepath"'))


def _sig_vscode_launch(b, t):
    return _sig_json(b, t) and "configurations" in (t or "").lower()


def _sig_xml(b, t):
    return bool(t) and ("<?xml" in t[:200] or "<project" in t.lower()
                        or "<component" in t.lower())


def _sig_idea_datasources(b, t):
    return _sig_xml(b, t) and "datasource" in (t or "").lower()


def _sig_eclipse_project(b, t):
    return _sig_xml(b, t) and "<projectdescription" in (t or "").lower()


def _sig_eclipse_classpath(b, t):
    return _sig_xml(b, t) and "<classpath" in (t or "").lower()


def _sig_sublime(b, t):
    return _sig_json(b, t) and ("folders" in (t or "").lower()
                                 or "settings" in (t or "").lower())


def _sig_dsstore(b, t):
    return bool(b) and len(b) >= 8 and b[:8] == b"\x00\x00\x00\x01Bud1"


def _sig_thumbsdb(b, t):
    # OLE compound document magic
    return bool(b) and b[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _sig_desktop_ini(b, t):
    return bool(t) and ("[.shellclassinfo]" in (t or "").lower()
                        or "[viewstate]" in (t or "").lower())


def _sig_env(b, t):
    if not t:
        return False
    if "<html" in t[:200].lower() or "<!doctype" in t[:200].lower():
        return False
    # Needs at least one KEY=VALUE line
    for line in t.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^[A-Z0-9_]+\s*=\s*\S", line):
            return True
    return False


def _sig_yaml(b, t):
    if not t:
        return False
    if "<html" in t[:200].lower():
        return False
    return bool(re.search(r"^[A-Za-z0-9_\-]+\s*:\s*", t, re.M))


def _sig_php_backup(b, t):
    return bool(t) and ("<?php" in t or "define(" in t or "DB_PASSWORD" in t)


def _sig_sql_dump(b, t):
    if not t:
        return False
    low = t.lower()
    return any(tok in low for tok in ("create table", "insert into",
                                       "drop table", "-- mysql dump",
                                       "-- postgresql database dump"))


def _sig_gzip(b, t):
    return bool(b) and b[:2] == b"\x1f\x8b"


def _sig_zip(b, t):
    return bool(b) and b[:2] == b"PK"


def _sig_webconfig(b, t):
    return _sig_xml(b, t) and ("<configuration" in (t or "").lower()
                                or "<system.web" in (t or "").lower())


def _sig_aws_creds(b, t):
    return bool(t) and bool(re.search(r"\[.+\].*aws_access_key_id",
                                       t, re.I | re.S))


def _sig_aws_config(b, t):
    return bool(t) and bool(re.search(r"\[(default|profile\s)", t))


def _sig_ini_section(b, t):
    return bool(t) and bool(re.search(r"^\s*\[[^\]]+\]", t, re.M))


def _sig_npmrc(b, t):
    return bool(t) and bool(re.search(r"(_authToken|registry\s*=|//.+/:_)", t))


def _sig_credentials_text(b, t):
    if not t:
        return False
    # A rendered HTML page (login form, SPA shell, error page) routinely
    # contains the word "password"/"token"; it is NOT a leaked creds file.
    if "<html" in t[:200].lower() or "<!doctype" in t[:200].lower():
        return False
    low = t.lower()
    return any(k in low for k in ("password", "passwd", "secret", "token",
                                   "api_key", "apikey", "aws_access"))


def _sig_laravel_log(b, t):
    return bool(t) and bool(re.search(r"^\[\d{4}-\d{2}-\d{2}", t, re.M))


def _sig_django_settings(b, t):
    return bool(t) and ("SECRET_KEY" in t or "INSTALLED_APPS" in t
                        or "DATABASES" in t)


def _sig_wpconfig(b, t):
    return bool(t) and ("DB_PASSWORD" in t or "AUTH_KEY" in t
                        or "<?php" in t and "wp-" in t.lower())


def _sig_wp_debug_log(b, t):
    if not t:
        return False
    # Reject HTML: a plain "[" bracket matched almost any page before.
    if "<html" in t[:200].lower() or "<!doctype" in t[:200].lower():
        return False
    return (bool(re.search(r"\[\d{2}-[A-Za-z]{3}-\d{4}[ :]", t))
            or "PHP Stack trace" in t or "PHP Warning" in t
            or "PHP Notice" in t or "PHP Fatal" in t
            or "PHP Deprecated" in t)


def _sig_properties(b, t):
    if not t:
        return False
    if "<html" in t[:200].lower():
        return False
    return bool(re.search(r"^[A-Za-z0-9._\-]+\s*=\s*\S", t, re.M))


def _sig_log_generic(b, t):
    if not t:
        return False
    if "<html" in t[:200].lower() or "<!doctype" in t[:200].lower():
        return False
    # typical log timestamp or apache combined log heuristic
    return bool(re.search(r"\d{4}-\d{2}-\d{2}|\d{2}/[A-Z][a-z]{2}/\d{4}", t))


# ---------------------------------------------------------------------------
# Path catalog
# ---------------------------------------------------------------------------
# severity: critical | high | medium | low
# category: vcs | ide | os | backup | config | log | dump | framework

_BACKUP_SUFFIXES = [".bak", ".backup", ".old", ".orig", ".save", ".swp",
                    ".swo", ".tmp", "~", ".old.bak", ".copy", ".1", ".2"]
_BACKUP_SEEDS = ["index.php", "config.php", "database.php",
                 "wp-config.php", ".env"]


def _build_backup_paths():
    out = []
    for seed in _BACKUP_SEEDS:
        for suf in _BACKUP_SUFFIXES:
            # ~ attaches without a dot
            if suf == "~":
                p = f"/{seed}~"
            else:
                p = f"/{seed}{suf}"
            # Pick signature based on what the ORIGINAL file is
            if seed.endswith(".php"):
                sig = _sig_php_backup
            else:
                sig = _sig_env
            out.append({"path": p, "category": "backup", "severity": "high",
                        "signature": sig})
        # explicit _old.php / _backup.php style
        if seed.endswith(".php"):
            stem = seed[:-4]
            for extra in (f"{stem}_old.php", f"{stem}_backup.php"):
                out.append({"path": f"/{extra}", "category": "backup",
                            "severity": "high", "signature": _sig_php_backup})
    return out


_VCS_PATHS = [
    # Git — these feed the deep-analysis sub-phase
    {"path": "/.git/HEAD",         "category": "vcs", "severity": "critical", "signature": _sig_git_head},
    {"path": "/.git/config",       "category": "vcs", "severity": "critical", "signature": _sig_git_config},
    {"path": "/.git/index",        "category": "vcs", "severity": "critical", "signature": _sig_git_index},
    {"path": "/.git/packed-refs",  "category": "vcs", "severity": "critical", "signature": _sig_git_packed_refs},
    {"path": "/.git/logs/HEAD",    "category": "vcs", "severity": "critical", "signature": _sig_git_logs},

    # Subversion
    {"path": "/.svn/entries",      "category": "vcs", "severity": "critical", "signature": _sig_svn_entries},
    {"path": "/.svn/wc.db",        "category": "vcs", "severity": "critical", "signature": _sig_sqlite},
    {"path": "/.svn/format",       "category": "vcs", "severity": "high",     "signature": _sig_svn_format},

    # Mercurial
    {"path": "/.hg/00manifest.i",  "category": "vcs", "severity": "critical", "signature": _sig_hg_binary},
    {"path": "/.hg/dirstate",      "category": "vcs", "severity": "critical", "signature": _sig_hg_binary},
    {"path": "/.hg/hgrc",          "category": "vcs", "severity": "high",     "signature": _sig_hgrc},

    # Bazaar
    {"path": "/.bzr/branch-format", "category": "vcs", "severity": "high",    "signature": _sig_bzr},
    {"path": "/.bzr/README",       "category": "vcs", "severity": "medium",   "signature": _sig_bzr},

    # CVS
    {"path": "/CVS/Entries",       "category": "vcs", "severity": "high",     "signature": _sig_cvs_entries},
    {"path": "/CVS/Root",          "category": "vcs", "severity": "high",     "signature": _sig_cvs_root},

    # Darcs
    {"path": "/_darcs/format",     "category": "vcs", "severity": "high",     "signature": _sig_darcs},
]

_IDE_PATHS = [
    {"path": "/.vscode/settings.json", "category": "ide", "severity": "medium",   "signature": _sig_json},
    {"path": "/.vscode/launch.json",   "category": "ide", "severity": "medium",   "signature": _sig_vscode_launch},
    {"path": "/.vscode/tasks.json",    "category": "ide", "severity": "medium",   "signature": _sig_json},
    {"path": "/.vscode/sftp.json",     "category": "ide", "severity": "critical", "signature": _sig_sftp_json},

    {"path": "/.idea/workspace.xml",   "category": "ide", "severity": "high",     "signature": _sig_xml},
    {"path": "/.idea/dataSources.xml", "category": "ide", "severity": "critical", "signature": _sig_idea_datasources},
    {"path": "/.idea/webServers.xml",  "category": "ide", "severity": "high",     "signature": _sig_xml},

    {"path": "/.project",              "category": "ide", "severity": "medium",   "signature": _sig_eclipse_project},
    {"path": "/.classpath",            "category": "ide", "severity": "medium",   "signature": _sig_eclipse_classpath},
    {"path": "/.settings/org.eclipse.core.resources.prefs", "category": "ide", "severity": "low", "signature": _sig_properties},

    {"path": "/.sublime-project",      "category": "ide", "severity": "low",      "signature": _sig_sublime},
    {"path": "/.sublime-workspace",    "category": "ide", "severity": "low",      "signature": _sig_sublime},

    {"path": "/.vs/config/applicationhost.config", "category": "ide", "severity": "medium", "signature": _sig_xml},
    {"path": "/.vs/ProjectSettings.json",          "category": "ide", "severity": "low",    "signature": _sig_json},
]

_OS_PATHS = [
    {"path": "/.DS_Store",   "category": "os", "severity": "medium", "signature": _sig_dsstore},
    {"path": "/Thumbs.db",   "category": "os", "severity": "low",    "signature": _sig_thumbsdb},
    {"path": "/desktop.ini", "category": "os", "severity": "low",    "signature": _sig_desktop_ini},
    # Resource-fork wildcards aren't probable blindly, but a handful of
    # common names are worth a punt.
    {"path": "/._.DS_Store", "category": "os", "severity": "low",    "signature": _sig_dsstore},
    {"path": "/._index.html","category": "os", "severity": "low",    "signature": _sig_dsstore},
]

_CONFIG_PATHS = [
    # Dotenv family
    {"path": "/.env",                "category": "config", "severity": "critical", "signature": _sig_env},
    {"path": "/.env.local",          "category": "config", "severity": "critical", "signature": _sig_env},
    {"path": "/.env.production",     "category": "config", "severity": "critical", "signature": _sig_env},
    {"path": "/.env.staging",        "category": "config", "severity": "critical", "signature": _sig_env},
    {"path": "/.env.development",    "category": "config", "severity": "critical", "signature": _sig_env},
    {"path": "/.env.backup",         "category": "config", "severity": "critical", "signature": _sig_env},

    # Generic config files
    {"path": "/config.yaml",         "category": "config", "severity": "high",     "signature": _sig_yaml},
    {"path": "/config.yml",          "category": "config", "severity": "high",     "signature": _sig_yaml},
    {"path": "/config.json",         "category": "config", "severity": "high",     "signature": _sig_json},
    {"path": "/settings.yaml",       "category": "config", "severity": "high",     "signature": _sig_yaml},
    {"path": "/settings.yml",        "category": "config", "severity": "high",     "signature": _sig_yaml},

    # ASP.NET
    {"path": "/web.config",          "category": "config", "severity": "high",     "signature": _sig_webconfig},
    {"path": "/web.config.bak",      "category": "config", "severity": "critical", "signature": _sig_webconfig},
    {"path": "/appsettings.json",    "category": "config", "severity": "critical", "signature": _sig_json},
    {"path": "/appsettings.Development.json", "category": "config", "severity": "critical", "signature": _sig_json},

    # Secrets
    {"path": "/secrets.yaml",        "category": "config", "severity": "critical", "signature": _sig_yaml},
    {"path": "/secrets.yml",         "category": "config", "severity": "critical", "signature": _sig_yaml},
    {"path": "/secrets.json",        "category": "config", "severity": "critical", "signature": _sig_json},

    # Cloud / tooling creds
    {"path": "/.aws/credentials",    "category": "config", "severity": "critical", "signature": _sig_aws_creds},
    {"path": "/.aws/config",         "category": "config", "severity": "high",     "signature": _sig_aws_config},
    {"path": "/.docker/config.json", "category": "config", "severity": "high",     "signature": _sig_json},
    {"path": "/.npmrc",              "category": "config", "severity": "high",     "signature": _sig_npmrc},
    {"path": "/.pypirc",             "category": "config", "severity": "high",     "signature": _sig_ini_section},
    {"path": "/.gitconfig",          "category": "config", "severity": "medium",   "signature": _sig_ini_section},

    # Catch-alls
    {"path": "/credentials.json",    "category": "config", "severity": "critical", "signature": _sig_json},
    {"path": "/credentials.txt",     "category": "config", "severity": "critical", "signature": _sig_credentials_text},
]

_FRAMEWORK_PATHS = [
    # Laravel
    {"path": "/storage/logs/laravel.log",   "category": "framework", "severity": "high",     "signature": _sig_laravel_log},

    # Rails
    {"path": "/config/database.yml",        "category": "framework", "severity": "critical", "signature": _sig_yaml},
    {"path": "/config/secrets.yml",         "category": "framework", "severity": "critical", "signature": _sig_yaml},
    {"path": "/config/master.key",          "category": "framework", "severity": "critical", "signature": _sig_credentials_text},

    # Django (rare in prod but worth checking)
    {"path": "/settings.py",                "category": "framework", "severity": "critical", "signature": _sig_django_settings},

    # WordPress backup/debug
    {"path": "/wp-config.php.bak",          "category": "framework", "severity": "critical", "signature": _sig_wpconfig},
    {"path": "/wp-config.php.old",          "category": "framework", "severity": "critical", "signature": _sig_wpconfig},
    {"path": "/wp-config.php.swp",          "category": "framework", "severity": "critical", "signature": _sig_wpconfig},
    {"path": "/wp-config.php~",             "category": "framework", "severity": "critical", "signature": _sig_wpconfig},
    {"path": "/wp-content/debug.log",       "category": "framework", "severity": "high",     "signature": _sig_wp_debug_log},

    # Symfony
    {"path": "/app/config/parameters.yml",  "category": "framework", "severity": "critical", "signature": _sig_yaml},

    # Spring Boot / Java
    {"path": "/application.properties",     "category": "framework", "severity": "critical", "signature": _sig_properties},
    {"path": "/application.yml",            "category": "framework", "severity": "critical", "signature": _sig_yaml},
    {"path": "/application-dev.yml",        "category": "framework", "severity": "critical", "signature": _sig_yaml},
    {"path": "/application-prod.yml",       "category": "framework", "severity": "critical", "signature": _sig_yaml},
]

_LOG_PATHS = [
    {"path": "/debug.log",           "category": "log", "severity": "medium", "signature": _sig_log_generic},
    {"path": "/error.log",           "category": "log", "severity": "medium", "signature": _sig_log_generic},
    {"path": "/access.log",          "category": "log", "severity": "medium", "signature": _sig_log_generic},
    {"path": "/logs/error.log",      "category": "log", "severity": "medium", "signature": _sig_log_generic},
    {"path": "/logs/debug.log",      "category": "log", "severity": "medium", "signature": _sig_log_generic},
    {"path": "/logs/access.log",     "category": "log", "severity": "medium", "signature": _sig_log_generic},
    {"path": "/log/production.log",  "category": "log", "severity": "medium", "signature": _sig_log_generic},
]

_DUMP_PATHS = [
    {"path": "/backup.sql",       "category": "dump", "severity": "critical", "signature": _sig_sql_dump},
    {"path": "/database.sql",     "category": "dump", "severity": "critical", "signature": _sig_sql_dump},
    {"path": "/db.sql",           "category": "dump", "severity": "critical", "signature": _sig_sql_dump},
    {"path": "/dump.sql",         "category": "dump", "severity": "critical", "signature": _sig_sql_dump},
    {"path": "/wordpress.sql",    "category": "dump", "severity": "critical", "signature": _sig_sql_dump},
    {"path": "/wp-db.sql",        "category": "dump", "severity": "critical", "signature": _sig_sql_dump},
    {"path": "/backup.sql.gz",    "category": "dump", "severity": "critical", "signature": _sig_gzip},
    {"path": "/backup.sql.zip",   "category": "dump", "severity": "critical", "signature": _sig_zip},
    {"path": "/database.sql.gz",  "category": "dump", "severity": "critical", "signature": _sig_gzip},
    {"path": "/dump.sql.gz",      "category": "dump", "severity": "critical", "signature": _sig_gzip},
    {"path": "/backup.zip",       "category": "dump", "severity": "high",     "signature": _sig_zip},
    {"path": "/backup.tar.gz",    "category": "dump", "severity": "high",     "signature": _sig_gzip},
    {"path": "/www.zip",          "category": "dump", "severity": "high",     "signature": _sig_zip},
    {"path": "/site.zip",         "category": "dump", "severity": "high",     "signature": _sig_zip},
    {"path": "/public_html.zip",  "category": "dump", "severity": "high",     "signature": _sig_zip},
]


def _all_paths():
    buckets = {
        "vcs":       list(_VCS_PATHS),
        "ide":       list(_IDE_PATHS),
        "os":        list(_OS_PATHS),
        "backup":    _build_backup_paths(),
        "config":    list(_CONFIG_PATHS),
        "framework": list(_FRAMEWORK_PATHS),
        "log":       list(_LOG_PATHS),
        "dump":      list(_DUMP_PATHS),
    }
    return buckets


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class GitExposed(FetchErrorsMixin, BaseModule):
    name = "web/git_exposed"
    description = ("Detect exposed VCS metadata (.git/.svn/.hg/.bzr/CVS/_darcs), "
                   "IDE files, OS droppings, backup copies, DB dumps, framework "
                   "configs, logs and plaintext secrets")
    category = "web"
    target_type = "domain/url"
    intrusive = True

    _VALID_CATEGORIES = {"vcs", "ide", "os", "backup", "config",
                         "framework", "log", "dump"}

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option(
            "CATEGORIES", "all", False,
            "Comma-separated subset: vcs,ide,os,backup,config,framework,log,dump (or 'all')")
        self.add_option(
            "VERIFY_CONTENT", "true", False,
            "Reject 200 responses whose body doesn't match the expected signature")
        self.add_option("THREADS", "20", False, "Parallel worker count")
        self.add_option(
            "VERIFY_TLS", "true", False,
            "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    # -------- fetch ---------------------------------------------------------
    def _fetch(self, url):
        """Return (status, size, raw_bytes, text_or_None) or (None,...) on error."""
        try:
            resp = http.get(url, verify=self._verify_tls, allow_redirects=False,
                            timeout=12)
        except Exception as e:
            return (None, 0, None, None, str(e))
        try:
            raw = resp.content or b""
        except Exception:
            raw = b""
        text = None
        if raw:
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = None
        return (resp.status_code, len(raw), raw, text, None)

    # -------- severity styling ---------------------------------------------
    @staticmethod
    def _sev_icon(sev):
        return {
            "critical": f"{Colors.RED}{Colors.BOLD}[CRIT]{Colors.RESET}",
            "high":     f"{Colors.YELLOW}{Colors.BOLD}[HIGH]{Colors.RESET}",
            "medium":   f"{Colors.CYAN}[MED ]{Colors.RESET}",
            "low":      f"{Colors.DIM}[LOW ]{Colors.RESET}",
        }.get(sev, f"[{sev.upper()}]")

    @staticmethod
    def _evidence(text, raw):
        if text:
            snippet = text.strip().replace("\n", " ↵ ")
            return snippet[:100]
        if raw:
            return raw[:40].hex()
        return ""

    # -------- single probe --------------------------------------------------
    def _probe(self, base, entry):
        url = f"{base}{entry['path']}"
        status, size, raw, text, err = self._fetch(url)
        if status is None:
            return {"path": entry["path"], "url": url, "status": None,
                    "size": 0, "verified": False, "severity": entry["severity"],
                    "category": entry["category"], "evidence": "",
                    "error": err, "outcome": "error"}

        # Blocked but existing (403/401) is worth surfacing
        if status in (401, 403):
            return {"path": entry["path"], "url": url, "status": status,
                    "size": size, "verified": False,
                    "severity": "low", "category": entry["category"],
                    "evidence": "", "outcome": "blocked"}

        if status != 200:
            return {"path": entry["path"], "url": url, "status": status,
                    "size": size, "verified": False,
                    "severity": entry["severity"],
                    "category": entry["category"], "evidence": "",
                    "outcome": "clean"}

        verified = False
        try:
            verified = bool(entry["signature"](raw, text))
        except Exception:
            verified = False

        outcome = "verified" if verified else "false_positive"
        return {"path": entry["path"], "url": url, "status": status,
                "size": size, "verified": verified,
                "severity": entry["severity"], "category": entry["category"],
                "evidence": self._evidence(text, raw),
                "outcome": outcome,
                "_text": text if entry["category"] == "vcs" and verified else None}

    # -------- .git deep analysis -------------------------------------------
    def _parse_logs(self, logs_text):
        commits, emails, authors, messages = [], set(), set(), []
        pattern = re.compile(
            r"^([0-9a-f]{40})\s+([0-9a-f]{40})\s+(.+?)\s+<([^>]+)>\s+(\d+)\s+[+\-]\d+\t(.*)$")
        for line in logs_text.splitlines():
            m = pattern.match(line.strip())
            if m:
                _old_sha, new_sha, name, email, _ts, action = m.groups()
                commits.append(new_sha)
                emails.add(email.lower())
                authors.add(name)
                messages.append(action)
        return list(dict.fromkeys(commits)), sorted(emails), sorted(authors), messages

    def _deep_git(self, base, probe_map):
        """Extract remote URL / commits / author emails when .git/ files leak."""
        info = {"head_ref": None, "remotes": [], "refs": [],
                "commits": [], "author_emails": [], "author_names": [],
                "commit_messages": [], "index_present": False}

        head_probe = probe_map.get("/.git/HEAD")
        if head_probe and head_probe.get("verified") and head_probe.get("_text"):
            s = head_probe["_text"].strip()
            if s.startswith("ref:"):
                info["head_ref"] = s.replace("ref:", "").strip()

        cfg_probe = probe_map.get("/.git/config")
        if cfg_probe and cfg_probe.get("verified") and cfg_probe.get("_text"):
            info["remotes"] = [r.strip() for r in
                               re.findall(r"url\s*=\s*(.+)", cfg_probe["_text"])]

        logs_probe = probe_map.get("/.git/logs/HEAD")
        if logs_probe and logs_probe.get("verified") and logs_probe.get("_text"):
            commits, emails, authors, messages = self._parse_logs(logs_probe["_text"])
            info["commits"] = commits
            info["author_emails"] = emails
            info["author_names"] = authors
            info["commit_messages"] = messages[:30]

        packed = probe_map.get("/.git/packed-refs")
        if packed and packed.get("verified") and packed.get("_text"):
            info["refs"] = re.findall(r"[0-9a-f]{40}\s+(refs/\S+)",
                                      packed["_text"])

        idx = probe_map.get("/.git/index")
        info["index_present"] = bool(idx and idx.get("verified"))
        return info

    # -------- run -----------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        base = normalize_url(self.get_option("TARGET"))
        self._verify_tls = (self.get_option("VERIFY_TLS") or "true").lower() != "false"
        verify_content = (self.get_option("VERIFY_CONTENT") or "true").lower() != "false"
        try:
            threads = max(1, int(self.get_option("THREADS") or 20))
        except (TypeError, ValueError):
            threads = 20

        raw_cats = (self.get_option("CATEGORIES") or "all").strip().lower()
        if raw_cats in ("", "all", "*"):
            selected = set(self._VALID_CATEGORIES)
        else:
            selected = {c.strip() for c in raw_cats.split(",") if c.strip()}
            invalid = selected - self._VALID_CATEGORIES
            selected = selected & self._VALID_CATEGORIES
            if not selected:
                print_status(
                    f"No valid categories in '{raw_cats}'. Options: "
                    f"{','.join(sorted(self._VALID_CATEGORIES))}", "error")
                return False
            if invalid:
                print_status(f"Ignoring unknown categories: {','.join(sorted(invalid))}", "warning")

        buckets = _all_paths()
        checks = []
        seen_paths = set()
        for cat, entries in buckets.items():
            if cat not in selected:
                continue
            for e in entries:
                if e["path"] in seen_paths:
                    continue
                seen_paths.add(e["path"])
                checks.append(e)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*62}")
        print(f"  Exposed-files scan: {base}")
        print(f"  Checks: {len(checks)}  Categories: {','.join(sorted(selected))}  Threads: {threads}")
        print(f"{'='*62}{Colors.RESET}\n")

        # Parallel probing
        self._errors = []
        probe_map = {}
        exposures = []
        false_positives = 0
        blocked_hits = []
        error_hits = []
        warnings = []

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(self._probe, base, c): c for c in checks}
            done_count = 0
            total = len(futures)
            for fut in as_completed(futures):
                done_count += 1
                try:
                    r = fut.result()
                except Exception as exc:
                    warnings.append(f"probe crashed: {exc}")
                    continue
                probe_map[r["path"]] = r

                if r["outcome"] == "verified":
                    exposures.append(r)
                    print(f" {self._sev_icon(r['severity'])} "
                          f"{Colors.BOLD}{r['path']}{Colors.RESET}  "
                          f"{Colors.GREEN}200{Colors.RESET}  "
                          f"{r['size']}B  "
                          f"{Colors.DIM}[{r['category']}]{Colors.RESET}")
                    if r["evidence"]:
                        print(f"      {Colors.DIM}{r['evidence']}{Colors.RESET}")
                elif r["outcome"] == "false_positive":
                    false_positives += 1
                    if not verify_content:
                        # user asked us to keep unverified 200s
                        r_copy = dict(r)
                        r_copy["severity"] = "low"
                        exposures.append(r_copy)
                        print(f" {self._sev_icon('low')} "
                              f"{Colors.DIM}{r['path']} (200 but signature mismatch — kept){Colors.RESET}")
                elif r["outcome"] == "blocked":
                    blocked_hits.append(r)
                elif r["outcome"] == "error":
                    error_hits.append(r)
                # 'clean' is quiet

        # Deep .git analysis
        git_info = None
        git_paths = {"/.git/HEAD", "/.git/config", "/.git/index",
                     "/.git/packed-refs", "/.git/logs/HEAD"}
        git_hits = [p for p in git_paths
                    if probe_map.get(p, {}).get("verified")]
        if git_hits:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}--- Deep .git analysis ---{Colors.RESET}")
            git_info = self._deep_git(base, probe_map)
            if git_info["head_ref"]:
                print_status(f"HEAD ref: {git_info['head_ref']}", "info")
            for r in git_info["remotes"]:
                print_status(f"Remote: {r}", "warning")
            if git_info["commits"]:
                print_status(f"Recovered {len(git_info['commits'])} commit(s) from logs/HEAD",
                             "success")
            for e in git_info["author_emails"]:
                print_status(f"  Author email: {e}", "warning")
            for a in git_info["author_names"]:
                print_status(f"  Author name: {a}", "info")
            if git_info["refs"]:
                print_status(f"packed-refs: {len(git_info['refs'])} ref(s)", "info")
            if git_info["index_present"]:
                print_status("Index present — full tree reconstructable with git-dumper",
                             "warning")

        # Strip the internal _text payload before persisting
        for r in exposures:
            r.pop("_text", None)
        for r in probe_map.values():
            r.pop("_text", None)

        # Stats
        by_cat = {}
        by_sev = {}
        for r in exposures:
            by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1

        verified_count = sum(1 for r in exposures if r.get("verified"))

        connect_errors = len(error_hits)
        responded = len(checks) - connect_errors
        for r in error_hits[:20]:
            self._note_error(f"{r['path']}: {r.get('error') or 'request failed'}")

        self.results = {
            "target": base,
            "exposed": bool(exposures),
            "exposures": exposures,
            "blocked": blocked_hits,
            "git": git_info,
            "stats": {
                "total_checked": len(checks),
                "responded": responded,
                "connect_errors": connect_errors,
                "exposures_found": len(exposures),
                "verified_exposures": verified_count,
                "false_positives_filtered": false_positives,
                "blocked_but_present": len(blocked_hits),
                "by_category": by_cat,
                "by_severity": by_sev,
            },
            "warnings": warnings,
            "fetch_errors": list(self._errors),
        }

        # Host unreachable: every probe errored out. This is a FAILED scan, not
        # a clean "nothing exposed" result - never paint it green.
        if checks and responded == 0:
            self._fail()
            print(f"\n{Colors.BOLD}{Colors.RED}{'='*62}")
            print(f"  Scan FAILED - {base}: all {len(checks)} probe(s) errored "
                  f"(host unreachable). Exposure status UNKNOWN, not 'clean'.")
            print(f"{'='*62}{Colors.RESET}\n")
            return False

        # Summary
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*62}")
        print(f"  Scan summary — {base}")
        print(f"{'='*62}{Colors.RESET}")
        print(f"  Probed:               {len(checks)}")
        print(f"  Responded:            {responded}")
        print(f"  Connect errors:       {Colors.YELLOW if connect_errors else Colors.RESET}{connect_errors}{Colors.RESET}")
        print(f"  Verified exposures:   {Colors.RED if verified_count else Colors.GREEN}{verified_count}{Colors.RESET}")
        print(f"  False-positive 200s:  {false_positives}")
        print(f"  Blocked (401/403):    {len(blocked_hits)}")

        if by_sev:
            print(f"\n  {Colors.BOLD}By severity:{Colors.RESET}")
            for sev in ("critical", "high", "medium", "low"):
                if sev in by_sev:
                    print(f"    {self._sev_icon(sev)} {by_sev[sev]}")

        if by_cat:
            print(f"\n  {Colors.BOLD}By category:{Colors.RESET}")
            for cat in sorted(by_cat):
                print(f"    {cat:<10} {by_cat[cat]}")

        if git_hits:
            print(f"\n  {Colors.YELLOW}Tip: a full dump is possible with "
                  f"git-dumper against {base}/.git/{Colors.RESET}")

        print()
        return True
