import os
import re
import sys
import json
import importlib
import traceback
import datetime

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

from core.utils import Colors, print_status, print_banner, format_table, print_progress
from core.config import Config
from core.reporter import Reporter

# Matches `api_keys.<name>` anywhere in a module's source - used to show which
# modules consume an API key without editing every module to declare it.
_API_KEY_RE = re.compile(r"api_keys\.([A-Za-z_][A-Za-z0-9_]*)")


MODULE_REGISTRY = {
    "recon/dns_enum": ("modules.recon.dns_enum", "DnsEnum"),
    "recon/whois_lookup": ("modules.recon.whois_lookup", "WhoisLookup"),
    "recon/subdomain": ("modules.recon.subdomain", "SubdomainEnum"),
    "recon/port_scan": ("modules.recon.port_scan", "PortScan"),
    "recon/ip_geoloc": ("modules.recon.ip_geoloc", "IpGeoloc"),
    "recon/reverse_dns": ("modules.recon.reverse_dns", "ReverseDns"),
    "web/headers": ("modules.web.headers", "HeadersAnalysis"),
    "web/ssl_analysis": ("modules.web.ssl_analysis", "SslAnalysis"),
    "web/web_tech": ("modules.web.web_tech", "WebTech"),
    "web/wayback": ("modules.web.wayback", "Wayback"),
    "web/crawler": ("modules.web.crawler", "Crawler"),
    "harvest/email_harvest": ("modules.harvest.email_harvest", "EmailHarvest"),
    "harvest/google_dork": ("modules.harvest.google_dork", "GoogleDork"),
    "harvest/metadata": ("modules.harvest.metadata", "Metadata"),
    "recon/asn_lookup": ("modules.recon.asn_lookup", "AsnLookup"),
    "web/robots_sitemap": ("modules.web.robots_sitemap", "RobotsSitemap"),
    "web/js_scanner": ("modules.web.js_scanner", "JsScanner"),
    "web/dir_bruteforce": ("modules.web.dir_bruteforce", "DirBruteforce"),
    "web/favicon_hash": ("modules.web.favicon_hash", "FaviconHash"),
    "web/waf_detect": ("modules.web.waf_detect", "WafDetect"),
    "web/http_methods": ("modules.web.http_methods", "HttpMethods"),
    "web/security_txt": ("modules.web.security_txt", "SecurityTxt"),
    "web/subdomain_takeover": ("modules.web.subdomain_takeover", "SubdomainTakeover"),
    "web/api_discovery": ("modules.web.api_discovery", "ApiDiscovery"),
    "web/backup_finder": ("modules.web.backup_finder", "BackupFinder"),
    "web/vhost_scan": ("modules.web.vhost_scan", "VhostScan"),
    "web/param_finder": ("modules.web.param_finder", "ParamFinder"),
    "web/cms_scan": ("modules.web.cms_scan", "CmsScan"),
    "web/csp_analysis": ("modules.web.csp_analysis", "CspAnalysis"),
    "web/git_exposed": ("modules.web.git_exposed", "GitExposed"),
    "web/origin_ip": ("modules.web.origin_ip", "OriginIp"),
    "web/wappalyzer_full": ("modules.web.wappalyzer_full", "WappalyzerFull"),
    "web/full_web": ("modules.web.full_web", "FullWeb"),
    "web/recon_full": ("modules.web.recon_full", "ReconFull"),
    "harvest/paste_search": ("modules.harvest.paste_search", "PasteSearch"),
    "harvest/pastes_aggregator": ("modules.harvest.pastes_aggregator", "PastesAggregator"),
    "harvest/reverse_image_links": ("modules.harvest.reverse_image_links", "ReverseImageLinks"),
    "github/commit_emails": ("modules.github.commit_emails", "CommitEmails"),
    "github/user_profile": ("modules.github.user_profile", "UserProfile"),
    "github/keys_extract": ("modules.github.keys_extract", "KeysExtract"),
    "github/repo_analysis": ("modules.github.repo_analysis", "RepoAnalysis"),
    "github/event_history": ("modules.github.event_history", "EventHistory"),
    "github/gist_analysis": ("modules.github.gist_analysis", "GistAnalysis"),
    "github/social_network": ("modules.github.social_network", "SocialNetwork"),
    "github/code_search": ("modules.github.code_search", "CodeSearch"),
    "github/username_to_email": ("modules.github.username_to_email", "UsernameToEmail"),
    "github/commit_lookup": ("modules.github.commit_lookup", "CommitLookup"),
    "github/full_github": ("modules.github.full_github", "FullGithub"),
    "github/dorks": ("modules.github.dorks", "Dorks"),
    "harvest/email_osint": ("modules.harvest.email_osint", "EmailOsint"),
    "harvest/breach_check": ("modules.harvest.breach_check", "BreachCheck"),
    "harvest/image_metadata": ("modules.harvest.image_metadata", "ImageMetadata"),
    "harvest/domain_emails": ("modules.harvest.domain_emails", "DomainEmails"),
    "harvest/username_osint": ("modules.harvest.username_osint", "UsernameOsint"),
    "harvest/phone_osint": ("modules.harvest.phone_osint", "PhoneOsint"),
    "harvest/telegram_osint": ("modules.harvest.telegram_osint", "TelegramOsint"),
    "harvest/discord_osint": ("modules.harvest.discord_osint", "DiscordOsint"),
    "harvest/instagram_osint": ("modules.harvest.instagram_osint", "InstagramOsint"),
    "harvest/tiktok_osint": ("modules.harvest.tiktok_osint", "TiktokOsint"),
    "harvest/snapchat_osint": ("modules.harvest.snapchat_osint", "SnapchatOsint"),
    "harvest/twitter_osint": ("modules.harvest.twitter_osint", "TwitterOsint"),
    "harvest/youtube_osint": ("modules.harvest.youtube_osint", "YoutubeOsint"),
    "harvest/reddit_osint": ("modules.harvest.reddit_osint", "RedditOsint"),
    "harvest/linkedin_osint": ("modules.harvest.linkedin_osint", "LinkedinOsint"),
    "harvest/bluesky_osint": ("modules.harvest.bluesky_osint", "BlueskyOsint"),
    "harvest/mastodon_osint": ("modules.harvest.mastodon_osint", "MastodonOsint"),
    "harvest/twitch_osint": ("modules.harvest.twitch_osint", "TwitchOsint"),
    "harvest/steam_osint": ("modules.harvest.steam_osint", "SteamOsint"),
    "harvest/email_permutator": ("modules.harvest.email_permutator", "EmailPermutator"),
    "harvest/people_search": ("modules.harvest.people_search", "PeopleSearch"),
    "harvest/crypto_balance": ("modules.harvest.crypto_balance", "CryptoBalance"),
    "harvest/crypto_transactions": ("modules.harvest.crypto_transactions", "CryptoTransactions"),
    "harvest/crypto_profile": ("modules.harvest.crypto_profile", "CryptoProfile"),
    "harvest/crypto_portfolio": ("modules.harvest.crypto_portfolio", "CryptoPortfolio"),
    "harvest/crypto_tron": ("modules.harvest.crypto_tron", "CryptoTron"),
    "harvest/crypto_sanctions": ("modules.harvest.crypto_sanctions", "CryptoSanctions"),
    "harvest/oathnet": ("modules.harvest.oathnet", "OathNet"),
    "harvest/company_registry": ("modules.harvest.company_registry", "CompanyRegistry"),
    "harvest/crypto_ens": ("modules.harvest.crypto_ens", "CryptoEns"),
    "harvest/crypto_identity": ("modules.harvest.crypto_identity", "CryptoIdentity"),
    "harvest/crypto_multichain": ("modules.harvest.crypto_multichain", "CryptoMultichain"),
    "harvest/crypto_nft": ("modules.harvest.crypto_nft", "CryptoNft"),
    "harvest/crypto_full": ("modules.harvest.crypto_full", "CryptoFull"),
    "recon/shodan_search": ("modules.recon.shodan_search", "ShodanSearch"),
    "recon/cloud_enum": ("modules.recon.cloud_enum", "CloudEnum"),
    "recon/cve_lookup": ("modules.recon.cve_lookup", "CveLookup"),
    "recon/dns_history": ("modules.recon.dns_history", "DnsHistory"),
    "recon/ip_reputation": ("modules.recon.ip_reputation", "IpReputation"),
    "recon/reverse_ip": ("modules.recon.reverse_ip", "ReverseIp"),
    "recon/ssl_cert_search": ("modules.recon.ssl_cert_search", "SslCertSearch"),
    "recon/ip_range": ("modules.recon.ip_range", "IpRange"),
    "recon/whois_ip": ("modules.recon.whois_ip", "WhoisIp"),
    "recon/dnssec_check": ("modules.recon.dnssec_check", "DnssecCheck"),
    "recon/typosquat": ("modules.recon.typosquat", "Typosquat"),
    "recon/email_server": ("modules.recon.email_server", "EmailServer"),
    "recon/censys_search": ("modules.recon.censys_search", "CensysSearch"),
    "recon/urlscan": ("modules.recon.urlscan", "UrlScan"),
    "recon/hackertarget_api": ("modules.recon.hackertarget_api", "HackertargetApi"),
    "recon/greynoise": ("modules.recon.greynoise", "Greynoise"),
    "recon/otx_alienvault": ("modules.recon.otx_alienvault", "OtxAlienvault"),
    "recon/related_domains": ("modules.recon.related_domains", "RelatedDomains"),
    "recon/favicon_search": ("modules.recon.favicon_search", "FaviconSearch"),
    "recon/github_org": ("modules.recon.github_org", "GithubOrg"),
    "web/wayback_secrets": ("modules.web.wayback_secrets", "WaybackSecrets"),
    "harvest/dark_mentions": ("modules.harvest.dark_mentions", "DarkMentions"),
    "harvest/email_validator": ("modules.harvest.email_validator", "EmailValidator"),
    "web/screenshot": ("modules.web.screenshot", "Screenshot"),
    "full_recon": ("modules.full_recon", "FullRecon"),
    "identity_pivot": ("modules.identity_pivot", "IdentityPivot"),
    "monitor": ("modules.monitor", "Monitor"),
}


# Entity types the correlation engine emits, used for tab completion.
ENTITY_TYPES = ("email", "username", "domain", "ip", "url", "phone",
                "wallet", "asn", "token_contract")


COMMAND_HELP = {
    "use": ("use <module>",
            "Select a module to work with.",
            ["use web/full_web", "use harvest/username_osint"]),
    "set": ("set <option> <value>",
            "Set an option on the selected module (e.g. TARGET).",
            ["set TARGET example.com", "set THREADS 50"]),
    "run": ("run",
            "Execute the selected module. Aliases: exploit, execute.",
            ["run"]),
    "search": ("search <keyword>",
               "Find modules whose name or description match a keyword.",
               ["search email", "search cve"]),
    "modules": ("modules",
                "List every available module grouped by category.", ["modules"]),
    "info": ("info", "Show details about the selected module.", ["info"]),
    "options": ("options", "Show the selected module's options.", ["options"]),
    "results": ("results", "Print the last run's results as JSON.", ["results"]),
    "chain": ("chain <moduleA> <moduleB> [...] <target>",
              "Run modules in sequence; entities found by one feed the next "
              "(emails/IPs/domains/URLs routed by target type).",
              ["chain recon/dns_history recon/ip_reputation example.com"]),
    "html": ("html [target]",
             "Generate a styled HTML report of this session's results.",
             ["html", "html example.com"]),
    "db": ("db <stats|targets|entities|overlap|history|scans|report> [args]",
           "Query the results database. 'report <target>' builds an interactive "
           "graph of a target; 'overlap' lists entities seen for more than one "
           "target; 'history <value>' shows every target an entity appeared for.",
           ["db stats", "db entities example.com email", "db overlap email",
            "db history bob@example.com", "db report example.com"]),
    "auth": ("auth <show|cookie <value>|header <name> <value>|clear>",
             "Set a session cookie / headers so modules can scan authenticated areas.",
             ["auth cookie session=abc123", "auth header Authorization \"Bearer xyz\""]),
    "monitor": ("(module) set MODULE <m>; set TARGET <t>; run",
                "Re-run a module and diff vs the last run (new/removed entities).",
                ["use monitor", "set MODULE recon/subdomain", "set TARGET example.com"]),
    "proxy": ("proxy <status|on|off|tor|set http|https <url>>",
              "Route all HTTP traffic through a proxy or Tor.",
              ["proxy tor", "proxy set http http://127.0.0.1:8080", "proxy off"]),
    "apikeys": ("apikeys <list|set <name> <value>>",
                "View or set API keys (shodan, github, securitytrails, ...).",
                ["apikeys list", "apikeys set shodan YOUR_KEY"]),
    "full_recon": ("full_recon <target> [skip...]",
                   "Run the full recon/web/harvest suite on a domain or IP.",
                   ["full_recon example.com"]),
    "workspace": ("workspace <save|load|list|delete> [name]",
                  "Save or restore session state (selected module + options).",
                  ["workspace save job1", "workspace load job1"]),
    "export": ("export [target]",
               "Export all results for a target as a ZIP archive (JSON + HTML).",
               ["export example.com", "export"]),
    "note": ("note <add|list|delete> <target|id> [text]",
             "Add or list investigation notes attached to a target.",
             ["note add example.com 'Found admin panel at /admin'", "note list example.com"]),
    "pivot": ("pivot <target> [max_depth]",
              "Run identity_pivot on a target (shorthand: auto use/set/run).",
              ["pivot alice@example.com", "pivot johndoe 3"]),
    "tag": ("tag <add|list|remove> <target> [label]",
            "Label targets for grouping multi-target investigations.",
            ["tag add example.com phishing", "tag list phishing"]),
    "verify": ("verify apis",
               "Test every configured API key with a live call.",
               ["verify apis"]),
    "config": ("config", "Show the current configuration.", ["config"]),
    "set_config": ("set_config <key> <value>",
                   "Set a config value (dot notation for nested keys).",
                   ["set_config timeout 15", "set_config http.min_interval 1.0"]),
    "stats": ("stats", "Show session statistics.", ["stats"]),
}


HISTORY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".osintconsole_history")
WORKSPACES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "workspaces")

BASE_COMMANDS = [
    "help", "modules", "search", "use", "info", "options", "set", "run",
    "execute", "exploit", "results", "back", "full_recon", "report",
    "config", "set_config", "clear", "cls", "banner", "exit", "quit",
    "show", "workspace", "stats", "proxy", "apikeys", "db", "html", "chain",
    "auth", "export", "note", "pivot", "tag", "verify",
]


class OsintCompleter:
    """Tab-completion handler for the OsintConsole (Metasploit-style)."""

    _TRUE_FALSE = ("true", "false")

    def __init__(self, console):
        self.console = console
        self.matches = []

    def complete(self, text, state):
        if state == 0:
            line = readline.get_line_buffer() if readline else ""
            stripped = line.lstrip()
            self.matches = self._get_matches(stripped, text)
        return self.matches[state] if state < len(self.matches) else None

    @staticmethod
    def _starts(items, partial, suffix=" "):
        """Case-insensitive startswith filter with a trailing suffix."""
        p = partial.lower()
        return [i + suffix for i in sorted(items) if i.lower().startswith(p)]

    def _known_targets(self):
        """Pull previously-scanned targets from the DB for TARGET completion."""
        try:
            db = self.console._get_db()
            if not db:
                return []
            return [t["target"] for t in db.list_targets()[:50]]
        except Exception:
            return []

    def _config_keys(self, prefix=""):
        """Flatten the config keys to dot-notation for `set_config` completion."""
        out = []

        def walk(obj, path):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = f"{path}.{k}" if path else k
                    if isinstance(v, dict):
                        walk(v, new_path)
                    else:
                        out.append(new_path)

        try:
            walk(self.console.config.data, prefix)
        except Exception:
            pass
        return out

    def _get_matches(self, line, text):
        parts = line.split()
        n = len(parts)
        at_arg = (n == 0 or (n >= 1 and line.endswith(" ")))
        # argi is the index of the token we're completing (1-based for argv-style).
        argi = n if at_arg else max(0, n - 1)

        head = parts[0].lower() if n >= 1 else ""

        # ---- use / chain : module names ----
        if head == "use" and argi == 1:
            return self._starts(MODULE_REGISTRY.keys(), text)

        if head == "chain":
            # chain accepts module names across many positions; last one is the target.
            # Suggest modules while the user keeps typing names.
            return self._starts(MODULE_REGISTRY.keys(), text)

        # ---- set <OPTION> <VALUE> (module-scoped) ----
        if head == "set" and self.console.current_module:
            try:
                opts = list(self.console.current_module.options.keys())
            except (AttributeError, TypeError):
                opts = []
            if argi == 1:
                return self._starts(opts, text)
            if argi == 2 and n >= 2:
                opt_name = parts[1].upper()
                # Common value hints
                if opt_name in ("THREADS", "MAX_VARIATIONS", "TIMEOUT",
                                "MAX_RESULTS", "DEPTH", "LIMIT", "PAGES"):
                    return self._starts(("10", "20", "50", "100"), text)
                if opt_name.endswith(("S", "ON", "OFF", "ENABLED")) or opt_name in (
                        "VARIATIONS", "FETCH_POSTS", "FETCH_PHOTO_HASH",
                        "CHECK_RELATED", "USE_USER_TOKEN", "AGGRESSIVE_PROBE",
                        "WEB_SEARCH", "CHECK_SERVICES"):
                    return self._starts(self._TRUE_FALSE, text)
                if opt_name == "TARGET":
                    return self._starts(self._known_targets(), text)
                return []

        # ---- set_config <key> <value> ----
        if head == "set_config":
            if argi == 1:
                return self._starts(self._config_keys(), text)
            if argi == 2 and n >= 2:
                key = parts[1].lower()
                if key.endswith(("enabled", "verbose", "tor")):
                    return self._starts(self._TRUE_FALSE, text)
                return []

        # ---- workspace <sub> [name] ----
        if head == "workspace":
            if argi == 1:
                return self._starts(("save", "load", "list", "delete"), text)
            if argi == 2 and n >= 2 and parts[1] in ("load", "delete"):
                return self._starts(_list_workspace_names(), text)

        # ---- apikeys list | set <name> <value> ----
        if head == "apikeys":
            if argi == 1:
                return self._starts(("list", "set"), text)
            if argi == 2 and n >= 2 and parts[1] == "set":
                try:
                    keys = list(self.console.config.get("api_keys", {}).keys())
                except Exception:
                    keys = []
                return self._starts(keys, text)

        # ---- proxy status | on | off | tor | set http|https <url> ----
        if head == "proxy":
            if argi == 1:
                return self._starts(
                    ("status", "on", "off", "tor", "set"), text)
            if argi == 2 and n >= 2 and parts[1] == "set":
                return self._starts(("http", "https"), text)

        # ---- auth show | cookie <v> | header <k> <v> | clear ----
        if head == "auth":
            if argi == 1:
                return self._starts(
                    ("show", "cookie", "header", "host", "clear"), text)

        # ---- db stats|targets|entities|overlap|history|scans|report ----
        if head == "db":
            if argi == 1:
                return self._starts(
                    ("stats", "targets", "entities", "overlap", "history",
                     "scans", "report"), text)
            if argi == 2 and n >= 2 and parts[1] in ("entities", "scans", "report"):
                return self._starts(self._known_targets(), text)
            if argi == 2 and n >= 2 and parts[1] == "overlap":
                return self._starts(ENTITY_TYPES, text)
            if argi == 3 and n >= 3 and parts[1] == "entities":
                return self._starts(ENTITY_TYPES, text)

        # ---- export [target] ----
        if head == "export" and argi == 1:
            return self._starts(self._known_targets(), text)

        # ---- note add|list|delete ----
        if head == "note":
            if argi == 1:
                return self._starts(("add", "list", "delete"), text)
            if argi == 2:
                return self._starts(self._known_targets(), text)

        # ---- pivot <target> ----
        if head == "pivot" and argi == 1:
            return self._starts(self._known_targets(), text)

        # ---- tag add|list|remove ----
        if head == "tag":
            if argi == 1:
                return self._starts(("add", "list", "remove"), text)
            if argi == 2:
                return self._starts(self._known_targets(), text)

        # ---- verify apis ----
        if head == "verify" and argi == 1:
            return self._starts(("apis",), text)

        # ---- help <command> ----
        if head == "help" and argi == 1:
            return self._starts(COMMAND_HELP.keys(), text)

        # ---- modules passive|active ----
        if head == "modules" and argi == 1:
            return self._starts(("passive", "active"), text)

        # ---- html [target] | full_recon <target> ----
        if head in ("html", "full_recon") and argi == 1:
            return self._starts(self._known_targets(), text)

        # ---- show modules|options ----
        if head == "show" and argi == 1:
            return self._starts(("modules", "options"), text)

        # ---- search <keyword> : no completion ----
        if head == "search":
            return []

        # Default: complete top-level command names.
        if argi <= 1:
            return self._starts(BASE_COMMANDS, text)
        return []


def _list_workspace_names():
    """Return a sorted list of saved workspace names."""
    if not os.path.isdir(WORKSPACES_DIR):
        return []
    names = []
    for f in os.listdir(WORKSPACES_DIR):
        if f.endswith(".json"):
            names.append(f[:-5])
    return sorted(names)


def _safe_workspace_path(name):
    """Return ws_path only if it stays inside WORKSPACES_DIR; else None."""
    if not name or any(c in name for c in '/\\') or name.startswith('.'):
        return None
    import re as _re
    if not _re.match(r'^[A-Za-z0-9_.-]+$', name):
        return None
    ws_path = os.path.abspath(os.path.join(WORKSPACES_DIR, f"{name}.json"))
    base = os.path.abspath(WORKSPACES_DIR)
    if not ws_path.startswith(base + os.sep) and ws_path != base:
        return None
    return ws_path


class Console:
    def __init__(self):
        self.config = Config()
        self.reporter = Reporter(self.config.get("output_dir", "results"))
        self.current_module = None
        self.current_module_name = None
        self.last_results = None
        self.all_results = {}
        self.history = []
        self.session_start = datetime.datetime.now()
        self.modules_run_count = 0
        self.targets_scanned = set()
        self.results_saved_count = 0
        self.db = None
        self._setup_readline()
        self._apply_proxy_env()

    def _get_db(self):
        """Lazily open the SQLite backend if enabled in config."""
        if not self.config.get("database.enabled", True):
            return None
        if self.db is None:
            try:
                from core.database import Database
                self.db = Database()
            except Exception as e:
                print_status(f"Database unavailable: {e}", "warning")
                return None
        return self.db

    def _persist_to_db(self, target, module_name, results):
        """Save a scan and auto-extract entities into the database.

        Goes through core.correlate rather than utils.extract_entities so a
        single module run stores the same filtered entities full_recon does --
        the unfiltered walker turned every CDN host and analytics domain in a
        scraped page into a database row.
        """
        db = self._get_db()
        if not db:
            return
        try:
            from core.correlate import correlate
            db.save_scan(target, module_name, results)
            db.save_correlation(target, correlate(target, {module_name: results}))
        except Exception as e:
            # Always surface: if this fails the run's findings are NOT saved,
            # yet the UI otherwise implies they were.
            print_status(f"DB persist error (results not saved to DB): {e}", "warning")
            if self.config.get("verbose"):
                import traceback
                traceback.print_exc()

    def _setup_readline(self):
        """Configure readline for history and tab completion."""
        if readline is None:
            return
        try:
            completer = OsintCompleter(self)
            readline.set_completer(completer.complete)
            readline.set_completer_delims(" \t\n")
            # macOS uses libedit which needs a different parse_and_bind
            if "libedit" in (getattr(readline, "__doc__", "") or ""):
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
            # Load existing history
            if os.path.isfile(HISTORY_FILE):
                readline.read_history_file(HISTORY_FILE)
        except Exception:
            pass

    def _save_history(self):
        """Persist readline history to disk."""
        if readline is None:
            return
        try:
            readline.write_history_file(HISTORY_FILE)
        except Exception:
            pass

    def _shutdown(self):
        """Clean up resources on exit: save history and close the database."""
        self._save_history()
        if self.db:
            try:
                self.db.close()
            except Exception:
                pass
            self.db = None

    def print_progress(self, current, total, prefix=""):
        """Display a text-based progress bar."""
        print_progress(current, total, prefix=prefix)

    def _load_module(self, name):
        if name not in MODULE_REGISTRY:
            return None
        module_path, class_name = MODULE_REGISTRY[name]
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        return cls()

    def _module_api_keys(self, name):
        """The api_key names a module references, so the user can see which
        modules want a key BEFORE running them. Derived by scanning the module
        source for `api_keys.<name>` - accurate and auto-maintained, no
        per-module declaration to drift out of date."""
        if not hasattr(self, "_api_key_cache"):
            self._api_key_cache = {}
        if name in self._api_key_cache:
            return self._api_key_cache[name]
        keys = []
        try:
            import inspect
            entry = MODULE_REGISTRY.get(name)
            if entry:
                src = inspect.getsource(importlib.import_module(entry[0]))
                keys = sorted(set(_API_KEY_RE.findall(src)))
        except Exception:
            keys = []
        self._api_key_cache[name] = keys
        return keys

    def _prompt(self):
        if self.current_module_name:
            return f"{Colors.RED}osintconsole{Colors.RESET}({Colors.CYAN}{self.current_module_name}{Colors.RESET}) > "
        return f"{Colors.RED}osintconsole{Colors.RESET} > "

    def _cmd_help(self, args):
        # Detailed, per-command help: `help <command>`
        if args:
            name = args[0].lower().lstrip("/")
            entry = COMMAND_HELP.get(name)
            if not entry:
                print_status(f"No detailed help for '{name}'. Type 'help' for all commands.",
                             "warning")
                return
            usage, desc, examples = entry
            print(f"\n  {Colors.BOLD}{Colors.GREEN}{name}{Colors.RESET}")
            print(f"  {'─'*50}")
            print(f"  {Colors.BOLD}Usage:{Colors.RESET}   {usage}")
            print(f"  {Colors.BOLD}About:{Colors.RESET}   {desc}")
            if examples:
                print(f"  {Colors.BOLD}Examples:{Colors.RESET}")
                for ex in examples:
                    print(f"    {Colors.CYAN}osintconsole >{Colors.RESET} {ex}")
            print()
            return

        # Overview with a live module-count breakdown
        counts = {}
        for mod_name in MODULE_REGISTRY:
            cat = mod_name.split("/")[0] if "/" in mod_name else "auto"
            counts[cat] = counts.get(cat, 0) + 1
        breakdown = "  ".join(f"{Colors.CYAN}{c}{Colors.RESET}:{n}"
                              for c, n in sorted(counts.items()))

        def row(cmd, desc):
            return f"  {Colors.GREEN}{cmd:<26}{Colors.RESET}{desc}"

        print(f"""
{Colors.BOLD}{Colors.CYAN}  OsintConsole{Colors.RESET}  —  {len(MODULE_REGISTRY)} modules   [ {breakdown} ]
  {'='*56}

{Colors.BOLD}  Modules & Selection{Colors.RESET}
  {'─'*56}
{row("modules", "List all modules grouped by category")}
{row("search <keyword>", "Search modules by name/description")}
{row("use <module>", "Select a module to work with")}
{row("info / options", "Show module details / its options")}
{row("set <option> <value>", "Set an option (e.g. set TARGET ...)")}
{row("run", "Execute the selected module")}
{row("results", "Show the last run's results (JSON)")}
{row("back", "Deselect the current module")}

{Colors.BOLD}  Automation & Reporting{Colors.RESET}
  {'─'*56}
{row("full_recon <target>", "Run the full suite on a domain/IP")}
{row("chain <modA> <modB> <tgt>", "Pipe one module's findings into the next")}
{row("html [target]", "Build an HTML report of this session")}
{row("db <stats|targets|...>", "Query the results database")}

{Colors.BOLD}  Configuration{Colors.RESET}
  {'─'*56}
{row("proxy <on|off|tor|set>", "Route traffic via proxy / Tor")}
{row("auth <cookie|header|...>", "Session auth for scanning logged-in areas")}
{row("apikeys <list|set k v>", "View or set API keys")}
{row("config / set_config k v", "Show / change configuration")}
{row("workspace <save|load|...>", "Save or restore session state")}
{row("stats", "Session statistics")}

{Colors.BOLD}  Session{Colors.RESET}
  {'─'*56}
{row("clear / banner", "Clear screen / show banner")}
{row("exit / quit", "Leave the console")}

  {Colors.DIM}Quick start:{Colors.RESET} {Colors.CYAN}use{Colors.RESET} <module> → {Colors.CYAN}set{Colors.RESET} TARGET <value> → {Colors.CYAN}run{Colors.RESET}
  {Colors.DIM}Type{Colors.RESET} {Colors.GREEN}help <command>{Colors.RESET} {Colors.DIM}for usage and examples of any command.{Colors.RESET}
""")

    def _cmd_modules(self, args):
        # Optional filter: 'modules passive' or 'modules active'
        flt = args[0].lower() if args else None
        categories = {"recon": [], "web": [], "harvest": [], "auto": []}
        for name in sorted(MODULE_REGISTRY.keys()):
            try:
                mod = self._load_module(name)
                if mod and flt == "passive" and mod.intrusive:
                    continue
                if mod and flt == "active" and not mod.intrusive:
                    continue
                cat = mod.category if mod else name.split("/")[0]
                if cat not in categories:
                    categories[cat] = []
                kind = (f"{Colors.YELLOW}active{Colors.RESET}" if mod and mod.intrusive
                        else f"{Colors.DIM}passive{Colors.RESET}")
                keys = self._module_api_keys(name)
                if keys:
                    unset = [k for k in keys if not (self.config.get(f"api_keys.{k}") or "").strip()]
                    colour = Colors.YELLOW if unset else Colors.GREEN
                    key_cell = f"{colour}{','.join(keys)}{Colors.RESET}"
                else:
                    key_cell = f"{Colors.DIM}-{Colors.RESET}"
                categories[cat].append([name, kind, mod.description if mod else "",
                                        mod.target_type if mod else "", key_cell])
            except Exception:
                categories.setdefault("other", []).append([name, "", "Error loading", "", ""])

        for cat, mods in categories.items():
            if not mods:
                continue
            print(f"\n{Colors.BOLD}  {cat.upper()} Modules{Colors.RESET}")
            print(format_table(["Module", "Type", "Description", "Target", "API Key"], mods))
        print_status("API Key column: keys a module uses - "
                     f"{Colors.GREEN}green{Colors.RESET}=all set, "
                     f"{Colors.YELLOW}yellow{Colors.RESET}=one or more unset, "
                     f"'-'=no key needed. Most keyed modules still run free with reduced data.",
                     "info")
        if flt not in (None, "passive", "active"):
            print_status("Tip: 'modules passive' or 'modules active' to filter", "info")

    def _cmd_search(self, args):
        if not args:
            print_status("Usage: search <keyword>", "info")
            return
        keyword = args[0].lower()
        results = []
        for name in MODULE_REGISTRY:
            try:
                mod = self._load_module(name)
                if keyword in name.lower() or (mod and keyword in mod.description.lower()):
                    results.append([name, mod.description if mod else ""])
            except Exception as e:
                # A module that fails to import must not silently vanish from
                # search (it did before) - flag it like `modules` does.
                if keyword in name.lower():
                    results.append([name, f"{Colors.RED}(error loading: {e}){Colors.RESET}"])
        if results:
            print(f"\n{Colors.BOLD}  Search Results for '{keyword}':{Colors.RESET}")
            print(format_table(["Module", "Description"], results))
        else:
            print_status(f"No modules found matching '{keyword}'", "warning")

    def _cmd_use(self, args):
        if not args:
            print_status("Usage: use <module_name>", "info")
            return
        name = args[0]
        matches = [m for m in MODULE_REGISTRY if name in m]
        if not matches:
            print_status(f"Module '{name}' not found. Use 'modules' to list.", "error")
            return
        if name not in MODULE_REGISTRY and len(matches) == 1:
            name = matches[0]
        elif name not in MODULE_REGISTRY:
            print_status(f"Ambiguous match: {', '.join(matches)}", "warning")
            return

        try:
            self.current_module = self._load_module(name)
            self.current_module_name = name
            print_status(f"Using module: {name}", "info")
        except Exception as e:
            print_status(f"Failed to load module: {e}", "error")

    def _cmd_set(self, args):
        if not self.current_module:
            print_status("No module selected. Use 'use <module>' first.", "error")
            return
        if len(args) < 2:
            print_status("Usage: set <option> <value>", "info")
            return
        option = args[0]
        value = " ".join(args[1:])
        if self.current_module.set_option(option, value):
            print_status(f"{option} => {value}", "success")
        else:
            print_status(f"Unknown option '{option}'. Use 'options' to see available.", "error")

    def _cmd_run(self, args):
        if not self.current_module:
            print_status("No module selected. Use 'use <module>' first.", "error")
            return
        try:
            success = self.current_module.run()
            if success:
                self.modules_run_count += 1
                self.last_results = self.current_module.get_results()
                self.all_results[self.current_module_name] = self.last_results
                target = self.current_module.get_option("TARGET")
                if target:
                    self.targets_scanned.add(target)
                    self.reporter.save_module_result(
                        target, self.current_module_name, self.last_results
                    )
                    self.results_saved_count += 1
                    print_status(f"Results saved to {self.config.get('output_dir')}/", "success")
                    self._persist_to_db(target, self.current_module_name, self.last_results)
        except KeyboardInterrupt:
            print_status("Module execution interrupted", "warning")
        except Exception as e:
            print_status(f"Module execution failed: {e}", "error")
            if self.config.get("verbose"):
                traceback.print_exc()

    def _cmd_full_recon(self, args):
        if not args:
            print_status("Usage: full_recon <target>", "info")
            return
        target = args[0]
        mod = self._load_module("full_recon")
        mod.set_option("TARGET", target)
        if len(args) > 1:
            mod.set_option("SKIP", " ".join(args[1:]))
        try:
            mod.run()
            self.last_results = mod.get_results()
        except KeyboardInterrupt:
            print_status("Full recon interrupted", "warning")

    def _cmd_results(self, args):
        if not self.last_results:
            print_status("No results available. Run a module first.", "warning")
            return
        import json
        print(json.dumps(self.last_results, indent=2, default=str, ensure_ascii=False))

    def _cmd_config(self, args):
        import json
        print(f"\n{Colors.BOLD}  Current Configuration:{Colors.RESET}\n")
        print(json.dumps(self.config.data, indent=2, ensure_ascii=False))
        print()

    def _cmd_set_config(self, args):
        if len(args) < 2:
            print_status("Usage: set_config <key> <value>", "info")
            return
        key = args[0]
        value = " ".join(args[1:])
        self.config.set(key, value)
        self.config.save()
        print_status(f"Config: {key} => {value}", "success")

    def _cmd_workspace(self, args):
        if not args:
            print_status("Usage: workspace <save|load|list|delete> [name]", "info")
            return
        sub = args[0].lower()
        if sub == "list":
            names = _list_workspace_names()
            if not names:
                print_status("No saved workspaces.", "info")
                return
            print(f"\n{Colors.BOLD}  Saved Workspaces:{Colors.RESET}")
            for name in names:
                ws_path = os.path.join(WORKSPACES_DIR, f"{name}.json")
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(ws_path)).strftime("%Y-%m-%d %H:%M:%S")
                print(f"    {Colors.CYAN}{name}{Colors.RESET}  ({mtime})")
            print()
        elif sub == "save":
            if len(args) < 2:
                print_status("Usage: workspace save <name>", "info")
                return
            name = args[1]
            os.makedirs(WORKSPACES_DIR, exist_ok=True)
            # Gather current module options
            module_options = {}
            if self.current_module:
                try:
                    for opt_name, opt in self.current_module.options.items():
                        module_options[opt_name] = opt.get("value", "")
                except (AttributeError, TypeError):
                    pass
            state = {
                "module": self.current_module_name,
                "options": module_options,
                "history": self.history[-200:],
                "saved_at": datetime.datetime.now().isoformat(),
            }
            ws_path = _safe_workspace_path(name)
            if not ws_path:
                print_status(f"Invalid workspace name: {name}", "error")
                return
            with open(ws_path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
            print_status(f"Workspace saved: {name}", "success")
        elif sub == "load":
            if len(args) < 2:
                print_status("Usage: workspace load <name>", "info")
                return
            name = args[1]
            ws_path = _safe_workspace_path(name)
            if not ws_path:
                print_status(f"Invalid workspace name: {name}", "error")
                return
            if not os.path.isfile(ws_path):
                print_status(f"Workspace '{name}' not found.", "error")
                return
            with open(ws_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            # Restore module selection
            if state.get("module"):
                self._cmd_use([state["module"]])
                # Restore options
                if self.current_module and state.get("options"):
                    for k, v in state["options"].items():
                        if v:
                            self.current_module.set_option(k, v)
            # Restore command history
            if state.get("history"):
                self.history = state["history"]
            print_status(f"Workspace loaded: {name}", "success")
        elif sub == "delete":
            if len(args) < 2:
                print_status("Usage: workspace delete <name>", "info")
                return
            name = args[1]
            ws_path = _safe_workspace_path(name)
            if not ws_path:
                print_status(f"Invalid workspace name: {name}", "error")
                return
            if not os.path.isfile(ws_path):
                print_status(f"Workspace '{name}' not found.", "error")
                return
            os.remove(ws_path)
            print_status(f"Workspace deleted: {name}", "success")
        else:
            print_status("Usage: workspace <save|load|list|delete> [name]", "info")

    def _cmd_proxy(self, args):
        """Manage proxy / Tor routing for all HTTP traffic."""
        proxy = self.config.get("proxy", {})
        if not args or args[0] == "status":
            state = "ON" if proxy.get("enabled") else "OFF"
            print(f"\n{Colors.BOLD}  Proxy Status: "
                  f"{Colors.GREEN if proxy.get('enabled') else Colors.RED}{state}{Colors.RESET}")
            print(f"    Tor:   {proxy.get('tor')}  ({proxy.get('tor_address')})")
            print(f"    HTTP:  {proxy.get('http') or '(none)'}")
            print(f"    HTTPS: {proxy.get('https') or '(none)'}\n")
            return
        sub = args[0].lower()
        if sub == "on":
            self.config.set("proxy.enabled", True)
        elif sub == "off":
            self.config.set("proxy.enabled", False)
        elif sub == "tor":
            self.config.set("proxy.enabled", True)
            self.config.set("proxy.tor", True)
            print_status("Tor routing enabled (socks5h://127.0.0.1:9050)", "success")
        elif sub == "set" and len(args) >= 3:
            scheme = args[1].lower()
            url = args[2]
            self.config.set(f"proxy.{scheme}", url)
            self.config.set("proxy.enabled", True)
            self.config.set("proxy.tor", False)
            print_status(f"Proxy {scheme} => {url}", "success")
        else:
            print_status("Usage: proxy <status|on|off|tor|set http|https <url>>", "info")
            return
        self.config.save()
        self._apply_proxy_env()
        print_status("Proxy settings saved", "success")

    def _apply_proxy_env(self):
        """Export proxy to env so even non-core-http requests honor it."""
        proxies = self.config.proxies()
        if proxies:
            os.environ["HTTP_PROXY"] = proxies.get("http", "")
            os.environ["HTTPS_PROXY"] = proxies.get("https", "")
        else:
            os.environ.pop("HTTP_PROXY", None)
            os.environ.pop("HTTPS_PROXY", None)

    def _cmd_apikeys(self, args):
        """View or set API keys."""
        keys = self.config.get("api_keys", {})
        if not args or args[0] == "list":
            # Reverse map: which modules consume each key (answers "do I need
            # to set this key, and for what?"). Scans module sources once.
            used_by = {}
            for mod_name in MODULE_REGISTRY:
                for k in self._module_api_keys(mod_name):
                    used_by.setdefault(k, []).append(mod_name)
            print(f"\n{Colors.BOLD}  API Keys{Colors.RESET}\n  {'─'*40}")
            for name, val in keys.items():
                status = (f"{Colors.GREEN}set{Colors.RESET}" if val
                          else f"{Colors.DIM}not set{Colors.RESET}")
                masked = (val[:4] + "..." + val[-4:]) if val and len(val) > 8 else ("*" * len(val) if val else "")
                print(f"    {name:<20} {status}  {masked}")
                mods = used_by.get(name)
                if mods:
                    print(f"      {Colors.DIM}used by: {', '.join(mods)}{Colors.RESET}")
            # Keys referenced by a module but not declared in config = can't be set.
            undeclared = sorted(set(used_by) - set(keys))
            if undeclared:
                print(f"\n    {Colors.YELLOW}! referenced by modules but not "
                      f"settable (missing from config): {', '.join(undeclared)}{Colors.RESET}")
            print()
            return
        if args[0] == "set" and len(args) >= 3:
            name = args[1]
            value = args[2]
            if name not in keys:
                print_status(f"Unknown key '{name}'. Available: {', '.join(keys.keys())}", "error")
                return
            self.config.set(f"api_keys.{name}", value)
            self.config.save()
            print_status(f"API key '{name}' saved", "success")
        else:
            print_status("Usage: apikeys <list|set <name> <value>>", "info")

    def _cmd_auth(self, args):
        """Set cookies/headers so modules can scan authenticated areas."""
        if not args or args[0] == "show":
            headers = self.config.get("http.headers") or {}
            cookies = self.config.get("http.cookies") or ""
            hosts = self.config.get("http.auth_hosts") or []
            print(f"\n{Colors.BOLD}  Auth / Session{Colors.RESET}\n  {'-'*40}")
            print(f"    Cookie: {cookies or '(none)'}")
            for k, v in headers.items():
                print(f"    Header: {k}: {v}")
            print(f"    Sent only to hosts: {', '.join(hosts) or '(none set)'}")
            if (headers or cookies) and not hosts:
                print(f"    {Colors.YELLOW}! auth is set but NO hosts allowed — it "
                      f"is sent NOWHERE until you run 'auth host <host>'{Colors.RESET}")
            if not headers and not cookies:
                print(f"    {Colors.DIM}(nothing set){Colors.RESET}")
            print()
            return
        sub = args[0].lower()

        def _warn_hosts():
            if not (self.config.get("http.auth_hosts") or []):
                print_status("NOTE: auth is host-scoped — it will NOT be sent until "
                             "you run 'auth host <hostname>' (prevents leaking it to "
                             "third-party APIs)", "warning")

        if sub == "cookie" and len(args) >= 2:
            self.config.set("http.cookies", " ".join(args[1:]))
            self.config.save()
            print_status("Session cookie set (host-scoped)", "success")
            _warn_hosts()
        elif sub == "header" and len(args) >= 3:
            headers = dict(self.config.get("http.headers") or {})
            headers[args[1]] = " ".join(args[2:])
            self.config.set("http.headers", headers)
            self.config.save()
            print_status(f"Header '{args[1]}' set (host-scoped)", "success")
            _warn_hosts()
        elif sub == "host" and len(args) >= 2:
            hosts = list(self.config.get("http.auth_hosts") or [])
            for h in args[1:]:
                h = h.strip().lower()
                if h and h not in hosts:
                    hosts.append(h)
            self.config.set("http.auth_hosts", hosts)
            self.config.save()
            print_status(f"Auth now sent to: {', '.join(hosts)}", "success")
        elif sub == "clear":
            self.config.set("http.cookies", "")
            self.config.set("http.headers", {})
            self.config.set("http.auth_hosts", [])
            self.config.save()
            print_status("Auth cleared", "success")
        else:
            print_status("Usage: auth <show|cookie <value>|header <name> <value>|"
                         "host <hostname>|clear>", "info")

    def _cmd_db(self, args):
        """Query the SQLite results database."""
        db = self._get_db()
        if not db:
            print_status("Database is disabled (set_config database.enabled true)", "warning")
            return
        sub = args[0].lower() if args else "stats"
        if sub == "stats":
            s = db.stats()
            print(f"\n{Colors.BOLD}  Database Statistics{Colors.RESET}\n  {'─'*40}")
            print(f"    Total scans:    {s['total_scans']}")
            print(f"    Total targets:  {s['total_targets']}")
            print(f"    Total entities: {s['total_entities']}")
            for etype, count in s["entities_by_type"].items():
                print(f"      {etype}: {count}")
            print()
        elif sub == "targets":
            targets = db.list_targets()
            if not targets:
                print_status("No targets in database", "info")
                return
            print(f"\n{Colors.BOLD}  Scanned Targets{Colors.RESET}")
            rows = [[t["target"], t["scan_count"], t["last_seen"][:19]] for t in targets]
            print(format_table(["Target", "Scans", "Last Seen"], rows))
        elif sub == "entities":
            target = args[1] if len(args) > 1 else None
            etype = args[2] if len(args) > 2 else None
            entities = db.get_entities(target, etype)
            if not entities:
                print_status("No entities found", "info")
                return
            print(f"\n{Colors.BOLD}  Entities{Colors.RESET}")
            rows = [[e["entity_type"], e["value"],
                     e.get("confidence") or "-",
                     e.get("module_count") or "-",
                     e["source_module"]] for e in entities[:200]]
            print(format_table(
                ["Type", "Value", "Confidence", "Modules", "Source"], rows))
        elif sub == "overlap":
            etype = args[1] if len(args) > 1 else None
            rows_raw = db.entities_across_targets(min_targets=2, entity_type=etype)
            if not rows_raw:
                print_status(
                    "No entity has been seen for more than one target yet", "info")
                return
            print(f"\n{Colors.BOLD}  Entities shared across targets{Colors.RESET}")
            rows = [[r["entity_type"], r["value"], r["target_count"],
                     (r["targets"] or "")[:60]] for r in rows_raw[:200]]
            print(format_table(["Type", "Value", "Targets", "Seen for"], rows))
        elif sub == "history":
            if len(args) < 2:
                print_status("Usage: db history <entity value>", "info")
                return
            rows_raw = db.entity_history(args[1])
            if not rows_raw:
                print_status(f"'{args[1]}' is not in the database", "info")
                return
            print(f"\n{Colors.BOLD}  History for {args[1]}{Colors.RESET}")
            rows = [[r["target"], r["entity_type"], r.get("confidence") or "-",
                     (r.get("first_seen") or "")[:19],
                     (r.get("last_seen") or "")[:19]] for r in rows_raw]
            print(format_table(
                ["Target", "Type", "Confidence", "First Seen", "Last Seen"], rows))
        elif sub == "scans":
            target = args[1] if len(args) > 1 else None
            scans = db.get_scans(target)
            if not scans:
                print_status("No scans found", "info")
                return
            print(f"\n{Colors.BOLD}  Scan History{Colors.RESET}")
            rows = [[s["id"], s["target"], s["module"], s["timestamp"][:19]] for s in scans]
            print(format_table(["ID", "Target", "Module", "When"], rows))
        elif sub == "report":
            if len(args) < 2:
                print_status("Usage: db report <target>", "info")
                return
            self._db_target_report(db, args[1])
        else:
            print_status(
                "Usage: db <stats|targets|entities [target] [type]|"
                "overlap [type]|history <value>|scans [target]|report <target>>",
                "info")

    def _db_target_report(self, db, target):
        """Aggregate everything known about a target into one interactive graph report."""
        entities = db.get_entities(target)
        scans = db.get_scans(target)
        if not entities and not scans:
            print_status(f"Nothing in the database for '{target}'", "warning")
            return

        # Build the entity graph: target in the center, each entity a node.
        nodes = [{"id": target, "label": target, "group": "target", "value": 10,
                  "title": f"Target ({len(scans)} scans)"}]
        edges = []
        seen = {target}
        by_type = {}
        for e in entities:
            val, etype, src = e["value"], e["entity_type"], e.get("source_module", "")
            by_type.setdefault(etype, []).append((val, src))
            if val not in seen:
                seen.add(val)
                nodes.append({"id": val, "label": val, "group": etype,
                              "value": 3, "title": f"{etype} (via {src})"})
            edges.append({"from": target, "to": val, "label": src.split("/")[-1]})

        # Detail sections: entities grouped by type + scan history.
        sections = []
        for etype in sorted(by_type):
            rows = "".join(
                f"<tr><td>{self.reporter._esc(v)}</td><td>{self.reporter._esc(s)}</td></tr>"
                for v, s in sorted(set(by_type[etype])))
            sections.append((f"{etype} ({len(set(by_type[etype]))})",
                             f"<table><tr><th>Value</th><th>Found by</th></tr>{rows}</table>"))
        scan_rows = "".join(
            f"<tr><td>{self.reporter._esc(s['module'])}</td>"
            f"<td>{self.reporter._esc(s['timestamp'][:19])}</td></tr>" for s in scans)
        sections.append((f"Scan history ({len(scans)})",
                         f"<table><tr><th>Module</th><th>When</th></tr>{scan_rows}</table>"))

        path = self.reporter.generate_graph_html(target, nodes, edges, sections)
        print_status(f"Target report: {len(entities)} entities, {len(scans)} scans across "
                     f"{len(by_type)} type(s)", "success")
        print_status(f"Interactive graph report: {path}", "success")

    def _cmd_html(self, args):
        """Generate an HTML report from this session's results."""
        if not self.all_results:
            print_status("No results this session. Run some modules first.", "warning")
            return
        target = args[0] if args else (sorted(self.targets_scanned)[0]
                                       if self.targets_scanned else "session")
        path = self.reporter.generate_html_report(target, self.all_results)
        print_status(f"HTML report generated: {path}", "success")

    def _cmd_chain(self, args):
        """Chain modules: output entities of module A feed module B.

        Usage: chain <moduleA> <moduleB> [moduleC...] <target>
        """
        if len(args) < 3:
            print_status("Usage: chain <moduleA> <moduleB> [...] <target>", "info")
            print_status("Example: chain recon/dns_history recon/ip_reputation example.com", "info")
            return
        *module_names, target = args
        from core.utils import extract_entities

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Module Chain ({len(module_names)} stages)")
        print(f"  Seed target: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        current_targets = [target]
        for i, mod_name in enumerate(module_names):
            matches = [m for m in MODULE_REGISTRY if mod_name in m]
            if mod_name not in MODULE_REGISTRY:
                if len(matches) == 1:
                    mod_name = matches[0]
                else:
                    print_status(f"Stage {i+1}: '{mod_name}' not found/ambiguous, skipping", "error")
                    continue

            print(f"\n{Colors.YELLOW}{'─'*50}")
            print(f"  Stage {i+1}: {mod_name}  ({len(current_targets)} target(s))")
            print(f"{'─'*50}{Colors.RESET}")

            next_targets = set()
            for tgt in current_targets[:10]:
                try:
                    mod = self._load_module(mod_name)
                    mod.set_option("TARGET", tgt)
                    if mod.run():
                        results = mod.get_results()
                        self.all_results[f"{mod_name}:{tgt}"] = results
                        self.reporter.save_module_result(tgt, mod_name, results)
                        self._persist_to_db(tgt, mod_name, results)
                        ents = extract_entities(results)
                        for vals in ents.values():
                            next_targets.update(vals)
                except Exception as e:
                    print_status(f"  {tgt}: {e}", "error")

            if i < len(module_names) - 1:
                next_mod_type = None
                try:
                    probe = self._load_module(
                        module_names[i + 1] if module_names[i + 1] in MODULE_REGISTRY
                        else [m for m in MODULE_REGISTRY if module_names[i + 1] in m][0])
                    next_mod_type = probe.target_type
                except Exception:
                    pass
                filtered = self._filter_targets(next_targets, next_mod_type)
                current_targets = filtered or [target]
                print_status(f"Extracted {len(filtered)} target(s) for next stage", "info")

        print(f"\n{Colors.GREEN}{'='*58}")
        print(f"  Chain complete")
        print(f"{'='*58}{Colors.RESET}\n")

    def _filter_targets(self, values, target_type):
        """Pick entities matching the next module's expected target type.

        Handles ip, url, email, username, phone, wallet (BTC/ETH/LTC),
        cidr, asn and domain. Checks are ordered so that more specific
        shapes win before falling through to the broad `domain` test.
        """
        from core.utils import is_valid_ip, is_valid_domain, is_valid_url
        values = list(values)
        if not target_type:
            return values[:20]
        tt = target_type.lower()
        picked = []
        for v in values:
            if "ip" in tt and is_valid_ip(v):
                picked.append(v)
            elif "url" in tt and is_valid_url(v):
                picked.append(v)
            elif "email" in tt and "@" in v and "." in v.split("@")[-1]:
                picked.append(v)
            elif "username" in tt and re.match(r"^[A-Za-z0-9_.-]{3,32}$", v) and "@" not in v and "." not in v.replace("_", ""):
                picked.append(v)
            elif "phone" in tt and (v.startswith("+") or re.match(r"^\d{10,15}$", v.replace(" ", "").replace("-", ""))):
                picked.append(v)
            elif "wallet" in tt and re.match(r"^(0x[a-fA-F0-9]{40}|(1|3|bc1)[A-HJ-NP-Z0-9]{25,62}|(L|M|Q|ltc1)[A-HJ-NP-Z0-9]{25,62})$", v):
                picked.append(v)
            elif "cidr" in tt and "/" in v and is_valid_ip(v.split("/")[0]):
                picked.append(v)
            elif "asn" in tt and re.match(r"^(AS|ASN)?\d{1,10}$", v, re.I):
                picked.append(v)
            elif "domain" in tt and is_valid_domain(v) and "@" not in v:
                picked.append(v)
        return picked[:20]

    def _cmd_stats(self, args):
        elapsed = datetime.datetime.now() - self.session_start
        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        elapsed_str = f"{hours}h {minutes}m {seconds}s"

        print(f"""
{Colors.BOLD}  Session Statistics{Colors.RESET}
  {'─'*40}
  {Colors.GREEN}Session started:{Colors.RESET}   {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}
  {Colors.GREEN}Uptime:{Colors.RESET}            {elapsed_str}
  {Colors.GREEN}Modules run:{Colors.RESET}       {self.modules_run_count}
  {Colors.GREEN}Targets scanned:{Colors.RESET}   {len(self.targets_scanned)}
  {Colors.GREEN}Results saved:{Colors.RESET}     {self.results_saved_count}
  {Colors.GREEN}Commands entered:{Colors.RESET}  {len(self.history)}
""")

    def start(self):
        print_banner()
        print_status(f"Loaded {len(MODULE_REGISTRY)} modules", "info")
        print_status("Type 'help' for available commands\n", "info")

        while True:
            try:
                raw = input(self._prompt()).lstrip("﻿").strip()
                if not raw:
                    continue
                self.history.append(raw)
                parts = raw.split()
                cmd = parts[0].lower()
                args = parts[1:]

                commands = {
                    "help": self._cmd_help,
                    "?": self._cmd_help,
                    "modules": self._cmd_modules,
                    "show": lambda a: self._cmd_modules(a) if a and a[0] == "modules" else (
                        self.current_module.show_options() if self.current_module and (not a or a[0] == "options")
                        else print_status("Nothing to show", "info")),
                    "search": self._cmd_search,
                    "use": self._cmd_use,
                    "info": lambda a: self.current_module.show_info() if self.current_module else print_status("No module selected", "error"),
                    "options": lambda a: self.current_module.show_options() if self.current_module else print_status("No module selected", "error"),
                    "set": self._cmd_set,
                    "run": self._cmd_run,
                    "exploit": self._cmd_run,
                    "execute": self._cmd_run,
                    "results": self._cmd_results,
                    "back": lambda a: self._deselect_module(),
                    "full_recon": self._cmd_full_recon,
                    "report": self._cmd_results,
                    "config": self._cmd_config,
                    "set_config": self._cmd_set_config,
                    "clear": lambda a: os.system("cls" if os.name == "nt" else "clear"),
                    "cls": lambda a: os.system("cls" if os.name == "nt" else "clear"),
                    "banner": lambda a: print_banner(),
                    "workspace": self._cmd_workspace,
                    "stats": self._cmd_stats,
                    "proxy": self._cmd_proxy,
                    "apikeys": self._cmd_apikeys,
                    "auth": self._cmd_auth,
                    "db": self._cmd_db,
                    "html": self._cmd_html,
                    "chain": self._cmd_chain,
                    "export": self._cmd_export,
                    "note": self._cmd_note,
                    "pivot": self._cmd_pivot,
                    "tag": self._cmd_tag,
                    "verify": self._cmd_verify,
                    "exit": lambda a: sys.exit(0),
                    "quit": lambda a: sys.exit(0),
                }

                if cmd in commands:
                    commands[cmd](args)
                else:
                    print_status(f"Unknown command: '{cmd}'. Type 'help' for commands.", "error")

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Use 'exit' or 'quit' to leave{Colors.RESET}")
            except EOFError:
                print()
                self._shutdown()
                sys.exit(0)
            except SystemExit:
                self._shutdown()
                print(f"\n{Colors.GREEN}[*] Goodbye!{Colors.RESET}")
                raise
            except Exception as e:
                print_status(f"Error: {e}", "error")

    def _deselect_module(self):
        self.current_module = None
        self.current_module_name = None
        print_status("Module deselected", "info")

    def _cmd_export(self, args):
        """Export session results for a target as a ZIP archive."""
        import zipfile
        target = args[0] if args else (sorted(self.targets_scanned)[0] if self.targets_scanned else None)
        if not target and not self.all_results:
            print_status("No results to export. Run modules first.", "warning")
            return
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", target or "session")
        output_dir = self.config.get("output_dir", "results")
        os.makedirs(output_dir, exist_ok=True)
        zip_path = os.path.join(output_dir, f"{safe}_{ts}.zip")
        count = 0
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for mod_name, results in self.all_results.items():
                fname = re.sub(r"[^A-Za-z0-9._-]", "_", mod_name) + ".json"
                zf.writestr(fname, json.dumps(results, indent=2, default=str, ensure_ascii=False))
                count += 1
            if target and os.path.isdir(output_dir):
                for root_dir, _, files in os.walk(output_dir):
                    for f in files:
                        fp = os.path.join(root_dir, f)
                        if fp == zip_path:
                            continue
                        if safe in f or (target and target in f):
                            arc = os.path.relpath(fp, output_dir)
                            try:
                                zf.write(fp, arc)
                                count += 1
                            except Exception:
                                pass
            summary = {
                "target": target, "exported_at": datetime.datetime.now().isoformat(),
                "modules": list(self.all_results.keys()), "targets": list(self.targets_scanned),
            }
            zf.writestr("SUMMARY.json", json.dumps(summary, indent=2, ensure_ascii=False))
        print_status(f"Exported {count} file(s) → {zip_path}", "success")

    def _cmd_note(self, args):
        """Add, list, or delete investigation notes for a target."""
        db = self._get_db()
        if not db:
            print_status("Database unavailable", "error")
            return
        try:
            db.conn.execute("""CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL, note TEXT NOT NULL, timestamp TEXT NOT NULL)""")
        except Exception:
            pass
        if not args:
            print_status("Usage: note <add|list|delete> <target|id> [text]", "info")
            return
        sub = args[0].lower()
        if sub == "add":
            if len(args) < 3:
                print_status("Usage: note add <target> <text>", "info")
                return
            target, text = args[1], " ".join(args[2:])
            db.conn.execute("INSERT INTO notes (target, note, timestamp) VALUES (?, ?, ?)",
                            (target, text, datetime.datetime.now().isoformat()))
            db.conn.commit()
            print_status(f"Note added for {target}", "success")
        elif sub == "list":
            target = args[1] if len(args) > 1 else None
            if target:
                rows = db.conn.execute(
                    "SELECT id, note, timestamp FROM notes WHERE target=? ORDER BY timestamp",
                    (target,)).fetchall()
                print(f"\n{Colors.BOLD}  Notes for {target}{Colors.RESET}")
                for r in rows:
                    print(f"    [{r[0]}] {Colors.DIM}{r[2][:19]}{Colors.RESET}  {r[1]}")
            else:
                rows = db.conn.execute(
                    "SELECT id, target, note, timestamp FROM notes ORDER BY timestamp").fetchall()
                print(f"\n{Colors.BOLD}  All Notes{Colors.RESET}")
                for r in rows:
                    print(f"    [{r[0]}] {Colors.CYAN}{r[1]}{Colors.RESET}  {Colors.DIM}{r[3][:19]}{Colors.RESET}  {r[2]}")
            if not rows:
                print_status("No notes found", "info")
                return
            print()
        elif sub == "delete":
            if len(args) < 2:
                print_status("Usage: note delete <id>", "info")
                return
            db.conn.execute("DELETE FROM notes WHERE id=?", (args[1],))
            db.conn.commit()
            print_status(f"Note {args[1]} deleted", "success")
        else:
            print_status("Usage: note <add|list|delete> ...", "info")

    def _cmd_pivot(self, args):
        """Run identity_pivot on a target directly (shorthand)."""
        if not args:
            print_status("Usage: pivot <target> [max_depth]", "info")
            return
        import time as _time
        target = args[0]
        start = _time.time()
        mod = self._load_module("identity_pivot")
        mod.set_option("TARGET", target)
        if len(args) > 1 and args[1].isdigit():
            mod.set_option("MAX_DEPTH", args[1])
        print_status(f"Running identity_pivot on {target}...", "info")
        try:
            if mod.run():
                self.last_results = mod.get_results()
                self.all_results[f"identity_pivot:{target}"] = self.last_results
                self.reporter.save_module_result(target, "identity_pivot", self.last_results)
                self.targets_scanned.add(target)
                self.results_saved_count += 1
                self._persist_to_db(target, "identity_pivot", self.last_results)
                print_status(f"Pivot complete in {_time.time() - start:.1f}s", "success")
        except KeyboardInterrupt:
            print_status("Pivot interrupted", "warning")
        except Exception as e:
            print_status(f"Pivot failed: {e}", "error")

    def _cmd_tag(self, args):
        """Tag targets with labels for grouping investigations."""
        db = self._get_db()
        if not db:
            print_status("Database unavailable", "error")
            return
        try:
            db.conn.execute("""CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL, label TEXT NOT NULL, timestamp TEXT NOT NULL,
                UNIQUE(target, label))""")
        except Exception:
            pass
        if not args:
            print_status("Usage: tag <add|list|remove> <target> [label]", "info")
            return
        sub = args[0].lower()
        if sub == "add":
            if len(args) < 3:
                print_status("Usage: tag add <target> <label>", "info")
                return
            target, label = args[1], args[2]
            db.conn.execute(
                "INSERT OR IGNORE INTO tags (target, label, timestamp) VALUES (?, ?, ?)",
                (target, label, datetime.datetime.now().isoformat()))
            db.conn.commit()
            print_status(f"Tagged {Colors.CYAN}{target}{Colors.RESET} → {Colors.GREEN}{label}{Colors.RESET}", "success")
        elif sub == "list":
            label = args[1] if len(args) > 1 else None
            if label:
                rows = db.conn.execute(
                    "SELECT target, timestamp FROM tags WHERE label=? ORDER BY target",
                    (label,)).fetchall()
                print(f"\n{Colors.BOLD}  Targets tagged '{label}'{Colors.RESET}")
                for r in rows:
                    print(f"    {Colors.CYAN}{r[0]}{Colors.RESET}  {Colors.DIM}{r[1][:19]}{Colors.RESET}")
            else:
                rows = db.conn.execute(
                    "SELECT label, COUNT(*) FROM tags GROUP BY label ORDER BY label").fetchall()
                print(f"\n{Colors.BOLD}  Tags{Colors.RESET}")
                for r in rows:
                    print(f"    {Colors.CYAN}{r[0]}{Colors.RESET}  ({r[1]} target(s))")
            if not rows:
                print_status("No tags defined", "info")
                return
            print()
        elif sub == "remove":
            if len(args) < 3:
                print_status("Usage: tag remove <target> <label>", "info")
                return
            db.conn.execute("DELETE FROM tags WHERE target=? AND label=?", (args[1], args[2]))
            db.conn.commit()
            print_status(f"Tag removed: {args[1]} / {args[2]}", "success")
        else:
            print_status("Usage: tag <add|list|remove> ...", "info")

    def _cmd_verify(self, args):
        """Test all configured API keys with a live call."""
        from core import http as _http
        if args and args[0] != "apis":
            print_status("Usage: verify apis", "info")
            return
        keys = self.config.get("api_keys", {})
        tests = {
            "shodan":         ("GET", "https://api.shodan.io/api-info?key={key}", {}, 200),
            "virustotal":     ("GET", "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                               {"x-apikey": "{key}"}, 200),
            "hunter":         ("GET", "https://api.hunter.io/v2/account?api_key={key}", {}, 200),
            "securitytrails": ("GET", "https://api.securitytrails.com/v1/ping?apikey={key}", {}, 200),
            "github":         ("GET", "https://api.github.com/rate_limit",
                               {"Authorization": "token {key}"}, 200),
            "abuseipdb":      ("GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90",
                               {"Key": "{key}", "Accept": "application/json"}, 200),
            "greynoise":      ("GET", "https://api.greynoise.io/v3/community/8.8.8.8",
                               {"key": "{key}"}, 200),
            "urlscan":        ("GET", "https://urlscan.io/user/quotas/",
                               {"API-Key": "{key}"}, 200),
            "otx":            ("GET", "https://otx.alienvault.com/api/v1/user/me",
                               {"X-OTX-API-KEY": "{key}"}, 200),
            "oathnet":        ("GET", "https://oathnet.org/api/service/ip-info?ip=8.8.8.8",
                               {"x-api-key": "{key}"}, 200),
        }
        print(f"\n{Colors.BOLD}  API Key Verification{Colors.RESET}\n  {'─'*45}")
        for name, val in keys.items():
            if not val:
                print(f"    {Colors.DIM}{name:<22} not set{Colors.RESET}")
                continue
            if name not in tests:
                print(f"    {Colors.DIM}{name:<22} (no test defined){Colors.RESET}")
                continue
            _, url_tmpl, hdrs_tmpl, expected = tests[name]
            url = url_tmpl.replace("{key}", val)
            hdrs = {k: v.replace("{key}", val) for k, v in hdrs_tmpl.items()}
            try:
                r = _http.get(url, timeout=8, headers=hdrs if hdrs else None)
                # Only a 2xx (or the endpoint's declared expected status) means the
                # key works. 401/403 — exactly what a bad/revoked key returns — must
                # read as invalid, not pass because it is "< 500".
                ok = r.status_code == expected or 200 <= r.status_code < 300
                dot = f"{Colors.GREEN}✓ valid{Colors.RESET}" if ok else f"{Colors.RED}✗ invalid (HTTP {r.status_code}){Colors.RESET}"
                print(f"    {name:<22} {dot}")
            except Exception as e:
                print(f"    {Colors.RED}{name:<22} error: {e}{Colors.RESET}")
        print()
