from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.reporter import Reporter


class FullWeb(BaseModule):
    name = "web/full_web"
    description = "Full web assessment - runs all web modules on a target with unified risk report"
    category = "web"
    target_type = "domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("HEAVY", "false", False, "Also run slow modules (dir_bruteforce, js_scanner, crawler)")
        self.add_option("PASSIVE", "false", False, "Passive only - skip intrusive modules (no attacks/brute-force)")
        self.add_option("SKIP", "", False, "Comma-separated module names to skip")

    def _module_list(self, heavy):
        from modules.web.headers import HeadersAnalysis
        from modules.web.ssl_analysis import SslAnalysis
        from modules.web.web_tech import WebTech
        from modules.web.robots_sitemap import RobotsSitemap
        from modules.web.waf_detect import WafDetect
        from modules.web.http_methods import HttpMethods
        from modules.web.security_txt import SecurityTxt
        from modules.web.api_discovery import ApiDiscovery
        from modules.web.backup_finder import BackupFinder
        from modules.web.cms_scan import CmsScan
        from modules.web.csp_analysis import CspAnalysis
        from modules.web.git_exposed import GitExposed
        from modules.web.favicon_hash import FaviconHash

        mods = [
            ("web/headers", HeadersAnalysis),
            ("web/ssl_analysis", SslAnalysis),
            ("web/web_tech", WebTech),
            ("web/waf_detect", WafDetect),
            ("web/http_methods", HttpMethods),
            ("web/csp_analysis", CspAnalysis),
            ("web/robots_sitemap", RobotsSitemap),
            ("web/security_txt", SecurityTxt),
            ("web/api_discovery", ApiDiscovery),
            ("web/git_exposed", GitExposed),
            ("web/backup_finder", BackupFinder),
            ("web/cms_scan", CmsScan),
            ("web/favicon_hash", FaviconHash),
        ]

        # Note: cors_check/xss_scan/sqli_scan/lfi_scan were removed from the
        # project (active scanners, dropped for false positives); do not re-add.
        if heavy:
            from modules.web.js_scanner import JsScanner
            from modules.web.dir_bruteforce import DirBruteforce
            from modules.web.crawler import Crawler
            from modules.web.origin_ip import OriginIp
            mods += [
                ("web/js_scanner", JsScanner),
                ("web/dir_bruteforce", DirBruteforce),
                ("web/crawler", Crawler),
                ("web/origin_ip", OriginIp),
            ]
        return mods

    def _assess(self, results):
        risks = []
        level = "LOW"

        git = results.get("web/git_exposed", {})
        if git.get("exposed"):
            # git_exposed nests the recovered .git data under results["git"]
            # as "commits"/"author_emails" (the old code read non-existent
            # top-level "commit_count"/"author_emails" and always showed 0).
            ginfo = git.get("git") or {}
            if ginfo:
                commits = ginfo.get("commits") or []
                emails = ginfo.get("author_emails") or []
                risks.append(f"CRITICAL: exposed .git ({len(commits)} commits, "
                             f"{len(emails)} emails leaked)")
            else:
                stats = git.get("stats", {}) or {}
                n = stats.get("verified_exposures",
                              len(git.get("exposures", []) or []))
                risks.append(f"CRITICAL: {n} exposed sensitive file(s)")
            level = "HIGH"

        backup = results.get("web/backup_finder", {})
        if backup.get("critical_count"):
            risks.append(f"CRITICAL: {backup['critical_count']} sensitive file(s) exposed")
            level = "HIGH"
        if backup.get("directory_listings"):
            risks.append(f"{len(backup['directory_listings'])} open directory listing(s)")

        headers = results.get("web/headers", {})
        missing = headers.get("missing_security_headers", [])
        if len(missing) >= 5:
            risks.append(f"{len(missing)} security headers missing")
            if level != "HIGH":
                level = "MEDIUM"

        csp = results.get("web/csp_analysis", {})
        if not csp.get("clickjacking_protected", True):
            risks.append("Clickjacking not prevented")
            if level == "LOW":
                level = "MEDIUM"
        if csp.get("csp_weaknesses"):
            risks.append(f"{len(csp['csp_weaknesses'])} CSP weakness(es)")

        methods = results.get("web/http_methods", {})
        if methods.get("risky_methods"):
            names = ", ".join(r["method"] for r in methods["risky_methods"])
            risks.append(f"Risky HTTP methods enabled: {names}")
            if level == "LOW":
                level = "MEDIUM"

        api = results.get("web/api_discovery", {})
        if api.get("graphql_introspection"):
            risks.append("GraphQL introspection enabled")

        return level, risks

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        heavy = self.get_option("HEAVY").lower() == "true"
        passive = self.get_option("PASSIVE").lower() == "true"
        skip = [s.strip() for s in (self.get_option("SKIP") or "").split(",") if s.strip()]

        print(f"\n{Colors.BOLD}{Colors.CYAN}")
        print("=" * 60)
        print("  FULL WEB ASSESSMENT")
        print(f"  Target: {target}")
        print("=" * 60)
        print(f"{Colors.RESET}\n")

        module_list = self._module_list(heavy)
        if passive:
            module_list = [(n, c) for (n, c) in module_list if not getattr(c, "intrusive", False)]
            print_status(f"PASSIVE mode: running {len(module_list)} non-intrusive module(s)", "info")
        results = {}
        completed = failed = 0
        total = len(module_list)

        for mod_name, mod_class in module_list:
            if mod_name in skip:
                print_status(f"Skipping {mod_name}", "warning")
                continue
            print(f"\n{Colors.BOLD}{Colors.YELLOW}{'─'*50}")
            print(f"  Running: {mod_name} [{completed + failed + 1}/{total}]")
            print(f"{'─'*50}{Colors.RESET}")
            try:
                mod = mod_class()
                mod.set_option("TARGET", target)
                if mod.run():
                    results[mod_name] = mod.get_results()
                    completed += 1
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                print_status(f"{mod_name} error: {e}", "error")

        level, risks = self._assess(results)

        reporter = Reporter()
        md_path, json_path = reporter.generate_full_report(target, results)
        html_path = reporter.generate_html_report(target, results)

        print(f"\n{Colors.BOLD}{Colors.GREEN}")
        print("=" * 60)
        print("  FULL WEB ASSESSMENT COMPLETE")
        print("=" * 60)
        print(f"{Colors.RESET}")
        print(f"  Target:    {target}")
        print(f"  Modules:   {completed}/{total} completed")

        risk_color = (Colors.RED if level == "HIGH" else
                      Colors.YELLOW if level == "MEDIUM" else Colors.GREEN)
        print(f"\n  Risk Level: {risk_color}{level}{Colors.RESET}")
        for r in risks:
            print(f"    {Colors.RED}!{Colors.RESET} {r}")
        if not risks:
            print(f"    {Colors.GREEN}No major issues detected{Colors.RESET}")

        print(f"\n  Reports:")
        print(f"    {Colors.DIM}{md_path}{Colors.RESET}")
        print(f"    {Colors.DIM}{html_path}{Colors.RESET}")
        print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}\n")

        self.results = {
            "target": target,
            "risk_level": level,
            "risk_findings": risks,
            "modules_completed": completed,
            "modules_failed": failed,
            "report_md": md_path,
            "report_json": json_path,
            "report_html": html_path,
            "module_results": results,
        }
        return True
