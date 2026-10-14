import time
from urllib.parse import quote_plus

from modules.github.base import GitHubModule
from core.utils import print_status, Colors


# ---------------------------------------------------------------------------
# Dork catalog
# {target}      -> TARGET option (domain / org name / keyword)
# {domain_part} -> first label of a domain (e.g. "example" for "example.com")
# ---------------------------------------------------------------------------
DORK_TEMPLATES = {
    "secrets": [
        '"{target}" "api_key"',
        '"{target}" "api_secret"',
        '"{target}" "aws_access_key"',
        '"{target}" "AKIA" extension:env',
        '"{target}" "BEGIN RSA PRIVATE KEY"',
        '"{target}" extension:pem private',
        '"{target}" filename:credentials',
        '"{target}" filename:.env',
        '"{target}" filename:config.json password',
        '"{target}" filename:.npmrc _authToken',
        '"{target}" filename:.docker/config.json auth',
        '"{target}" filename:ftpconfig',
    ],
    "credentials": [
        '"{target}" password',
        '"{target}" "DB_PASSWORD"',
        '"{target}" "SLACK_TOKEN"',
        '"{target}" "SENDGRID_API_KEY"',
        '"{target}" "mongodb+srv://" "{target}"',
        '"{target}" "mysql://" OR "postgres://"',
    ],
    "configs": [
        '"{target}" filename:.htpasswd',
        '"{target}" filename:wp-config.php',
        '"{target}" filename:settings.py SECRET_KEY',
        '"{target}" filename:application.yml password',
        '"{target}" filename:prod.exs',
        '"{target}" filename:dump.sql',
    ],
    "emails": [
        '"@{domain_part}" extension:env',
        '"@{domain_part}" filename:config',
        '"@{domain_part}" filename:settings',
    ],
    "subdomains": [
        '"{target}" filename:nginx.conf',
        '"{target}" filename:httpd.conf',
        '"{target}" filename:resolv.conf',
    ],
    "endpoints": [
        '"{target}" filename:swagger.yaml',
        '"{target}" filename:openapi.yaml',
        '"{target}" filename:postman_collection.json',
    ],
    "cloud": [
        '"{target}" filename:terraform.tfvars',
        '"{target}" filename:cloudformation',
        '"{target}" filename:docker-compose.yml',
    ],
}


class Dorks(GitHubModule):
    """Advanced GitHub dork search for OSINT.

    Runs a curated catalog of search queries against GitHub's code search API
    to surface leaked secrets, emails, config files, and sensitive patterns
    tied to a target domain / organization / keyword.
    """

    name = "github/dorks"
    description = ("Advanced GitHub dork search - finds leaked secrets, emails, "
                   "subdomains and configs for a target domain or organization")
    target_type = "domain/keyword"

    # Code search = 10 req/min authenticated -> ~6s/query to stay under the cap
    SEARCH_DELAY = 6.5

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Domain (example.com), organization name, or keyword")
        self.add_option("CATEGORIES", "secrets,credentials,configs,emails", False,
                        "Comma-separated subset of catalog keys, or 'all'")
        self.add_option("MAX_PER_DORK", "3", False,
                        "Max results to fetch per individual dork")
        self.add_option("DRY_RUN", "false", False,
                        "If true, only generate / print dork URLs (no API calls)")

    # -------------------------------------------------------------- helpers --

    @staticmethod
    def _domain_part(target):
        """First label of a domain. 'example.com' -> 'example'. Keyword passthrough."""
        if "." in target:
            return target.split(".")[0]
        return target

    @staticmethod
    def _build_search_url(query):
        """Human-readable web URL for a dork query (used in DRY_RUN output)."""
        return f"https://github.com/search?q={quote_plus(query)}&type=code"

    def _select_categories(self, raw):
        raw = (raw or "").strip().lower()
        if raw in ("", "all"):
            return list(DORK_TEMPLATES.keys())
        wanted = [c.strip() for c in raw.split(",") if c.strip()]
        valid, bad = [], []
        for c in wanted:
            (valid if c in DORK_TEMPLATES else bad).append(c)
        for b in bad:
            print_status(f"Unknown category '{b}' - ignored", "warning")
        return valid

    def _format_dorks(self, categories, target, domain_part):
        """Expand all dork templates for the selected categories.

        Returns a list of tuples: (category, template, formatted_query).
        """
        formatted = []
        for cat in categories:
            for tmpl in DORK_TEMPLATES[cat]:
                try:
                    query = tmpl.format(target=target, domain_part=domain_part)
                except (KeyError, IndexError):
                    continue
                formatted.append((cat, tmpl, query))
        return formatted

    @staticmethod
    def _parse_item(item, query):
        repo = item.get("repository", {}) or {}
        match_lines = []
        for tm in item.get("text_matches", []) or []:
            frag = tm.get("fragment", "") or ""
            for ln in frag.splitlines():
                ln = ln.strip()
                if ln and ln not in match_lines:
                    match_lines.append(ln)
                if len(match_lines) >= 5:
                    break
            if len(match_lines) >= 5:
                break
        return {
            "query": query,
            "repo": repo.get("full_name", ""),
            "path": item.get("path", ""),
            "html_url": item.get("html_url", ""),
            "match_lines": match_lines,
            "stars": repo.get("stargazers_count", 0),
        }

    def _execute_dork(self, query, max_per_dork):
        """Run a single dork via the GitHub client's session.

        Returns a (status, items) tuple where status is one of:
            'ok', 'rate_limited', 'invalid', 'error'.
        """
        url = f"{self.client.BASE_API}/search/code"
        params = {"q": query, "per_page": max(1, min(max_per_dork, 100))}
        # Opt in to text match fragments so match_lines gets populated
        headers = dict(self.client.session.headers)
        headers["Accept"] = "application/vnd.github.v3.text-match+json"
        try:
            resp = self.client.session.get(
                url, params=params, headers=headers,
                timeout=self.client.timeout,
            )
        except Exception as exc:
            print_status(f"API error: {exc}", "error")
            return "error", []

        # Keep the shared client's rate counters in sync
        try:
            self.client._update_rate_limit(resp)
        except Exception:
            pass

        if resp.status_code == 200:
            data = resp.json() if resp.content else {}
            items = [self._parse_item(it, query)
                     for it in (data.get("items", []) or [])[:max_per_dork]]
            return "ok", items
        if resp.status_code == 403:
            body = (resp.text or "").lower()
            if "rate limit" in body or "secondary" in body or "abuse" in body:
                return "rate_limited", []
            return "error", []
        if resp.status_code == 422:
            return "invalid", []
        return "error", []

    # ---------------------------------------------------------------- run --

    def run(self):
        if not self.validate():
            return False

        self._init_client()
        target = (self.get_option("TARGET") or "").strip()
        categories_raw = self.get_option("CATEGORIES") or ""
        try:
            max_per_dork = max(1, int(self.get_option("MAX_PER_DORK") or 3))
        except (ValueError, TypeError):
            max_per_dork = 3
        dry_run = str(self.get_option("DRY_RUN") or "false").strip().lower() in (
            "true", "yes", "1", "on",
        )

        # Authentication is mandatory for live code search
        if not self.client.authenticated and not dry_run:
            print_status("GitHub token required for code search", "error")
            print_status("Set api_keys.github in config, or run with DRY_RUN=true", "warning")
            self.results = {
                "target": target,
                "error": "GitHub token required for code search",
                "categories_run": [],
                "dork_count": 0,
                "findings": {},
                "dork_urls_generated": [],
                "total_matches": 0,
                "stats": {"dorks_run": 0, "duration_sec": 0, "rate_limit_hit": False},
                "warnings": [],
            }
            return False

        categories = self._select_categories(categories_raw)
        if not categories:
            print_status("No valid categories selected. Available: "
                         + ", ".join(DORK_TEMPLATES.keys()), "error")
            return False

        domain_part = self._domain_part(target)
        dorks = self._format_dorks(categories, target, domain_part)
        if not dorks:
            print_status("No dork queries generated.", "error")
            return False

        print_status(
            f"GitHub dorks for '{target}' (domain_part='{domain_part}')", "info")
        print_status(
            f"Categories: {', '.join(categories)} | "
            f"Dorks: {len(dorks)} | Max/dork: {max_per_dork} | "
            f"DRY_RUN={dry_run}", "info")

        # ---------------------- DRY_RUN: just emit URLs ---------------------
        if dry_run:
            dork_urls = []
            print(f"\n{Colors.BOLD}  Generated dork queries (DRY_RUN):{Colors.RESET}")
            for i, (cat, _tmpl, query) in enumerate(dorks, 1):
                web_url = self._build_search_url(query)
                dork_urls.append({
                    "category": cat, "query": query, "search_url": web_url,
                })
                short = query if len(query) <= 70 else (query[:67] + "...")
                print(f"  {Colors.DIM}[{i}/{len(dorks)}]{Colors.RESET} "
                      f"{Colors.CYAN}{cat}{Colors.RESET}: {short}")
                print(f"      {Colors.DIM}{web_url}{Colors.RESET}")
            print()
            self.results = {
                "target": target,
                "categories_run": categories,
                "dork_count": len(dorks),
                "findings": {cat: [] for cat in categories},
                "dork_urls_generated": dork_urls,
                "total_matches": 0,
                "stats": {"dorks_run": 0, "duration_sec": 0, "rate_limit_hit": False},
                "warnings": [],
            }
            return True

        # ---------------------- Live execution -----------------------------
        findings = {cat: [] for cat in categories}
        seen_urls = set()
        warnings = []
        rate_limit_hit = False
        rate_retry_used = False
        dorks_run = 0
        start_ts = time.time()

        for idx, (cat, _tmpl, query) in enumerate(dorks, 1):
            short = query if len(query) <= 70 else (query[:67] + "...")
            print(f"  {Colors.DIM}[{idx}/{len(dorks)}]{Colors.RESET} "
                  f"{Colors.CYAN}{cat}{Colors.RESET}: {short}")

            status, items = self._execute_dork(query, max_per_dork)
            dorks_run += 1

            # 403 rate limit -> sleep + retry once, otherwise give up gracefully
            if status == "rate_limited":
                rate_limit_hit = True
                if not rate_retry_used:
                    rate_retry_used = True
                    print_status("[WARN] 403 rate limit - sleeping 60s then "
                                 "retrying once", "warning")
                    time.sleep(60)
                    status, items = self._execute_dork(query, max_per_dork)
                if status == "rate_limited":
                    print_status("[WARN] still rate limited - stopping remaining "
                                 "dorks", "warning")
                    warnings.append(f"rate_limited:{query}")
                    break

            if status == "invalid":
                print_status(f"[WARN] 422 invalid query - skipping: {short}",
                             "warning")
                warnings.append(f"invalid:{query}")
                time.sleep(self.SEARCH_DELAY)
                continue

            if status == "error":
                print_status(f"[WARN] API error - skipping: {short}", "warning")
                warnings.append(f"error:{query}")
                time.sleep(self.SEARCH_DELAY)
                continue

            # status == "ok" -> dedupe by html_url, record new findings
            new_items = []
            for it in items:
                url = it.get("html_url") or ""
                if url and url in seen_urls:
                    continue
                if url:
                    seen_urls.add(url)
                new_items.append(it)

            if new_items:
                findings[cat].extend(new_items)
                if cat in ("secrets", "credentials"):
                    print(f"      {Colors.RED}{Colors.BOLD}[SECRET FOUND]"
                          f"{Colors.RESET} {len(new_items)} hit(s) in {cat}")
                else:
                    print(f"      {Colors.GREEN}[+]{Colors.RESET} "
                          f"{len(new_items)} new hit(s)")
                for it in new_items[:3]:
                    print(f"        {Colors.DIM}{it['repo']}/{it['path']}"
                          f"{Colors.RESET}")

            # Pace between dorks (skip after the final one)
            if idx < len(dorks):
                time.sleep(self.SEARCH_DELAY)

        duration = round(time.time() - start_ts, 2)
        total_matches = sum(len(v) for v in findings.values())

        # ------------------------------- summary ---------------------------
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}")
        print(f"  GitHub Dork Results: {target}")
        print(f"{'=' * 60}{Colors.RESET}")
        print(f"  {Colors.GREEN}Dorks run:{Colors.RESET}       "
              f"{dorks_run}/{len(dorks)}")
        print(f"  {Colors.GREEN}Total findings:{Colors.RESET}  {total_matches}")
        print(f"  {Colors.GREEN}Duration:{Colors.RESET}        {duration}s")

        for cat in categories:
            cat_hits = findings.get(cat, [])
            if not cat_hits:
                continue
            color = Colors.RED if cat in ("secrets", "credentials") else Colors.YELLOW
            print(f"\n  {color}{Colors.BOLD}{cat.upper()} "
                  f"({len(cat_hits)} hits):{Colors.RESET}")
            for item in cat_hits[:5]:
                print(f"    {color}-{Colors.RESET} "
                      f"{item['repo']}/{item['path']}")
            if len(cat_hits) > 5:
                print(f"    ... and {len(cat_hits) - 5} more")

        # Top 3 repos by finding count
        repo_counts = {}
        for cat_hits in findings.values():
            for it in cat_hits:
                r = it.get("repo") or ""
                if r:
                    repo_counts[r] = repo_counts.get(r, 0) + 1
        top_repos = sorted(repo_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_repos:
            print(f"\n  {Colors.BOLD}Top repos:{Colors.RESET}")
            for repo, count in top_repos:
                print(f"    {Colors.CYAN}-{Colors.RESET} {repo} "
                      f"({count} finding{'s' if count != 1 else ''})")

        if rate_limit_hit:
            print(f"\n  {Colors.YELLOW}[!] Rate limit was hit during this run "
                  f"- results may be partial{Colors.RESET}")
        if warnings:
            print(f"  {Colors.YELLOW}[!] {len(warnings)} warning(s) during "
                  f"execution{Colors.RESET}")

        print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")

        self.results = {
            "target": target,
            "categories_run": categories,
            "dork_count": len(dorks),
            "findings": findings,
            "dork_urls_generated": [],
            "total_matches": total_matches,
            "stats": {
                "dorks_run": dorks_run,
                "duration_sec": duration,
                "rate_limit_hit": rate_limit_hit,
            },
            "warnings": warnings,
        }
        return True
