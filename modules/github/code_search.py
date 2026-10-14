import time
from modules.github.base import GitHubModule
from core.utils import print_status, Colors


class CodeSearch(GitHubModule):
    name = "github/code_search"
    description = "GitHub Code Search for secrets, emails, credentials, and mentions in user code"

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username")
        self.add_option("SEARCH_QUERIES", "", False,
                        "Additional custom search queries, comma-separated")
        self.add_option("MAX_RESULTS", "50", False, "Maximum results per query")

    def _search_code(self, query, max_results):
        """Run a single code search query and return items."""
        params = {"q": query, "per_page": min(max_results, 100)}
        data = self.client.get("/search/code", params=params)
        if data is None:
            return [], 0
        items = []
        for item in data.get("items", []):
            items.append({
                "name": item.get("name", ""),
                "path": item.get("path", ""),
                "repository": item.get("repository", {}).get("full_name", ""),
                "html_url": item.get("html_url", ""),
                "score": item.get("score", 0),
            })
        total = data.get("total_count", 0)
        return items, total

    def run(self):
        if not self.validate():
            return False

        self._init_client()
        target = self.get_option("TARGET")
        max_results = int(self.get_option("MAX_RESULTS") or 50)
        custom_queries_raw = self.get_option("SEARCH_QUERIES") or ""

        parsed = self.parse_github_target(target)
        username = parsed["owner"]

        # Code search requires authentication
        if not self.client.authenticated:
            print_status("Code search requires a GitHub API token.", "error")
            print_status("Set api_keys.github in config to enable code search.", "warning")
            self.results = {
                "target": username,
                "error": "Not authenticated. Code search requires a GitHub token.",
                "code_matches": {},
                "files_with_secrets": [],
                "repos_with_matches": [],
                "total_matches": 0,
            }
            return True

        print_status(f"Starting code search for user: {username}", "info")

        # Define search categories
        search_categories = {
            "emails": [
                f'"@gmail.com" user:{username}',
                f'"@yahoo.com" user:{username}',
                f'"@hotmail.com" user:{username}',
                f'"@outlook.com" user:{username}',
                f'"@protonmail.com" user:{username}',
            ],
            "secrets": [
                f'"password" user:{username}',
                f'"api_key" user:{username}',
                f'"secret" user:{username}',
                f'"token" user:{username}',
                f'"private_key" user:{username}',
            ],
            "config_files": [
                f'filename:.env user:{username}',
                f'filename:config user:{username}',
                f'filename:.htpasswd user:{username}',
                f'filename:credentials user:{username}',
            ],
            "credentials": [
                f'"DB_PASSWORD" user:{username}',
                f'"AWS_ACCESS" user:{username}',
                f'"AZURE_KEY" user:{username}',
                f'"DATABASE_URL" user:{username}',
                f'"SMTP_PASSWORD" user:{username}',
            ],
        }

        code_matches = {}
        files_with_secrets = []
        repos_seen = set()
        total_matches = 0
        search_delay = 2  # GitHub search rate limit: ~10 req/min

        for category, queries in search_categories.items():
            print_status(f"Searching category: {category}", "info")
            category_results = []

            for query in queries:
                time.sleep(search_delay)
                items, count = self._search_code(query, max_results)
                if items:
                    print_status(f"  Query '{query}': {count} results", "success")
                    for item in items:
                        item["query"] = query
                        item["category"] = category
                        category_results.append(item)
                        repos_seen.add(item["repository"])

                        # Track files with secret-like content
                        if category in ("secrets", "credentials", "config_files"):
                            files_with_secrets.append({
                                "file": item["path"],
                                "repo": item["repository"],
                                "category": category,
                                "query": query,
                                "url": item["html_url"],
                            })

                    total_matches += len(items)

            code_matches[category] = category_results

        # Custom queries
        if custom_queries_raw.strip():
            custom_queries = [q.strip() for q in custom_queries_raw.split(",")
                              if q.strip()]
            print_status(f"Running {len(custom_queries)} custom queries...", "info")
            custom_results = []
            for query in custom_queries:
                full_query = f'{query} user:{username}'
                time.sleep(search_delay)
                items, count = self._search_code(full_query, max_results)
                if items:
                    print_status(f"  Custom query '{query}': {count} results", "success")
                    for item in items:
                        item["query"] = full_query
                        item["category"] = "custom"
                        custom_results.append(item)
                        repos_seen.add(item["repository"])
                    total_matches += len(items)
            code_matches["custom"] = custom_results

        # Domain search across all of GitHub
        # Try to find domain from user profile
        profile = self.client.get(f"/users/{username}")
        domain = None
        if profile:
            blog = profile.get("blog", "") or ""
            if blog:
                # Extract domain from blog URL
                blog = blog.replace("https://", "").replace("http://", "")
                blog = blog.strip("/").split("/")[0]
                if "." in blog:
                    domain = blog

        domain_results = []
        if domain:
            print_status(f"Searching for domain '{domain}' across GitHub...", "info")
            time.sleep(search_delay)
            items, count = self._search_code(f'"{domain}"', max_results)
            if items:
                print_status(f"  Domain search: {count} results for {domain}", "success")
                for item in items:
                    item["query"] = f'"{domain}"'
                    item["category"] = "domain"
                    domain_results.append(item)
                    repos_seen.add(item["repository"])
                total_matches += len(items)
            code_matches["domain"] = domain_results

        repos_with_matches = sorted(repos_seen)

        # ── Summary ──────────────────────────────────────────────
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*55}")
        print(f"  Code Search Results: {username}")
        print(f"{'='*55}{Colors.RESET}")
        print(f"  {Colors.GREEN}Total matches:{Colors.RESET}         {total_matches}")
        print(f"  {Colors.GREEN}Repos with matches:{Colors.RESET}    {len(repos_with_matches)}")
        print(f"  {Colors.GREEN}Files with secrets:{Colors.RESET}    {len(files_with_secrets)}")

        for category, results in code_matches.items():
            if results:
                print(f"\n  {Colors.BOLD}{category.upper()} ({len(results)} matches):{Colors.RESET}")
                for r in results[:5]:
                    print(f"    {Colors.YELLOW}-{Colors.RESET} {r['repository']}/{r['path']}")
                if len(results) > 5:
                    print(f"    ... and {len(results) - 5} more")

        if files_with_secrets:
            print(f"\n  {Colors.YELLOW}{Colors.BOLD}[~] Keyword matches (UNVERIFIED - "
                  f"a file merely containing the term; review manually):{Colors.RESET}")
            for s in files_with_secrets[:10]:
                print(f"    {Colors.YELLOW}-{Colors.RESET} {s['repo']}/{s['file']} ({s['category']})")
            if len(files_with_secrets) > 10:
                print(f"    ... and {len(files_with_secrets) - 10} more")

        print(f"\n{Colors.CYAN}{'='*55}{Colors.RESET}\n")

        self.results = {
            "target": username,
            "code_matches": code_matches,
            # Keyword-only matches (file contains the term / filename pattern).
            # NOT validated secrets - consumers must treat as leads to review,
            # not confirmed credentials, and must not drive a risk verdict.
            "files_with_secrets": files_with_secrets,
            "files_with_secrets_unverified": True,
            "repos_with_matches": repos_with_matches,
            "total_matches": total_matches,
            "domain_searched": domain,
        }
        return True
