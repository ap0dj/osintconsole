import re
from modules.github.base import GitHubModule
from core.utils import print_status


class RepoAnalysis(GitHubModule):
    name = "github/repo_analysis"
    description = "Deep repository analysis - languages, contributors, sensitive files, and metadata"
    target_type = "username/org"

    SENSITIVE_FILES = [
        ".env",
        "config.yml",
        "config.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "Dockerfile",
        ".github/workflows",
    ]

    # Files whose MERE EXISTENCE in a public repo is normal and not a finding
    # (every containerized/CI repo has these). Reported as informational only -
    # they must NOT drive the risk verdict. Only high-signal files like .env
    # (secret-bearing) count as real signal.
    INFO_ONLY_FILES = {
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".github/workflows",
    }

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username or organization")
        self.add_option("MAX_REPOS", "10", False, "Maximum number of repos to analyze")
        self.add_option("CHECK_FILES", "true", False, "Check for sensitive files (true/false)")

    def _analyze_repo(self, owner, repo_name):
        """Fetch detailed info for a single repository."""
        # Contributors
        contributors = []
        contribs_data = self.client.paginate(
            f"/repos/{owner}/{repo_name}/contributors", max_pages=2
        )
        if contribs_data:
            for c in contribs_data:
                contributors.append({
                    "login": c.get("login", ""),
                    "contributions": c.get("contributions", 0),
                    "html_url": c.get("html_url", ""),
                })

        # Language breakdown
        languages = self.client.get(f"/repos/{owner}/{repo_name}/languages") or {}

        return contributors, languages

    def _check_sensitive_files(self, owner, repo_name):
        """Check if sensitive files or directories exist in the repo root."""
        found = []
        contents = self.client.get(f"/repos/{owner}/{repo_name}/contents/")
        if not contents or not isinstance(contents, list):
            return found

        root_names = {item.get("name", ""): item.get("type", "") for item in contents}

        for sensitive in self.SENSITIVE_FILES:
            if "/" in sensitive:
                # Directory path like .github/workflows - check directory exists first
                top_dir = sensitive.split("/")[0]
                if top_dir in root_names and root_names[top_dir] == "dir":
                    subpath = sensitive
                    sub_contents = self.client.get(
                        f"/repos/{owner}/{repo_name}/contents/{subpath}"
                    )
                    if sub_contents is not None:
                        found.append({
                            "file": sensitive,
                            "repo": f"{owner}/{repo_name}",
                            "type": "directory" if isinstance(sub_contents, list) else "file",
                            "informational": sensitive in self.INFO_ONLY_FILES,
                        })
            else:
                if sensitive in root_names:
                    found.append({
                        "file": sensitive,
                        "repo": f"{owner}/{repo_name}",
                        "type": root_names[sensitive],
                        "informational": sensitive in self.INFO_ONLY_FILES,
                    })

        return found

    def run(self):
        if not self.validate():
            return False

        self._init_client()
        target = self.get_option("TARGET")
        max_repos = int(self.get_option("MAX_REPOS") or 10)
        check_files = (self.get_option("CHECK_FILES") or "true").lower() == "true"

        parsed = self.parse_github_target(target)
        owner = parsed["owner"]

        print_status(f"Analyzing repositories for '{owner}'", "info")

        # Fetch repos sorted by last update
        repos_data = self.client.paginate(
            f"/users/{owner}/repos",
            params={"sort": "updated", "direction": "desc"},
            max_pages=max(1, (max_repos // 100) + 1),
        )

        if not repos_data:
            print_status(f"No public repositories found for '{owner}'", "warning")
            self.results = {
                "target": owner,
                "repos": [],
                "all_contributors": [],
                "all_languages": {},
                "sensitive_files_found": [],
                "total_stars": 0,
                "total_forks": 0,
            }
            return True

        repos_data = repos_data[:max_repos]
        print_status(f"Found {len(repos_data)} repositories to analyze", "info")

        repos = []
        all_contributors = {}
        all_languages = {}
        sensitive_files_found = []
        total_stars = 0
        total_forks = 0

        for i, repo_raw in enumerate(repos_data, 1):
            repo_name = repo_raw.get("name", "")
            full_name = repo_raw.get("full_name", f"{owner}/{repo_name}")
            stars = repo_raw.get("stargazers_count", 0)
            forks = repo_raw.get("forks_count", 0)

            print_status(
                f"[{i}/{len(repos_data)}] Analyzing {full_name} "
                f"({stars} stars, {forks} forks)", "info"
            )

            total_stars += stars
            total_forks += forks

            # Get contributors and languages for this repo
            contributors, languages = self._analyze_repo(owner, repo_name)

            # Merge contributors
            for contrib in contributors:
                login = contrib["login"]
                if login in all_contributors:
                    all_contributors[login]["contributions"] += contrib["contributions"]
                else:
                    all_contributors[login] = {
                        "login": login,
                        "contributions": contrib["contributions"],
                        "html_url": contrib["html_url"],
                    }

            # Merge languages
            for lang, byte_count in languages.items():
                all_languages[lang] = all_languages.get(lang, 0) + byte_count

            # Check for sensitive files
            repo_sensitive = []
            if check_files:
                repo_sensitive = self._check_sensitive_files(owner, repo_name)
                sensitive_files_found.extend(repo_sensitive)
                if repo_sensitive:
                    for sf in repo_sensitive:
                        print_status(
                            f"  Sensitive file found: {sf['file']} in {full_name}",
                            "warning",
                        )

            repo_info = {
                "name": repo_name,
                "full_name": full_name,
                "html_url": repo_raw.get("html_url", ""),
                "description": repo_raw.get("description", ""),
                "language": repo_raw.get("language", ""),
                "languages": languages,
                "topics": repo_raw.get("topics", []),
                "stars": stars,
                "forks": forks,
                "size_kb": repo_raw.get("size", 0),
                "license": (repo_raw.get("license") or {}).get("spdx_id", "None"),
                "default_branch": repo_raw.get("default_branch", ""),
                "created_at": repo_raw.get("created_at", ""),
                "updated_at": repo_raw.get("updated_at", ""),
                "pushed_at": repo_raw.get("pushed_at", ""),
                "is_fork": repo_raw.get("fork", False),
                "is_archived": repo_raw.get("archived", False),
                "contributors": contributors,
                "contributor_count": len(contributors),
                "sensitive_files": repo_sensitive,
            }
            repos.append(repo_info)

            print_status(
                f"  {len(contributors)} contributors, "
                f"{len(languages)} languages, "
                f"{len(repo_sensitive)} sensitive files", "info"
            )

        # Sort contributors by total contributions
        sorted_contributors = sorted(
            all_contributors.values(),
            key=lambda c: c["contributions"],
            reverse=True,
        )

        # Sort languages by total bytes
        sorted_languages = dict(
            sorted(all_languages.items(), key=lambda x: x[1], reverse=True)
        )

        # Print summary
        print_status(f"Analysis complete for {owner}", "success")
        print_status(f"  Repos analyzed: {len(repos)}", "info")
        print_status(f"  Total stars: {total_stars}", "info")
        print_status(f"  Total forks: {total_forks}", "info")
        print_status(f"  Unique contributors: {len(sorted_contributors)}", "info")
        print_status(f"  Languages: {', '.join(list(sorted_languages.keys())[:10])}", "info")
        if sensitive_files_found:
            print_status(
                f"  Sensitive files found: {len(sensitive_files_found)}", "warning"
            )

        # High-signal = secret-bearing files (e.g. .env); the rest
        # (Dockerfile/compose/workflows) are informational infra files.
        high_signal_files = [f for f in sensitive_files_found
                             if not f.get("informational")]

        self.results = {
            "target": owner,
            "repos": repos,
            "all_contributors": sorted_contributors,
            "all_languages": sorted_languages,
            "sensitive_files_found": sensitive_files_found,
            "high_signal_files": high_signal_files,
            "total_stars": total_stars,
            "total_forks": total_forks,
            "repos_analyzed": len(repos),
        }
        return True
