import re
from modules.github.base import GitHubModule
from core.utils import print_status, print_progress


class CommitEmails(GitHubModule):
    """Extract real emails from GitHub commits using the .patch trick.

    Adding .patch to any GitHub commit URL reveals the actual email
    configured in git (From: / Author: / Committer: headers), which
    is often the user's real email rather than the GitHub noreply address.
    """

    name = "github/commit_emails"
    description = "Extract real emails from commit patches (.patch trick) and commit API data"
    target_type = "username/owner/repo"

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username or owner/repo")
        self.add_option("MAX_REPOS", "5", False, "Maximum repos to check (username target)")
        self.add_option("MAX_COMMITS", "20", False, "Maximum commits to check per repo")

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _get_repos_for_user(self, username, max_repos):
        """Fetch public repos for a user, sorted by most recently pushed."""
        repos = self.client.paginate(
            f"/users/{username}/repos",
            params={"sort": "pushed", "direction": "desc"},
            max_pages=1,
        )
        if not repos:
            print_status(f"No public repos found for '{username}'", "warning")
            return []
        # Limit and filter forks for better signal
        repos = [r for r in repos if not r.get("fork")][:max_repos]
        if not repos:
            # Fall back to including forks if everything is a fork
            repos = self.client.paginate(
                f"/users/{username}/repos",
                params={"sort": "pushed"},
                max_pages=1,
            )[:max_repos]
        return repos

    def _extract_emails_from_patch(self, patch_text):
        """Parse From:, Author:, and Committer: headers from a .patch file."""
        emails = {}
        if not patch_text:
            return emails

        from_matches = re.findall(
            r'^From:\s*(.+?)\s*<([^>]+)>', patch_text, re.MULTILINE
        )
        for display_name, email in from_matches:
            emails[email.lower()] = display_name.strip()

        author_matches = re.findall(
            r'^Author:\s*(.+?)\s*<([^>]+)>', patch_text, re.MULTILINE
        )
        for display_name, email in author_matches:
            emails[email.lower()] = display_name.strip()

        committer_matches = re.findall(
            r'^Committer:\s*(.+?)\s*<([^>]+)>', patch_text, re.MULTILINE
        )
        for display_name, email in committer_matches:
            emails[email.lower()] = display_name.strip()

        return emails

    def _process_repo(self, owner, repo, max_commits, target_username):
        """Check commits in a single repo and return discovered emails."""
        full_name = f"{owner}/{repo}"
        repo_emails = {}  # email -> {name, sources: []}

        # --- Step 1: API commits -------------------------------------------
        params = {"per_page": min(max_commits, 100)}
        if target_username:
            params["author"] = target_username

        commits = self.client.get(
            f"/repos/{owner}/{repo}/commits", params=params
        )
        if not commits or not isinstance(commits, list):
            return repo_emails, 0

        commits = commits[:max_commits]
        checked = 0

        for idx, commit_obj in enumerate(commits):
            sha = commit_obj.get("sha", "")
            if not sha:
                continue
            checked += 1

            # Emails from the API commit object
            commit_data = commit_obj.get("commit", {})
            for role in ("author", "committer"):
                person = commit_data.get(role, {})
                email = (person.get("email") or "").lower()
                name = person.get("name", "")
                if email and not email.endswith("@users.noreply.github.com") \
                        and email != "noreply@github.com":
                    if email not in repo_emails:
                        repo_emails[email] = {"name": name, "sources": []}
                    repo_emails[email]["sources"].append(
                        f"{full_name}@{sha[:7]} (API {role})"
                    )

            # --- Step 2: .patch trick --------------------------------------
            patch_url = f"{self.client.BASE_WEB}/{owner}/{repo}/commit/{sha}.patch"
            patch_text = self.client.get_raw(patch_url)
            patch_emails = self._extract_emails_from_patch(patch_text)

            for email, display_name in patch_emails.items():
                if email.endswith("@users.noreply.github.com") \
                        or email == "noreply@github.com":
                    continue
                if email not in repo_emails:
                    repo_emails[email] = {"name": display_name, "sources": []}
                repo_emails[email]["sources"].append(
                    f"{full_name}@{sha[:7]} (.patch)"
                )

        return repo_emails, checked

    # -----------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------

    def run(self):
        if not self.validate():
            return False

        self._init_client()

        target = self.get_option("TARGET")
        max_repos = int(self.get_option("MAX_REPOS") or 5)
        max_commits = int(self.get_option("MAX_COMMITS") or 20)
        parsed = self.parse_github_target(target)

        print_status(f"Starting commit-email extraction for '{target}'", "info")

        # Determine which repos to scan
        repos_to_scan = []  # list of (owner, repo_name)
        target_username = None

        if parsed["type"] == "repo":
            repos_to_scan.append((parsed["owner"], parsed["repo"]))
            print_status(f"Targeting single repo: {parsed['owner']}/{parsed['repo']}", "info")
        else:
            target_username = parsed["owner"]
            print_status(f"Fetching repos for user '{target_username}'...", "info")
            user_repos = self._get_repos_for_user(target_username, max_repos)
            for r in user_repos:
                full = r.get("full_name", "")
                if "/" in full:
                    o, n = full.split("/", 1)
                    repos_to_scan.append((o, n))
            print_status(f"Will scan {len(repos_to_scan)} repo(s)", "info")

        # Collect emails across repos
        all_emails = {}       # email -> {name, sources}
        emails_by_repo = {}   # full_name -> [emails]
        total_checked = 0

        for i, (owner, repo_name) in enumerate(repos_to_scan):
            full_name = f"{owner}/{repo_name}"
            print_status(f"Scanning [{i+1}/{len(repos_to_scan)}] {full_name}...", "info")

            repo_emails, checked = self._process_repo(
                owner, repo_name, max_commits, target_username
            )
            total_checked += checked
            emails_by_repo[full_name] = list(repo_emails.keys())

            for email, info in repo_emails.items():
                if email in all_emails:
                    all_emails[email]["sources"].extend(info["sources"])
                    if not all_emails[email]["name"] and info["name"]:
                        all_emails[email]["name"] = info["name"]
                else:
                    all_emails[email] = {
                        "name": info["name"],
                        "sources": list(info["sources"]),
                    }

        # Deduplicate sources
        for email in all_emails:
            all_emails[email]["sources"] = sorted(set(all_emails[email]["sources"]))

        # Print summary
        unique = list(all_emails.keys())
        print_status(f"Checked {total_checked} commits across {len(repos_to_scan)} repo(s)", "info")
        if unique:
            print_status(f"Found {len(unique)} unique email(s):", "success")
            for email in sorted(unique):
                name = all_emails[email]["name"]
                label = f" ({name})" if name else ""
                print_status(f"  {email}{label}", "success")
        else:
            print_status("No emails discovered", "warning")

        self.results = {
            "target": target,
            "unique_emails": sorted(unique),
            "email_details": all_emails,
            "emails_by_repo": emails_by_repo,
            "total_commits_checked": total_checked,
            "repos_scanned": [f"{o}/{r}" for o, r in repos_to_scan],
        }
        return True
