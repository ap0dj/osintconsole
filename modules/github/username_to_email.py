import re
import hashlib
import requests
from collections import defaultdict
from modules.github.base import GitHubModule
from core.utils import print_status, Colors


class UsernameToEmail(GitHubModule):
    """All-in-one: GitHub username → real email via 6 different techniques."""

    name = "github/username_to_email"
    description = "Extract real email from GitHub username using 6 OSINT techniques"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username")
        self.add_option("MAX_REPOS", "5", False, "Repos to scan for commits")
        self.add_option("MAX_COMMITS", "10", False, "Commits per repo to check")

    def _method_1_profile(self, username):
        """Method 1: Public profile email (if user made it public)."""
        emails = set()
        data = self.client.get(f"/users/{username}")
        if data and data.get("email"):
            emails.add(data["email"])
        return emails, "Profile API"

    def _method_2_events(self, username):
        """Method 2: Push events contain author.email in commit payloads."""
        emails = set()
        events = self.client.paginate(
            f"/users/{username}/events/public", max_pages=3
        )
        for event in events:
            if event.get("type") == "PushEvent":
                for commit in event.get("payload", {}).get("commits", []):
                    email = commit.get("author", {}).get("email", "")
                    if email:
                        emails.add(email)
        return emails, "Push Events API"

    def _method_3_patch(self, username, max_repos, max_commits):
        """Method 3: The .patch trick - append .patch to commit URL to get real email."""
        emails = set()
        repos = self.client.get(
            f"/users/{username}/repos",
            params={"sort": "pushed", "per_page": max_repos}
        )
        if not repos:
            return emails, "Commit .patch"

        for repo in repos:
            if repo.get("fork"):
                continue
            repo_name = repo.get("full_name")
            commits = self.client.get(
                f"/repos/{repo_name}/commits",
                params={"author": username, "per_page": max_commits}
            )
            if not commits:
                continue

            for commit in commits[:max_commits]:
                sha = commit.get("sha")
                if not sha:
                    continue
                patch_url = f"https://github.com/{repo_name}/commit/{sha}.patch"
                patch = self.client.get_raw(patch_url)
                if patch:
                    from_matches = re.findall(
                        r'^From:\s*.+?\s*<([^>]+)>', patch, re.MULTILINE
                    )
                    for email in from_matches:
                        emails.add(email)
                    author_matches = re.findall(
                        r'^Author:\s*.+?\s*<([^>]+)>', patch, re.MULTILINE
                    )
                    for email in author_matches:
                        emails.add(email)

        return emails, "Commit .patch files"

    def _method_4_commit_api(self, username, max_repos, max_commits):
        """Method 4: Commits API - commit.author.email and commit.committer.email."""
        emails = set()
        repos = self.client.get(
            f"/users/{username}/repos",
            params={"sort": "pushed", "per_page": max_repos}
        )
        if not repos:
            return emails, "Commits API"

        for repo in repos:
            if repo.get("fork"):
                continue
            repo_name = repo.get("full_name")
            commits = self.client.get(
                f"/repos/{repo_name}/commits",
                params={"author": username, "per_page": max_commits}
            )
            if not commits:
                continue

            for commit in commits:
                commit_obj = commit.get("commit", {})
                for role in ("author", "committer"):
                    email = commit_obj.get(role, {}).get("email", "")
                    if email:
                        emails.add(email)

        return emails, "Commits API"

    def _method_5_gpg_keys(self, username):
        """Method 5: GPG public keys contain email addresses."""
        emails = set()
        keys = self.client.get(f"/users/{username}/gpg_keys")
        if keys:
            for key in keys:
                for email_obj in key.get("emails", []):
                    email = email_obj.get("email", "")
                    if email:
                        emails.add(email)
                raw = key.get("raw_key", "")
                if raw:
                    emails.update(self.extract_emails_from_text(raw))

        return emails, "GPG Keys"

    def _method_6_atom_feed(self, username):
        """Method 6: GitHub Atom feed may contain email in author entries."""
        emails = set()
        feed_url = f"https://github.com/{username}.atom"
        feed = self.client.get_raw(feed_url)
        if feed:
            email_matches = re.findall(r'<email>([^<]+)</email>', feed)
            for email in email_matches:
                emails.add(email)

        return emails, "Atom Feed"

    def run(self):
        if not self.validate():
            return False

        self._init_client()
        username = self.get_option("TARGET").strip()
        max_repos = int(self.get_option("MAX_REPOS") or 5)
        max_commits = int(self.get_option("MAX_COMMITS") or 10)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*55}")
        print(f"  Username -> Email Extraction")
        print(f"  Target: {username}")
        print(f"  Methods: 6 techniques")
        print(f"{'='*55}{Colors.RESET}\n")

        profile = self.client.get(f"/users/{username}")
        if not profile:
            print_status(f"User '{username}' not found on GitHub", "error")
            return False

        real_name = profile.get("name", "")
        if real_name:
            print_status(f"Real name: {real_name}", "info")

        methods = [
            ("1", lambda: self._method_1_profile(username)),
            ("2", lambda: self._method_2_events(username)),
            ("3", lambda: self._method_3_patch(username, max_repos, max_commits)),
            ("4", lambda: self._method_4_commit_api(username, max_repos, max_commits)),
            ("5", lambda: self._method_5_gpg_keys(username)),
            ("6", lambda: self._method_6_atom_feed(username)),
        ]

        all_emails = set()
        email_sources = defaultdict(list)
        method_results = {}

        for num, method_fn in methods:
            try:
                emails, method_name = method_fn()

                clean = set()
                for e in emails:
                    e = e.lower().strip()
                    if (e and "@" in e
                            and not e.endswith("noreply.github.com")
                            and e != "noreply@github.com"):
                        clean.add(e)

                method_results[f"method_{num}"] = {
                    "name": method_name,
                    "emails_found": sorted(list(clean)),
                    "count": len(clean),
                }

                if clean:
                    print_status(f"[Method {num}] {method_name}: "
                                 f"found {len(clean)} email(s)", "success")
                    for e in clean:
                        print_status(f"  -> {e}", "success")
                        email_sources[e].append(method_name)
                    all_emails.update(clean)
                else:
                    print_status(f"[Method {num}] {method_name}: no emails", "warning")

            except Exception as exc:
                print_status(f"[Method {num}] failed: {exc}", "error")
                method_results[f"method_{num}"] = {"name": str(exc), "count": 0}

        email_confidence = {}
        for email, sources in email_sources.items():
            score = len(sources)
            if any("Profile" in s for s in sources):
                score += 2
            if any(".patch" in s for s in sources):
                score += 2
            if any("GPG" in s for s in sources):
                score += 1

            if score >= 5:
                confidence = "HIGH"
            elif score >= 3:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"

            email_confidence[email] = {
                "email": email,
                "confidence": confidence,
                "score": score,
                "found_by": sources,
                "source_count": len(sources),
            }

        self.results = {
            "username": username,
            "real_name": real_name,
            "profile_url": profile.get("html_url"),
            "all_emails": sorted(list(all_emails)),
            "email_confidence": email_confidence,
            "method_results": method_results,
            "total_emails_found": len(all_emails),
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*55}")
        print(f"  Results for: {username}")
        if real_name:
            print(f"  Name: {real_name}")
        print(f"  Emails found: {len(all_emails)}")
        print(f"{'─'*55}")
        for email, info in sorted(email_confidence.items(),
                                   key=lambda x: x[1]["score"], reverse=True):
            conf = info["confidence"]
            color = Colors.GREEN if conf == "HIGH" else (
                Colors.YELLOW if conf == "MEDIUM" else Colors.DIM)
            print(f"  {color}{email:<35} [{conf}] "
                  f"({info['source_count']} sources){Colors.RESET}")
        print(f"{'='*55}{Colors.RESET}\n")

        return True
