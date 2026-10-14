import re
from modules.github.base import GitHubModule
from core.utils import print_status, Colors


class CommitLookup(GitHubModule):
    """Deep analysis of a specific commit - extract all OSINT from .patch and API."""

    name = "github/commit_lookup"
    description = "Deep commit analysis - extract emails, names, diffs, and metadata from any commit"
    target_type = "commit_url/sha"

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Commit URL (github.com/owner/repo/commit/sha) or owner/repo:sha")
        self.add_option("FOLLOW_AUTHOR", "true", False,
                        "Follow author to find more commits/emails")

    def _parse_commit_target(self, target):
        """Parse commit URL or owner/repo:sha format."""
        target = target.strip().rstrip("/")
        target = re.sub(r'^https?://github\.com/', '', target)

        match = re.match(r'([^/]+)/([^/]+)/commit/([a-f0-9]+)', target)
        if match:
            return match.group(1), match.group(2), match.group(3)

        match = re.match(r'([^/]+)/([^/:]+):([a-f0-9]+)', target)
        if match:
            return match.group(1), match.group(2), match.group(3)

        match = re.match(r'([^/]+)/([^/]+)\s+([a-f0-9]+)', target)
        if match:
            return match.group(1), match.group(2), match.group(3)

        return None, None, None

    def _fetch_patch(self, owner, repo, sha):
        """Fetch .patch file and extract all info."""
        patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
        patch_text = self.client.get_raw(patch_url)
        if not patch_text:
            return {}

        info = {"raw_length": len(patch_text)}

        from_matches = re.findall(r'^From:\s*(.+?)\s*<([^>]+)>', patch_text, re.MULTILINE)
        if from_matches:
            info["from_name"] = from_matches[0][0].strip()
            info["from_email"] = from_matches[0][1].strip()

        author_matches = re.findall(r'^Author:\s*(.+?)\s*<([^>]+)>', patch_text, re.MULTILINE)
        if author_matches:
            info["author_name"] = author_matches[0][0].strip()
            info["author_email"] = author_matches[0][1].strip()

        date_match = re.search(r'^Date:\s*(.+)$', patch_text, re.MULTILINE)
        if date_match:
            info["date"] = date_match.group(1).strip()

        subject_match = re.search(r'^Subject:\s*(.+?)(?:\n\s|$)', patch_text, re.MULTILINE)
        if subject_match:
            info["subject"] = subject_match.group(1).strip()

        files_changed = re.findall(r'^diff --git a/(.+?) b/', patch_text, re.MULTILINE)
        info["files_changed"] = files_changed

        additions = len(re.findall(r'^\+[^+]', patch_text, re.MULTILINE))
        deletions = len(re.findall(r'^-[^-]', patch_text, re.MULTILINE))
        info["additions"] = additions
        info["deletions"] = deletions

        all_emails = self.extract_emails_from_text(patch_text)
        info["all_emails_in_patch"] = sorted(list(all_emails))

        urls = re.findall(r'https?://[^\s<>"\']+', patch_text)
        internal_urls = [u for u in urls if "github.com" not in u]
        info["urls_in_diff"] = list(set(internal_urls))[:20]

        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', patch_text)
        ips = [ip for ip in ips if not ip.startswith(("0.", "127."))]
        info["ips_in_diff"] = list(set(ips))[:10]

        return info

    def _fetch_api_data(self, owner, repo, sha):
        """Fetch commit data from API."""
        data = self.client.get(f"/repos/{owner}/{repo}/commits/{sha}")
        if not data:
            return {}

        commit = data.get("commit", {})
        author_info = commit.get("author", {})
        committer_info = commit.get("committer", {})
        gh_author = data.get("author", {})
        gh_committer = data.get("committer", {})

        return {
            "sha": data.get("sha"),
            "message": commit.get("message", ""),
            "url": data.get("html_url"),
            "api_author": {
                "name": author_info.get("name"),
                "email": author_info.get("email"),
                "date": author_info.get("date"),
            },
            "api_committer": {
                "name": committer_info.get("name"),
                "email": committer_info.get("email"),
                "date": committer_info.get("date"),
            },
            "github_author": {
                "login": gh_author.get("login") if gh_author else None,
                "url": gh_author.get("html_url") if gh_author else None,
                "avatar": gh_author.get("avatar_url") if gh_author else None,
            },
            "github_committer": {
                "login": gh_committer.get("login") if gh_committer else None,
                "url": gh_committer.get("html_url") if gh_committer else None,
            },
            "stats": data.get("stats", {}),
            "files_count": len(data.get("files", [])),
            "parents": [p.get("sha", "")[:8] for p in data.get("parents", [])],
            "verified": commit.get("verification", {}).get("verified", False),
            "signature_type": commit.get("verification", {}).get("reason"),
        }

    def _follow_author(self, owner, repo, author_email):
        """Find more commits by the same author in the same repo."""
        commits = self.client.paginate(
            f"/repos/{owner}/{repo}/commits",
            params={"author": author_email},
            max_pages=1,
        )

        other_emails = set()
        other_names = set()
        for c in commits:
            commit_obj = c.get("commit", {})
            for role in ("author", "committer"):
                info = commit_obj.get(role, {})
                email = info.get("email", "").lower()
                name = info.get("name", "")
                if email and not email.endswith("noreply.github.com"):
                    other_emails.add(email)
                if name:
                    other_names.add(name)

        return {
            "total_commits_in_repo": len(commits),
            "all_emails": sorted(list(other_emails)),
            "all_names": sorted(list(other_names)),
        }

    def run(self):
        if not self.validate():
            return False

        self._init_client()
        target = self.get_option("TARGET")
        owner, repo, sha = self._parse_commit_target(target)

        if not all((owner, repo, sha)):
            print_status("Invalid format. Use: owner/repo/commit/sha or owner/repo:sha", "error")
            return False

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*55}")
        print(f"  Commit Deep Analysis")
        print(f"  {owner}/{repo} @ {sha[:12]}")
        print(f"{'='*55}{Colors.RESET}\n")

        print_status("Fetching .patch file...", "info")
        patch_info = self._fetch_patch(owner, repo, sha)
        if patch_info:
            if "from_email" in patch_info:
                print_status(f"REAL EMAIL (from .patch): {patch_info['from_name']} "
                             f"<{patch_info['from_email']}>", "success")
            if patch_info.get("all_emails_in_patch"):
                for e in patch_info["all_emails_in_patch"]:
                    print_status(f"Email in patch: {e}", "success")
            if patch_info.get("files_changed"):
                print_status(f"Files changed: {len(patch_info['files_changed'])}", "info")
            if patch_info.get("urls_in_diff"):
                for u in patch_info["urls_in_diff"][:5]:
                    print_status(f"URL in diff: {u}", "info")
            if patch_info.get("ips_in_diff"):
                for ip in patch_info["ips_in_diff"]:
                    print_status(f"IP in diff: {ip}", "warning")

        print_status("Fetching commit API data...", "info")
        api_data = self._fetch_api_data(owner, repo, sha)
        if api_data:
            auth = api_data.get("api_author", {})
            print_status(f"Author: {auth.get('name')} <{auth.get('email')}>", "success")
            gh_author = api_data.get("github_author", {})
            if gh_author.get("login"):
                print_status(f"GitHub account: {gh_author['login']} ({gh_author.get('url')})", "success")
            print_status(f"Commit verified: {api_data.get('verified')}", "info")

        follow_data = {}
        if self.get_option("FOLLOW_AUTHOR").lower() == "true":
            author_email = (patch_info.get("from_email")
                            or api_data.get("api_author", {}).get("email"))
            if author_email:
                print_status(f"Following author {author_email} for more commits...", "info")
                follow_data = self._follow_author(owner, repo, author_email)
                if follow_data.get("all_emails"):
                    for e in follow_data["all_emails"]:
                        print_status(f"Author also uses: {e}", "success")
                print_status(f"Total commits by author in this repo: "
                             f"{follow_data.get('total_commits_in_repo')}", "info")

        all_emails = set()
        if patch_info.get("from_email"):
            all_emails.add(patch_info["from_email"])
        if patch_info.get("author_email"):
            all_emails.add(patch_info["author_email"])
        for e in patch_info.get("all_emails_in_patch", []):
            all_emails.add(e)
        if api_data.get("api_author", {}).get("email"):
            all_emails.add(api_data["api_author"]["email"])
        if api_data.get("api_committer", {}).get("email"):
            all_emails.add(api_data["api_committer"]["email"])
        for e in follow_data.get("all_emails", []):
            all_emails.add(e)
        all_emails = {e for e in all_emails
                      if not e.endswith("noreply.github.com") and e != "noreply@github.com"}

        self.results = {
            "owner": owner,
            "repo": repo,
            "sha": sha,
            "patch_info": patch_info,
            "api_data": api_data,
            "follow_data": follow_data,
            "all_unique_emails": sorted(list(all_emails)),
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*55}")
        print(f"  All emails extracted: {len(all_emails)}")
        for e in sorted(all_emails):
            print(f"    -> {e}")
        print(f"{'='*55}{Colors.RESET}\n")

        return True
