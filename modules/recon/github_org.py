"""GitHub Organization OSINT — enumerate members, repos, and metadata via public API."""
from core.base_module import BaseModule
import core.http as http_client
from core.utils import print_status
from modules.harvest.crypto_transactions import FetchErrorsMixin


class GithubOrg(FetchErrorsMixin, BaseModule):
    name = "recon/github_org"
    description = "Enumerate GitHub org members, repos, and public metadata (no auth required)"
    category = "recon"
    target_type = "org/domain/username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub org/username or domain (org extracted from domain)")
        self.add_option("MAX_REPOS", "50", False, "Max repos to fetch per org")
        self.add_option("MAX_MEMBERS", "100", False, "Max members to fetch")

    def run(self):
        if not self.validate():
            return False

        raw = (self.get_option("TARGET") or "").strip()
        # If domain provided, strip TLD and try as org name
        org = raw.split(".")[0] if "." in raw else raw

        try:
            max_repos = int(self.get_option("MAX_REPOS") or "50")
        except (TypeError, ValueError):
            max_repos = 50
        try:
            max_members = int(self.get_option("MAX_MEMBERS") or "100")
        except (TypeError, ValueError):
            max_members = 100

        base = "https://api.github.com"
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

        from core.config import Config
        cfg = Config()
        # The token lives at api_keys.github (same accessor the github/* modules
        # use); the old cfg.get("github") read a non-existent top-level key.
        gh_token = cfg.get("api_keys.github")
        if gh_token:
            headers["Authorization"] = f"Bearer {gh_token}"

        self._errors = []
        results = {
            "org": org,
            "profile": {},
            "repos": [],
            "members": [],
            "topics": [],
            "total_repos": 0,
            "total_members": 0,
            "fetch_errors": [],
        }

        # Org profile
        print_status(f"Fetching org profile: {org}", "info")
        r = http_client.get(f"{base}/orgs/{org}", headers=headers)
        if r is not None and r.status_code == 200:
            d = r.json()
            results["profile"] = {
                "name": d.get("name"),
                "description": d.get("description"),
                "blog": d.get("blog"),
                "location": d.get("location"),
                "email": d.get("email"),
                "public_repos": d.get("public_repos"),
                "created_at": d.get("created_at"),
                "avatar_url": d.get("avatar_url"),
                "html_url": d.get("html_url"),
                "type": d.get("type"),
            }
            results["total_repos"] = d.get("public_repos", 0)
            # GitHub's org object has NO public_members count, so members are
            # counted honestly from the /members listing further down.
            print_status(
                f"Org: {d.get('name') or org} | repos={d.get('public_repos')}",
                "success",
            )
        elif r is not None and r.status_code == 404:
            # Genuinely not an org -> try as a user account.
            ru = http_client.get(f"{base}/users/{org}", headers=headers)
            if ru is not None and ru.status_code == 200:
                d = ru.json()
                results["profile"] = {
                    "name": d.get("name"),
                    "bio": d.get("bio"),
                    "blog": d.get("blog"),
                    "location": d.get("location"),
                    "email": d.get("email"),
                    "public_repos": d.get("public_repos"),
                    "followers": d.get("followers"),
                    "created_at": d.get("created_at"),
                    "html_url": d.get("html_url"),
                    "type": d.get("type"),
                }
                results["total_repos"] = d.get("public_repos", 0)
                print_status(f"Found user profile: {d.get('name') or org}", "success")
            elif ru is not None and ru.status_code == 404:
                print_status(f"Org/user '{org}' not found on GitHub", "warning")
                self.results = results
                return True
            else:
                code = ru.status_code if ru is not None else "no response"
                self._note_error(
                    f"GitHub user lookup failed: HTTP {code} (unauthenticated "
                    f"API is capped at 60 req/hr - set api_keys.github)")
                self.results = results
                return self._fail()
        else:
            # 403 rate-limit / 5xx / no response: a fetch failure, NOT "not found".
            code = r.status_code if r is not None else "no response"
            self._note_error(
                f"GitHub org lookup failed: HTTP {code} (unauthenticated API is "
                f"capped at 60 req/hr - set api_keys.github)")
            self.results = results
            return self._fail()

        # Repos
        print_status(f"Fetching repos (max {max_repos})...", "info")
        per_page = min(max_repos, 100)
        repos_failed = False
        r = http_client.get(
            f"{base}/orgs/{org}/repos",
            headers=headers,
            params={"per_page": per_page, "sort": "updated", "type": "public"},
        )
        if r is not None and r.status_code == 200:
            for repo in r.json()[:max_repos]:
                results["repos"].append({
                    "name": repo.get("name"),
                    "description": repo.get("description"),
                    "language": repo.get("language"),
                    "stars": repo.get("stargazers_count"),
                    "forks": repo.get("forks_count"),
                    "open_issues": repo.get("open_issues_count"),
                    "pushed_at": repo.get("pushed_at"),
                    "html_url": repo.get("html_url"),
                    "topics": repo.get("topics", []),
                    "archived": repo.get("archived"),
                })
                for t in repo.get("topics", []):
                    if t not in results["topics"]:
                        results["topics"].append(t)
        elif r is not None and r.status_code == 404:
            # Not an org account -> user repos.
            ru = http_client.get(
                f"{base}/users/{org}/repos",
                headers=headers,
                params={"per_page": per_page, "sort": "updated", "type": "public"},
            )
            if ru is not None and ru.status_code == 200:
                for repo in ru.json()[:max_repos]:
                    results["repos"].append({
                        "name": repo.get("name"),
                        "description": repo.get("description"),
                        "language": repo.get("language"),
                        "stars": repo.get("stargazers_count"),
                        "forks": repo.get("forks_count"),
                        "pushed_at": repo.get("pushed_at"),
                        "html_url": repo.get("html_url"),
                    })
            elif ru is None or ru.status_code != 404:
                repos_failed = True
                code = ru.status_code if ru is not None else "no response"
                self._note_error(f"GitHub user repos fetch failed: HTTP {code}")
        else:
            # 403 rate-limit / 5xx: surface as error, do not report a clean 0.
            repos_failed = True
            code = r.status_code if r is not None else "no response"
            self._note_error(f"GitHub repos fetch failed: HTTP {code}")

        if repos_failed:
            print_status("Repo fetch FAILED (rate-limited/error) - count is NOT "
                         "a true zero", "warning")
        else:
            print_status(f"Got {len(results['repos'])} repos", "success")

        # Members (org only)
        if results["profile"].get("type") == "Organization":
            print_status(f"Fetching members (max {max_members})...", "info")
            r = http_client.get(
                f"{base}/orgs/{org}/members",
                headers=headers,
                params={"per_page": min(max_members, 100), "filter": "all"},
            )
            if r is not None and r.status_code == 200:
                for m in r.json()[:max_members]:
                    results["members"].append({
                        "login": m.get("login"),
                        "html_url": m.get("html_url"),
                        "avatar_url": m.get("avatar_url"),
                    })
                print_status(f"Got {len(results['members'])} members", "success")
            else:
                code = r.status_code if r is not None else "no response"
                self._note_error(f"GitHub members fetch failed: HTTP {code}")

        # Honest count from what the /members listing actually returned.
        results["total_members"] = len(results["members"])
        results["fetch_errors"] = list(getattr(self, "_errors", []))

        # Print summary
        print(f"\n  Org:     {org}")
        print(f"  Repos:   {len(results['repos'])}")
        print(f"  Members: {len(results['members'])}")
        if results["topics"]:
            print(f"  Topics:  {', '.join(results['topics'][:10])}")
        for r2 in results["repos"][:5]:
            stars = r2.get("stars", 0) or 0
            print(f"    * {r2['name']} (★{stars}) — {r2.get('language') or 'unknown'}")

        self.results = results
        return True
