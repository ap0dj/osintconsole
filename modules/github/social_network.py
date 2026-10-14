from collections import Counter
from modules.github.base import GitHubModule
from core.utils import print_status, Colors


class SocialNetwork(GitHubModule):
    name = "github/social_network"
    description = "GitHub social graph analysis - followers, following, orgs, starred repos, and interest profiling"

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username")
        self.add_option("MAX_PAGES", "3", False, "Max pages to paginate for each endpoint")
        self.add_option("DEEP_ORG_SCAN", "false", False, "Fetch members for each organization")

    def run(self):
        if not self.validate():
            return False

        self._init_client()
        target = self.get_option("TARGET")
        max_pages = int(self.get_option("MAX_PAGES") or 3)
        deep_org = (self.get_option("DEEP_ORG_SCAN") or "false").lower() == "true"

        parsed = self.parse_github_target(target)
        username = parsed["owner"]

        print_status(f"Analyzing social network for: {username}", "info")

        # ── 1. Followers ─────────────────────────────────────────
        print_status("Fetching followers...", "info")
        raw_followers = self.client.paginate(f"/users/{username}/followers",
                                             max_pages=max_pages)
        followers = []
        for u in raw_followers:
            followers.append({
                "login": u.get("login", ""),
                "id": u.get("id"),
                "html_url": u.get("html_url", ""),
                "type": u.get("type", ""),
                "avatar_url": u.get("avatar_url", ""),
            })
        print_status(f"Found {len(followers)} followers", "success")

        # ── 2. Following ─────────────────────────────────────────
        print_status("Fetching following...", "info")
        raw_following = self.client.paginate(f"/users/{username}/following",
                                             max_pages=max_pages)
        following = []
        for u in raw_following:
            following.append({
                "login": u.get("login", ""),
                "id": u.get("id"),
                "html_url": u.get("html_url", ""),
                "type": u.get("type", ""),
                "avatar_url": u.get("avatar_url", ""),
            })
        print_status(f"Following {len(following)} users", "success")

        # ── 3. Mutual connections ─────────────────────────────────
        follower_logins = {u["login"] for u in followers}
        following_logins = {u["login"] for u in following}
        mutual_logins = follower_logins & following_logins
        mutual_connections = [u for u in followers if u["login"] in mutual_logins]
        print_status(f"Found {len(mutual_connections)} mutual connections", "success")

        # ── 4. Starred repos ─────────────────────────────────────
        print_status("Fetching starred repositories...", "info")
        raw_starred = self.client.paginate(f"/users/{username}/starred",
                                           max_pages=max_pages)
        starred_repos = []
        for r in raw_starred:
            starred_repos.append({
                "full_name": r.get("full_name", ""),
                "description": r.get("description", ""),
                "html_url": r.get("html_url", ""),
                "language": r.get("language", ""),
                "stars": r.get("stargazers_count", 0),
                "topics": r.get("topics", []),
            })
        print_status(f"Found {len(starred_repos)} starred repos", "success")

        # ── 5. Interest profile from starred repos ────────────────
        lang_counter = Counter()
        topic_counter = Counter()
        for r in starred_repos:
            lang = r.get("language")
            if lang:
                lang_counter[lang] += 1
            for t in r.get("topics", []):
                topic_counter[t] += 1

        interest_profile = {
            "top_languages": dict(lang_counter.most_common(15)),
            "top_topics": dict(topic_counter.most_common(20)),
            "total_starred": len(starred_repos),
        }

        # ── 6. Organizations ─────────────────────────────────────
        print_status("Fetching organization memberships...", "info")
        raw_orgs = self.client.paginate(f"/users/{username}/orgs",
                                        max_pages=max_pages)
        organizations = []
        for o in raw_orgs:
            organizations.append({
                "login": o.get("login", ""),
                "id": o.get("id"),
                "description": o.get("description", ""),
                "url": f"https://github.com/{o.get('login', '')}",
                "avatar_url": o.get("avatar_url", ""),
            })
        print_status(f"Member of {len(organizations)} organizations", "success")

        # ── 7. Org members (deep scan) ────────────────────────────
        org_members = {}
        if deep_org and organizations:
            print_status("Deep scanning organization members...", "info")
            for org in organizations:
                org_login = org["login"]
                print_status(f"  Fetching members for org: {org_login}", "info")
                members_raw = self.client.paginate(f"/orgs/{org_login}/members",
                                                    max_pages=max_pages)
                members = []
                for m in members_raw:
                    members.append({
                        "login": m.get("login", ""),
                        "html_url": m.get("html_url", ""),
                        "type": m.get("type", ""),
                    })
                org_members[org_login] = members
                print_status(f"  {org_login}: {len(members)} public members", "info")

        # ── Summary ──────────────────────────────────────────────
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*55}")
        print(f"  Social Network Summary: {username}")
        print(f"{'='*55}{Colors.RESET}")
        print(f"  {Colors.GREEN}Followers:{Colors.RESET}          {len(followers)}")
        print(f"  {Colors.GREEN}Following:{Colors.RESET}          {len(following)}")
        print(f"  {Colors.GREEN}Mutual connections:{Colors.RESET} {len(mutual_connections)}")
        print(f"  {Colors.GREEN}Starred repos:{Colors.RESET}      {len(starred_repos)}")
        print(f"  {Colors.GREEN}Organizations:{Colors.RESET}      {len(organizations)}")

        if mutual_connections:
            print(f"\n  {Colors.BOLD}Mutual connections:{Colors.RESET}")
            for mc in mutual_connections[:15]:
                print(f"    {Colors.CYAN}-{Colors.RESET} {mc['login']}")
            if len(mutual_connections) > 15:
                print(f"    ... and {len(mutual_connections) - 15} more")

        if interest_profile["top_languages"]:
            print(f"\n  {Colors.BOLD}Top languages (by starred repos):{Colors.RESET}")
            for lang, count in list(interest_profile["top_languages"].items())[:8]:
                print(f"    {Colors.YELLOW}-{Colors.RESET} {lang}: {count}")

        if interest_profile["top_topics"]:
            print(f"\n  {Colors.BOLD}Top topics:{Colors.RESET}")
            for topic, count in list(interest_profile["top_topics"].items())[:8]:
                print(f"    {Colors.MAGENTA}-{Colors.RESET} {topic}: {count}")

        if organizations:
            print(f"\n  {Colors.BOLD}Organizations:{Colors.RESET}")
            for org in organizations:
                print(f"    {Colors.BLUE}-{Colors.RESET} {org['login']}")

        print(f"\n{Colors.CYAN}{'='*55}{Colors.RESET}\n")

        self.results = {
            "target": username,
            "followers": followers,
            "followers_count": len(followers),
            "following": following,
            "following_count": len(following),
            "mutual_connections": mutual_connections,
            "mutual_count": len(mutual_connections),
            "starred_repos": starred_repos,
            "organizations": organizations,
            "org_members": org_members,
            "interest_profile": interest_profile,
        }
        return True
