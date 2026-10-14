import re
import base64
from modules.github.base import GitHubModule
from core.utils import print_status


class UserProfile(GitHubModule):
    """Full GitHub user/organization profile OSINT.

    Pulls profile data, avatar, profile README, and extracts emails
    and social links from all available sources.
    """

    name = "github/user_profile"
    description = "Full GitHub user/org profile recon - profile, avatar, README, emails, social links"
    target_type = "username/org"

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username or organization")

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _fetch_profile(self, username):
        """GET /users/{username} and return structured profile dict."""
        data = self.client.get(f"/users/{username}")
        if not data:
            return None

        profile = {
            "login": data.get("login", ""),
            "id": data.get("id"),
            "name": data.get("name", ""),
            "type": data.get("type", ""),  # User or Organization
            "bio": data.get("bio", ""),
            "company": data.get("company", ""),
            "location": data.get("location", ""),
            "email": data.get("email", ""),
            "blog": data.get("blog", ""),
            "twitter_username": data.get("twitter_username", ""),
            "hireable": data.get("hireable"),
            "public_repos": data.get("public_repos", 0),
            "public_gists": data.get("public_gists", 0),
            "followers": data.get("followers", 0),
            "following": data.get("following", 0),
            "created_at": data.get("created_at", ""),
            "updated_at": data.get("updated_at", ""),
            "html_url": data.get("html_url", ""),
            "avatar_url": data.get("avatar_url", ""),
        }
        return profile

    def _fetch_org_info(self, org_name):
        """GET /orgs/{name} for organization-specific data."""
        data = self.client.get(f"/orgs/{org_name}")
        if not data:
            return None
        return {
            "org_name": data.get("name", ""),
            "org_description": data.get("description", ""),
            "org_email": data.get("email", ""),
            "org_blog": data.get("blog", ""),
            "org_location": data.get("location", ""),
            "org_company": data.get("company", ""),
            "is_verified": data.get("is_verified", False),
            "has_organization_projects": data.get("has_organization_projects", False),
            "public_members_count": data.get("public_members_url", ""),
            "total_private_repos": data.get("total_private_repos", 0),
            "owned_private_repos": data.get("owned_private_repos", 0),
        }

    def _fetch_avatar_url(self, username):
        """Return the direct avatar URL (the .png redirect)."""
        return f"{self.client.BASE_WEB}/{username}.png"

    def _fetch_profile_readme(self, username):
        """Try to fetch the user's profile README from {user}/{user}/README.md."""
        data = self.client.get(f"/repos/{username}/{username}/contents/README.md")
        if not data:
            return None
        content_b64 = data.get("content", "")
        encoding = data.get("encoding", "")
        if encoding == "base64" and content_b64:
            try:
                return base64.b64decode(content_b64).decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    def _extract_social_links(self, text):
        """Pull URLs and common social-media handles from text."""
        if not text:
            return []
        links = []

        # Full URLs
        urls = re.findall(r'https?://[^\s\)\]>\"\']+', text)
        for url in urls:
            url = url.rstrip(".,;:!?")
            links.append(url)

        # Twitter / X handles
        twitter = re.findall(r'(?:^|\s)@([A-Za-z0-9_]{1,15})\b', text)
        for handle in twitter:
            if handle.lower() not in ("github", "mentions"):
                links.append(f"https://twitter.com/{handle}")

        return sorted(set(links))

    # -----------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------

    def run(self):
        if not self.validate():
            return False

        self._init_client()

        target = self.get_option("TARGET")
        parsed = self.parse_github_target(target)
        username = parsed["owner"]

        print_status(f"Fetching profile for '{username}'...", "info")

        # 1. Core profile
        profile = self._fetch_profile(username)
        if not profile:
            print_status(f"User/org '{username}' not found on GitHub", "error")
            self.results = {"target": username, "error": "User not found"}
            return False

        is_org = profile.get("type") == "Organization"
        kind = "organization" if is_org else "user"
        print_status(f"Found GitHub {kind}: {profile['login']}", "success")

        # 2. Organization-specific info
        org_info = None
        if is_org:
            print_status("Fetching organization details...", "info")
            org_info = self._fetch_org_info(username)

        # 3. Avatar
        avatar_url = self._fetch_avatar_url(username)
        print_status(f"Avatar: {avatar_url}", "info")

        # 4. Profile README
        print_status("Checking for profile README...", "info")
        readme_content = self._fetch_profile_readme(username)
        if readme_content:
            print_status(f"Profile README found ({len(readme_content)} chars)", "success")
        else:
            print_status("No profile README", "info")

        # 5. Extract emails from all sources
        collected_emails = set()

        # From profile fields
        if profile.get("email"):
            collected_emails.add(profile["email"].lower())
        if org_info and org_info.get("org_email"):
            collected_emails.add(org_info["org_email"].lower())

        # From bio
        collected_emails.update(self.extract_emails_from_text(profile.get("bio", "")))

        # From README
        if readme_content:
            collected_emails.update(self.extract_emails_from_text(readme_content))

        # 6. Social links from README and bio
        social_links = []
        social_links.extend(self._extract_social_links(readme_content))
        social_links.extend(self._extract_social_links(profile.get("bio", "")))
        if profile.get("blog"):
            social_links.append(profile["blog"])
        if profile.get("twitter_username"):
            social_links.append(f"https://twitter.com/{profile['twitter_username']}")
        social_links = sorted(set(social_links))

        # 7. Blog URL info
        blog_url = profile.get("blog", "")

        # Print summary
        if collected_emails:
            print_status(f"Emails found: {', '.join(sorted(collected_emails))}", "success")
        if social_links:
            print_status(f"Social/links found: {len(social_links)}", "info")
            for link in social_links[:10]:
                print_status(f"  {link}", "info")

        self.results = {
            "target": username,
            "profile": profile,
            "org_info": org_info,
            "avatar_url": avatar_url,
            "readme_content": readme_content,
            "extracted_emails": sorted(collected_emails),
            "social_links": social_links,
            "blog_url": blog_url,
            "account_type": kind,
        }
        return True
