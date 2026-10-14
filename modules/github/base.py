import re
import time
import requests
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config


class GitHubClient:
    """Shared GitHub API client with authentication, rate limiting, and pagination."""

    BASE_API = "https://api.github.com"
    BASE_RAW = "https://raw.githubusercontent.com"
    BASE_WEB = "https://github.com"

    def __init__(self, token=None):
        config = Config()
        self.token = token or config.get("api_keys.github", "")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": config.get("user_agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        })
        if self.token:
            self.session.headers["Authorization"] = f"token {self.token}"
        self.timeout = config.get("timeout", 15)
        self._rate_remaining = None
        self._rate_reset = None

    @property
    def authenticated(self):
        return bool(self.token)

    def _update_rate_limit(self, response):
        self._rate_remaining = int(response.headers.get("X-RateLimit-Remaining", -1))
        self._rate_reset = int(response.headers.get("X-RateLimit-Reset", 0))
        if self._rate_remaining == 0:
            wait = max(self._rate_reset - int(time.time()), 1)
            print_status(f"Rate limited. Waiting {wait}s...", "warning")
            time.sleep(min(wait, 60))

    def get(self, endpoint, params=None):
        url = endpoint if endpoint.startswith("http") else f"{self.BASE_API}{endpoint}"
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            self._update_rate_limit(resp)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                print_status("API rate limit reached", "warning")
                return None
            if resp.status_code == 404:
                return None
            return None
        except requests.RequestException as exc:
            print_status(f"GitHub API error: {exc}", "error")
            return None

    def _strip_auth_on_redirect(self, resp, **kwargs):
        # not a redirect: nothing to do
        pass

    def _safe_get_raw(self, url, timeout=15):
        """Get raw URL; strip Authorization if redirected off api.github.com/github.com."""
        import requests as _rq
        from urllib.parse import urlparse
        headers = dict(self.session.headers)
        try:
            r = _rq.get(url, headers=headers, timeout=timeout, allow_redirects=False)
            # Follow redirects manually, stripping auth when leaving github.com
            hops = 0
            while r.is_redirect and hops < 5:
                loc = r.headers.get('Location', '')
                if not loc:
                    break
                if not loc.startswith('http'):
                    from urllib.parse import urljoin
                    loc = urljoin(url, loc)
                host = urlparse(loc).netloc
                next_headers = dict(headers)
                if host not in ('api.github.com', 'github.com', 'www.github.com'):
                    next_headers.pop('Authorization', None)
                r = _rq.get(loc, headers=next_headers, timeout=timeout, allow_redirects=False)
                url = loc
                hops += 1
            return r
        except Exception:
            return None

    def get_raw(self, url):
        r = self._safe_get_raw(url, timeout=self.timeout)
        if r is None:
            return None
        # 429 handling: respect Retry-After, retry once
        if r.status_code == 429:
            try:
                retry_after = int(r.headers.get('Retry-After', 10))
            except (ValueError, TypeError):
                retry_after = 10
            time.sleep(min(60, retry_after))
            r = self._safe_get_raw(url, timeout=self.timeout)
            if r is None:
                return None
        if r.status_code == 200:
            return r.text
        return None

    def paginate(self, endpoint, params=None, max_pages=5):
        params = dict(params or {})
        params.setdefault("per_page", 100)
        all_items = []
        url = endpoint if endpoint.startswith("http") else f"{self.BASE_API}{endpoint}"
        for _ in range(max_pages):
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
                self._update_rate_limit(resp)
                if resp.status_code != 200:
                    break
                data = resp.json()
                if not data:
                    break
                all_items.extend(data)
                link = resp.headers.get("Link", "")
                match = re.search(r'<([^>]+)>;\s*rel="next"', link)
                if not match:
                    break
                url = match.group(1)
                params = {}
            except requests.RequestException:
                break
        return all_items

    def check_rate_limit(self):
        data = self.get("/rate_limit")
        if data:
            core = data.get("resources", {}).get("core", {})
            search = data.get("resources", {}).get("search", {})
            return {
                "core_remaining": core.get("remaining"),
                "core_limit": core.get("limit"),
                "search_remaining": search.get("remaining"),
                "search_limit": search.get("limit"),
                "authenticated": self.authenticated,
            }
        return None


class GitHubModule(BaseModule):
    """Base class for all GitHub OSINT modules. Provides shared GitHubClient."""

    category = "github"
    target_type = "username/org/repo"

    def __init__(self):
        super().__init__()
        self.client = None

    def _init_client(self):
        self.client = GitHubClient()
        if self.client.authenticated:
            print_status("Authenticated with GitHub token", "success")
        else:
            print_status("No GitHub token (rate limit: 60 req/hr). "
                         "Set api_keys.github in config for 5000 req/hr", "warning")
        return self.client

    @staticmethod
    def extract_emails_from_text(text):
        if not text:
            return set()
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        found = re.findall(pattern, text)
        skip = {"noreply@github.com", "notifications@github.com"}
        return {e.lower() for e in found
                if not e.endswith("@users.noreply.github.com") and e.lower() not in skip}

    @staticmethod
    def parse_github_target(target):
        target = target.strip().rstrip("/")
        target = re.sub(r'^https?://github\.com/', '', target)
        parts = target.split("/")
        if len(parts) >= 2:
            return {"owner": parts[0], "repo": parts[1], "type": "repo"}
        return {"owner": parts[0], "type": "user"}
