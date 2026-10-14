import base64
import hashlib
import re
from bs4 import BeautifulSoup
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config
from core import http

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

FAVICON_PATHS = [
    "/favicon.ico",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/favicon-32x32.png",
    "/favicon-16x16.png",
]


class FaviconHash(BaseModule):
    name = "web/favicon_hash"
    description = "Favicon discovery, hashing, and Shodan search query generation"
    category = "web"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain or URL")
        self.add_option("TIMEOUT", "10", False, "Request timeout in seconds")

    def _normalize_url(self, target):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        return target.rstrip("/")

    def _parse_favicon_from_html(self, base_url, html):
        """Parse HTML to find favicon link tags."""
        urls = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.find_all("link", rel=True):
                rel = " ".join(link["rel"]).lower()
                if "icon" in rel:
                    href = link.get("href", "")
                    if href:
                        if href.startswith("//"):
                            href = "https:" + href
                        elif href.startswith("/"):
                            href = base_url + href
                        elif not href.startswith("http"):
                            href = base_url + "/" + href
                        urls.append(href)
        except Exception:
            pass
        return urls

    def _download_favicon(self, url, config):
        """Download favicon and return raw bytes or None."""
        try:
            resp = http.get(
                url,
                timeout=int(self.get_option("TIMEOUT") or 10),
                allow_redirects=True,
            )
            if resp.status_code == 200 and len(resp.content) > 0:
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" in content_type and len(resp.content) > 10000:
                    return None
                return resp.content
        except Exception:
            pass
        return None

    def _compute_hashes(self, data):
        """Compute favicon hashes. Shodan uses MurmurHash3 of the base64 icon."""
        hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        if HAS_MMH3:
            b64 = base64.encodebytes(data)
            hashes["mmh3"] = mmh3.hash(b64)
        return hashes

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        base_url = self._normalize_url(target)
        config = Config()

        print_status(f"Searching for favicon on {base_url}", "info")

        favicon_url = None
        favicon_data = None

        # Step 1: Parse HTML for favicon link tags
        print_status("Parsing HTML for favicon references...", "info")
        try:
            resp = http.get(
                base_url,
                timeout=int(self.get_option("TIMEOUT") or 10),
                allow_redirects=True,
            )
            if resp.status_code == 200:
                html_favicons = self._parse_favicon_from_html(base_url, resp.text)
                for url in html_favicons:
                    print_status(f"Found favicon reference in HTML: {url}", "info")
                    data = self._download_favicon(url, config)
                    if data:
                        favicon_url = url
                        favicon_data = data
                        print_status(f"Downloaded favicon from HTML link: {url}", "success")
                        break
        except Exception as e:
            print_status(f"Failed to fetch HTML: {e}", "warning")

        # Step 2: Try common favicon paths
        if not favicon_data:
            print_status("Trying common favicon paths...", "info")
            for path in FAVICON_PATHS:
                url = base_url + path
                data = self._download_favicon(url, config)
                if data:
                    favicon_url = url
                    favicon_data = data
                    print_status(f"Found favicon at {url}", "success")
                    break
                else:
                    print_status(f"No favicon at {path}", "warning")

        if not favicon_data:
            print_status("No favicon found on target", "error")
            self.results = {
                "target": base_url,
                "favicon_found": False,
                "favicon_url": None,
                "hashes": {},
                "size": 0,
                "shodan_query": None,
            }
            return True

        # Compute hashes
        hashes = self._compute_hashes(favicon_data)
        size = len(favicon_data)
        if HAS_MMH3:
            shodan_query = f'http.favicon.hash:{hashes["mmh3"]}'
        else:
            shodan_query = None

        print_status(f"Favicon URL: {favicon_url}", "success")
        print_status(f"Favicon size: {size} bytes", "info")
        print_status(f"MD5: {hashes['md5']}", "success")
        print_status(f"SHA256: {hashes['sha256']}", "success")
        if HAS_MMH3:
            print_status(f"MurmurHash3: {hashes['mmh3']}", "success")
            print_status(f"Shodan query: {shodan_query}", "info")
        else:
            print_status("Install 'mmh3' for the Shodan favicon hash query", "warning")

        self.results = {
            "target": base_url,
            "favicon_found": True,
            "favicon_url": favicon_url,
            "hashes": hashes,
            "size": size,
            "shodan_query": shodan_query,
        }

        print_status("Favicon hash analysis complete", "info")
        return True
