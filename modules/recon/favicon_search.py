"""favicon_search — find hosts sharing the same favicon hash via Shodan and Censys.

Workflow
--------
1. Normalize target to a favicon URL.
2. Download the favicon and compute Shodan (MurmurHash3), MD5 and SHA256 hashes.
3. Query Shodan's host-search API (if SHODAN_KEY is set).
4. Query Censys hosts API (if CENSYS_ID + CENSYS_SECRET are set).
5. Always output manual lookup URLs for Shodan, Censys and FOFA.
"""
import base64
import hashlib
from urllib.parse import urlparse, quote as urlquote

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http

try:
    import mmh3
    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False


# ---------------------------------------------------------------------------
# Pure-Python MurmurHash3 32-bit (Shodan-compatible, signed output)
# ---------------------------------------------------------------------------

def _murmurhash3_32(data: str, seed: int = 0) -> int:
    """MurmurHash3 32-bit — Shodan-compatible favicon hash."""
    key = data.encode("utf-8")
    length = len(key)
    nblocks = length // 4
    h1 = seed
    c1, c2 = 0xCC9E2D51, 0x1B873593

    for block_start in range(0, nblocks * 4, 4):
        k1 = (
            key[block_start + 3] << 24
            | key[block_start + 2] << 16
            | key[block_start + 1] << 8
            | key[block_start]
        )
        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = key[nblocks * 4:]
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= tail[2] << 16
    if tail_size >= 2:
        k1 ^= tail[1] << 8
    if tail_size >= 1:
        k1 ^= tail[0]
        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit integer (Shodan stores the signed form)
    if h1 > 0x7FFFFFFF:
        h1 -= 0x100000000
    return h1


def _compute_shodan_hash(favicon_bytes: bytes) -> int:
    """Compute the Shodan favicon hash (MurmurHash3 of base64-encoded icon)."""
    encoded = base64.encodebytes(favicon_bytes).decode("utf-8")
    if _HAS_MMH3:
        return mmh3.hash(encoded)
    return _murmurhash3_32(encoded)


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class FaviconSearch(BaseModule):
    name = "recon/favicon_search"
    description = "Find hosts sharing the same favicon hash via Shodan and Censys"
    category = "recon"
    # _build_favicon_url() prepends https:// for a bare host, so a plain
    # domain works and full_recon should include this in domain scans too.
    target_type = "url/domain"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "URL or domain (e.g. https://example.com or example.com)")
        self.add_option("SHODAN_KEY", "", False, "Shodan API key")
        self.add_option("CENSYS_ID", "", False, "Censys API ID")
        self.add_option("CENSYS_SECRET", "", False, "Censys API secret")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_favicon_url(self, target: str) -> tuple:
        """Return (favicon_url, host) from a raw user target."""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        scheme = parsed.scheme or "https"
        host = parsed.netloc or parsed.path.split("/")[0]
        favicon_url = f"{scheme}://{host}/favicon.ico"
        return favicon_url, host

    def _download_favicon(self, favicon_url: str) -> bytes:
        """Download the favicon and return raw bytes, or raise on failure."""
        resp = http.get(favicon_url, timeout=10, allow_redirects=True)
        if resp.status_code != 200:
            raise ValueError(
                f"HTTP {resp.status_code} fetching {favicon_url}"
            )
        # Prefer .content (bytes) over re-encoding text
        try:
            raw = resp.content
        except AttributeError:
            raw = resp.text.encode("latin-1")
        if not raw:
            raise ValueError("Empty response body — no favicon data")
        return raw

    def _compute_hashes(self, favicon_bytes: bytes) -> dict:
        shodan_hash = _compute_shodan_hash(favicon_bytes)
        md5_hash = hashlib.md5(favicon_bytes).hexdigest()
        sha256_hash = hashlib.sha256(favicon_bytes).hexdigest()
        return {
            "shodan": shodan_hash,
            "md5": md5_hash,
            "sha256": sha256_hash,
        }

    # ------------------------------------------------------------------
    # Shodan API search
    # ------------------------------------------------------------------

    def _shodan_search(self, shodan_hash: int, api_key: str) -> list:
        """Query Shodan host-search API and return a list of hit dicts."""
        results = []
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            "key": api_key,
            "query": f"http.favicon.hash:{shodan_hash}",
            "facets": "org,country",
        }
        try:
            resp = http.get(url, params=params, timeout=20)
            if resp.status_code == 401:
                print_status("Shodan: invalid API key (401)", "warning")
                return results
            if resp.status_code != 200:
                print_status(f"Shodan: HTTP {resp.status_code}", "warning")
                return results
            data = resp.json()
        except Exception as exc:
            print_status(f"Shodan search error: {exc}", "warning")
            return results

        for m in (data.get("matches") or [])[:20]:
            location = m.get("location") or {}
            http_data = m.get("http") or {}
            results.append({
                "ip": m.get("ip_str", ""),
                "port": m.get("port", ""),
                "org": m.get("org", ""),
                "country": location.get("country_code", ""),
                "hostnames": m.get("hostnames") or [],
                "title": http_data.get("title", ""),
            })
        return results

    # ------------------------------------------------------------------
    # Censys API search
    # ------------------------------------------------------------------

    def _censys_search(self, md5_hash: str, censys_id: str, censys_secret: str) -> list:
        """Query Censys v2 hosts API and return a list of hit dicts."""
        results = []
        url = "https://search.censys.io/api/v2/hosts/search"
        body = {
            "q": f'services.http.response.favicons.md5_hash="{md5_hash}"',
            "per_page": 20,
        }
        try:
            resp = http.post(
                url,
                json=body,
                auth=(censys_id, censys_secret),
                timeout=20,
            )
            if resp.status_code == 401:
                print_status("Censys: invalid credentials (401)", "warning")
                return results
            if resp.status_code == 422:
                print_status("Censys: query rejected (422)", "warning")
                return results
            if resp.status_code != 200:
                print_status(f"Censys: HTTP {resp.status_code}", "warning")
                return results
            data = resp.json()
        except Exception as exc:
            print_status(f"Censys search error: {exc}", "warning")
            return results

        result_block = data.get("result") or {}
        for hit in (result_block.get("hits") or []):
            services = hit.get("services") or []
            matched = hit.get("matched_services") or []
            ports = [str(s.get("port", "")) for s in services if s.get("port")]
            protocol = matched[0].get("transport_protocol", "") if matched else ""
            results.append({
                "ip": hit.get("ip", ""),
                "ports": ports,
                "transport_protocol": protocol,
            })
        return results

    # ------------------------------------------------------------------
    # Build manual lookup URLs (no key needed)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_search_urls(shodan_hash: int, md5_hash: str) -> dict:
        shodan_url = (
            f"https://www.shodan.io/search"
            f"?query=http.favicon.hash%3A{shodan_hash}"
        )
        censys_query = f'services.http.response.favicons.md5_hash="{md5_hash}"'
        censys_url = (
            "https://search.censys.io/search"
            f"?resource=hosts&q={urlquote(censys_query)}"
        )
        fofa_raw = f'icon_hash="{shodan_hash}"'
        fofa_b64 = base64.b64encode(fofa_raw.encode()).decode()
        fofa_url = f"https://fofa.info/result?qbase64={fofa_b64}"
        return {
            "shodan": shodan_url,
            "censys": censys_url,
            "fofa": fofa_url,
        }

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        shodan_key = (self.get_option("SHODAN_KEY") or "").strip()
        censys_id = (self.get_option("CENSYS_ID") or "").strip()
        censys_secret = (self.get_option("CENSYS_SECRET") or "").strip()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Favicon Search: {target}")
        print(f"{'='*60}{Colors.RESET}\n")

        # Step 1 — normalize target to a favicon URL
        try:
            favicon_url, host = self._build_favicon_url(target)
        except Exception as exc:
            print_status(f"Failed to parse target URL: {exc}", "error")
            return False
        print_status(f"Favicon URL: {favicon_url}", "info")

        # Step 2 — download favicon
        print_status("Downloading favicon...", "info")
        try:
            favicon_bytes = self._download_favicon(favicon_url)
        except Exception as exc:
            print_status(f"Could not download favicon: {exc}", "error")
            self.results = {
                "target": target,
                "favicon_url": favicon_url,
                "favicon_size_bytes": 0,
                "error": str(exc),
            }
            return False

        favicon_size = len(favicon_bytes)
        print_status(f"Downloaded {favicon_size} bytes", "success")

        # Step 3 — compute hashes
        print_status("Computing hashes...", "info")
        hashes = self._compute_hashes(favicon_bytes)
        shodan_hash = hashes["shodan"]
        md5_hash = hashes["md5"]
        sha256_hash = hashes["sha256"]
        mmh3_source = "mmh3 library" if _HAS_MMH3 else "pure-Python fallback"

        print_status(f"Shodan hash (MurmurHash3 via {mmh3_source}): {shodan_hash}", "success")
        print_status(f"MD5:    {md5_hash}", "success")
        print_status(f"SHA256: {sha256_hash}", "success")

        # Step 4 — Shodan API search
        shodan_results = []
        if shodan_key:
            print_status("Querying Shodan API...", "info")
            shodan_results = self._shodan_search(shodan_hash, shodan_key)
            if shodan_results:
                print_status(f"Shodan: {len(shodan_results)} result(s)", "success")
                for r in shodan_results:
                    hostnames = ", ".join(r["hostnames"][:3]) if r["hostnames"] else ""
                    print_status(
                        f"  {r['ip']}:{r['port']}  org={r['org']}  "
                        f"country={r['country']}  title={r['title']}"
                        + (f"  hostnames={hostnames}" if hostnames else ""),
                        "success",
                    )
            else:
                print_status("Shodan: no results", "warning")
        else:
            print_status("SHODAN_KEY not set — skipping API search", "warning")

        # Step 5 — Censys API search
        censys_results = []
        if censys_id and censys_secret:
            print_status("Querying Censys API...", "info")
            censys_results = self._censys_search(md5_hash, censys_id, censys_secret)
            if censys_results:
                print_status(f"Censys: {len(censys_results)} result(s)", "success")
                for r in censys_results:
                    ports_str = ", ".join(r["ports"]) if r["ports"] else "?"
                    print_status(
                        f"  {r['ip']}  ports={ports_str}  proto={r['transport_protocol']}",
                        "success",
                    )
            else:
                print_status("Censys: no results", "warning")
        else:
            print_status("CENSYS_ID/SECRET not set — skipping API search", "warning")

        # Step 6 — manual search URLs (always shown)
        search_urls = self._build_search_urls(shodan_hash, md5_hash)
        print_status("Manual lookup URLs (open in browser):", "info")
        print_status(f"  Shodan:  {search_urls['shodan']}", "info")
        print_status(f"  Censys:  {search_urls['censys']}", "info")
        print_status(f"  FOFA:    {search_urls['fofa']}", "info")

        total_found = len(shodan_results) + len(censys_results)
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}")
        print(f"  Total hosts found: {total_found} "
              f"(Shodan: {len(shodan_results)}, Censys: {len(censys_results)})")
        print(f"{'='*60}{Colors.RESET}\n")

        self.results = {
            "target": target,
            "favicon_url": favicon_url,
            "favicon_size_bytes": favicon_size,
            "shodan_hash": shodan_hash,
            "md5_hash": md5_hash,
            "sha256_hash": sha256_hash,
            "search_urls": search_urls,
            "shodan_results": shodan_results,
            "censys_results": censys_results,
            "total_found": total_found,
        }
        return True
