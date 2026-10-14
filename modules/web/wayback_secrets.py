"""wayback_secrets — search Wayback Machine snapshots for exposed secrets.

Workflow
--------
1. Query the CDX API for archived URLs under the target domain.
2. Filter URLs that look sensitive (by path pattern or file extension).
3. Fetch up to MAX_SNAPSHOTS of those archived pages (raw content via `if_` flag).
4. Scan content for API keys, credentials, and other secrets using regex patterns.
5. Report interesting paths and redacted secret matches.
"""
import re
import datetime
from urllib.parse import urlparse

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http


# ---------------------------------------------------------------------------
# Interest patterns — URLs that are worth fetching and scanning
# ---------------------------------------------------------------------------

_INTERESTING_KEYWORDS = [
    ".env", "config", "secrets", "credentials", "api", "token", "key",
    "passwd", "password", "backup", ".bak", ".sql", ".json", ".yaml",
    ".yml", ".xml", ".log", ".conf", "admin", "debug", "phpinfo",
    "swagger", "graphql", ".git", "composer.json", "package.json",
    "requirements.txt", "Dockerfile", ".htaccess", "wp-config",
]

_INTERESTING_EXTENSIONS = {
    ".env", ".bak", ".sql", ".log", ".conf", ".cfg", ".key",
    ".pem", ".cert", ".p12",
}


# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    # AWS access key
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    # AWS secret key label
    (re.compile(r"aws_secret_access_key\s*[=:]\s*\S+", re.I), "aws_secret_key"),
    # GitHub personal access token
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github_pat"),
    # GitHub server-to-server token
    (re.compile(r"ghs_[A-Za-z0-9]{36}"), "github_server_token"),
    # Slack token
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"), "slack_token"),
    # Generic key/token/secret assignment
    (
        re.compile(
            r'(?i)(?:password|passwd|secret|api_key|apikey|token)\s*[=:]\s*["\']([^"\']{8,})["\']'
        ),
        "generic_secret",
    ),
    # Email:password combos. The lookahead rejects host:port in a plain URL
    # (user@host.com:8080/path), which otherwise matched as a credential.
    (
        re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}:(?!\d+[/\s:]|\d+$)[^\s]{8,}"
        ),
        "email_password_combo",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(target: str) -> str:
    """Strip scheme and path from user input, return bare domain."""
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path.split("/")[0]
    # Strip port if present
    host = host.split(":")[0]
    # Not lstrip("www."): that strips any leading 'w'/'.' characters, turning
    # www.wordpress.com into ordpress.com.
    return host[4:] if host.startswith("www.") else host


def _is_interesting(url: str) -> str:
    """Return a reason string if the URL looks interesting, else empty string."""
    url_lower = url.lower()
    for kw in _INTERESTING_KEYWORDS:
        if kw in url_lower:
            return kw
    # Check extension
    path = urlparse(url).path.lower()
    for ext in _INTERESTING_EXTENSIONS:
        if path.endswith(ext):
            return ext
    return ""


def _redact(value: str) -> str:
    """Show first 4 and last 4 chars, mask the middle."""
    if len(value) <= 8:
        return value[:2] + "..." + value[-2:]
    return value[:4] + "..." + value[-4:]


def _scan_for_secrets(content: str, url: str, timestamp: str) -> list:
    """Apply all secret patterns against content; return list of finding dicts."""
    findings = []
    for pattern, label in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            raw = match.group(0)
            # For generic_secret, prefer the captured group (the actual value)
            if label == "generic_secret" and match.lastindex:
                raw_value = match.group(1)
            else:
                raw_value = raw
            if len(raw_value) < 8:
                continue
            findings.append({
                "url": url,
                "timestamp": timestamp,
                "type": label,
                "redacted_value": _redact(raw_value),
            })
    return findings


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class WaybackSecrets(BaseModule):
    name = "web/wayback_secrets"
    description = (
        "Search Wayback Machine snapshots for exposed API keys, "
        "credentials, and sensitive paths"
    )
    category = "web"
    # _extract_domain() accepts a bare host, so domain scans get this too.
    target_type = "url/domain"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Domain or URL to investigate")
        self.add_option(
            "YEARS_BACK", "3", False, "How many years back to search"
        )
        self.add_option(
            "MAX_SNAPSHOTS", "50", False,
            "Maximum number of interesting snapshots to probe"
        )

    # ------------------------------------------------------------------
    # CDX API fetch
    # ------------------------------------------------------------------

    def _cdx_fetch(self, cdx_url: str):
        """Fetch a CDX endpoint. Returns (rows, ok): ok is False on a request /
        HTTP / parse failure, so an unreachable CDX is not read as 'no data'."""
        rows = []
        try:
            resp = http.get(cdx_url, timeout=30)
            if resp.status_code != 200:
                print_status(f"CDX HTTP {resp.status_code} ({cdx_url[:80]}...)", "warning")
                return rows, False
            data = resp.json()
        except Exception as exc:
            print_status(f"CDX request failed ({cdx_url[:80]}...): {exc}", "warning")
            return rows, False
        if not data or len(data) < 2:
            return rows, True  # reachable, just no rows
        # First row is the header ["original", "timestamp"]
        header = data[0]
        try:
            orig_idx = header.index("original")
            ts_idx = header.index("timestamp")
        except ValueError:
            orig_idx, ts_idx = 0, 1
        for row in data[1:]:
            try:
                rows.append([row[orig_idx], row[ts_idx]])
            except IndexError:
                continue
        return rows, True

    def _fetch_all_cdx(self, domain: str, start_year: int) -> list:
        """Fetch both wildcard and direct CDX results; return merged, deduplicated rows."""
        base_params = (
            f"&output=json&fl=original,timestamp"
            f"&collapse=urlkey&limit=500&filter=statuscode:200&from={start_year}"
        )
        wild_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*{base_params}"
        )
        direct_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*{base_params}"
        )
        print_status("Fetching CDX wildcard index...", "info")
        rows_wild, ok_wild = self._cdx_fetch(wild_url)
        print_status(f"  CDX wildcard: {len(rows_wild)} URLs", "info")

        print_status("Fetching CDX direct index...", "info")
        rows_direct, ok_direct = self._cdx_fetch(direct_url)
        print_status(f"  CDX direct:   {len(rows_direct)} URLs", "info")

        # Record whether the CDX API was reachable at all, so an empty result
        # from an unreachable API is not mistaken for "no archived URLs".
        self._cdx_ok = ok_wild or ok_direct

        # Merge and deduplicate by URL
        seen = set()
        merged = []
        for orig, ts in rows_wild + rows_direct:
            if orig not in seen:
                seen.add(orig)
                merged.append({"url": orig, "timestamp": ts})
        return merged

    # ------------------------------------------------------------------
    # Snapshot probing
    # ------------------------------------------------------------------

    def _fetch_snapshot(self, timestamp: str, original_url: str) -> str:
        """Fetch a Wayback snapshot's raw content (without toolbar injection)."""
        wayback_url = (
            f"https://web.archive.org/web/{timestamp}if_/{original_url}"
        )
        try:
            resp = http.get(wayback_url, timeout=15, allow_redirects=True)
            if resp.status_code != 200:
                return ""
            try:
                return resp.content.decode("utf-8", errors="replace")
            except AttributeError:
                return resp.text or ""
        except Exception as exc:
            print_status(f"  Snapshot fetch failed: {exc}", "warning")
            return ""

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        try:
            years_back = int(self.get_option("YEARS_BACK") or 3)
        except (TypeError, ValueError):
            years_back = 3
        try:
            max_snapshots = int(self.get_option("MAX_SNAPSHOTS") or 50)
        except (TypeError, ValueError):
            max_snapshots = 50

        domain = _extract_domain(target)
        start_year = datetime.datetime.now().year - years_back

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*62}")
        print(f"  Wayback Secrets: {domain}")
        print(f"  Searching back to {start_year}  |  Max snapshots: {max_snapshots}")
        print(f"{'='*62}{Colors.RESET}\n")

        # Step 1 — fetch CDX index
        all_urls = self._fetch_all_cdx(domain, start_year)
        print_status(f"Total unique URLs from CDX: {len(all_urls)}", "info")

        if not all_urls:
            # CDX unreachable -> status UNKNOWN, not a clean "nothing archived".
            if not getattr(self, "_cdx_ok", True):
                print_status("CDX API unreachable - archived-URL status UNKNOWN, "
                             "not 'no URLs / no secrets'", "error")
                self.results = {
                    "domain": domain,
                    "interesting_urls": [],
                    "potential_secrets": [],
                    "total_snapshots_checked": 0,
                    "total_interesting": 0,
                    "total_secrets": 0,
                    "error": "fetch_failed",
                }
                return False
            print_status("No archived URLs found for this domain", "warning")
            self.results = {
                "domain": domain,
                "interesting_urls": [],
                "potential_secrets": [],
                "total_snapshots_checked": 0,
                "total_interesting": 0,
                "total_secrets": 0,
            }
            return True

        # Step 2 — filter interesting URLs
        interesting_urls = []
        for entry in all_urls:
            reason = _is_interesting(entry["url"])
            if reason:
                interesting_urls.append({
                    "url": entry["url"],
                    "timestamp": entry["timestamp"],
                    "reason": reason,
                })

        print_status(
            f"Interesting URLs found: {len(interesting_urls)} / {len(all_urls)}",
            "info",
        )

        if interesting_urls:
            print(f"\n  {Colors.BOLD}Interesting paths:{Colors.RESET}")
            for entry in interesting_urls[:30]:
                print_status(
                    f"  [{entry['timestamp']}]  {entry['url']}  "
                    f"({Colors.YELLOW}{entry['reason']}{Colors.RESET})",
                    "success",
                )
            if len(interesting_urls) > 30:
                print_status(
                    f"  ... and {len(interesting_urls) - 30} more (see results dict)",
                    "info",
                )

        # Step 3 — probe interesting snapshots
        to_probe = interesting_urls[:max_snapshots]
        print(f"\n  {Colors.BOLD}Probing {len(to_probe)} snapshot(s) for secrets...{Colors.RESET}\n")

        potential_secrets = []
        snapshots_checked = 0

        for idx, entry in enumerate(to_probe, 1):
            print_status(
                f"[{idx}/{len(to_probe)}] {entry['url'][:80]}",
                "info",
            )
            content = self._fetch_snapshot(entry["timestamp"], entry["url"])
            snapshots_checked += 1
            if not content:
                continue

            findings = _scan_for_secrets(content, entry["url"], entry["timestamp"])
            if findings:
                for f in findings:
                    potential_secrets.append(f)
                    print_status(
                        f"  {Colors.RED}[SECRET]{Colors.RESET} "
                        f"type={f['type']}  "
                        f"redacted={Colors.YELLOW}{f['redacted_value']}{Colors.RESET}",
                        "warning",
                    )

        # Step 4 — summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*62}")
        print(f"  Summary — {domain}")
        print(f"{'='*62}{Colors.RESET}")
        print(f"  Total URLs indexed:      {len(all_urls)}")
        print(f"  Interesting paths:       {len(interesting_urls)}")
        print(f"  Snapshots probed:        {snapshots_checked}")
        print(
            f"  Potential secrets:       "
            f"{Colors.RED if potential_secrets else Colors.GREEN}"
            f"{len(potential_secrets)}{Colors.RESET}"
        )

        if potential_secrets:
            print(f"\n  {Colors.BOLD}Secret findings:{Colors.RESET}")
            for f in potential_secrets:
                print_status(
                    f"  [{f['timestamp']}] {f['url'][:60]}  "
                    f"type={f['type']}  value={f['redacted_value']}",
                    "warning",
                )
        print()

        self.results = {
            "domain": domain,
            "interesting_urls": interesting_urls,
            "potential_secrets": potential_secrets,
            "total_snapshots_checked": snapshots_checked,
            "total_interesting": len(interesting_urls),
            "total_secrets": len(potential_secrets),
        }
        return True
