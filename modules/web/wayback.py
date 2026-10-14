"""Deep Wayback Machine OSINT.

Pulls historical URLs from the CDX API, categorises them, finds entries that
disappeared (200-then-404/403), mines snapshot bodies for emails / phones /
endpoints / cloud URLs, and compares oldest vs. newest page titles.

The Internet Archive CDX API is free and unauthenticated:
    http://web.archive.org/cdx/search/cdx
"""

import re
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from core.base_module import BaseModule
from core.utils import (
    EMAIL_RE,
    PHONE_RE,
    URL_RE,
    Colors,
    print_status,
)
from core import http


CDX_API = "http://web.archive.org/cdx/search/cdx"
WAYBACK_SNAPSHOT = "http://web.archive.org/web/{ts}id_/{url}"

# High-value file extensions grouped by purpose. Keys become bucket names in
# ``self.results["interesting_files"]`` and the output report.
INTERESTING_EXT = {
    "pdf": [".pdf"],
    "doc": [".doc", ".docx"],
    "xls": [".xls", ".xlsx"],
    "ppt": [".ppt", ".pptx"],
    "sql": [".sql", ".sqlite", ".db", ".dbf"],
    "backup": [".bak", ".backup", ".old", ".orig", ".save", ".swp", "~"],
    "config": [".env", ".config", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".toml"],
    "vcs": [".git", ".svn", ".hg", ".bzr"],
    "key": [".key", ".pem", ".crt", ".cer", ".p12", ".pfx", ".jks"],
    "log": [".log"],
    "archive": [".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".gz", ".bz2"],
    "data": [".json", ".xml", ".csv", ".tsv"],
    "map": [".map"],
}

# Cloud storage patterns worth surfacing.
CLOUD_PATTERNS = [
    re.compile(r"https?://[\w.-]*\.s3[\w.-]*\.amazonaws\.com/[^\s\"'<>]*", re.I),
    re.compile(r"https?://s3[\w.-]*\.amazonaws\.com/[\w.-]+/[^\s\"'<>]*", re.I),
    re.compile(r"https?://[\w.-]+\.blob\.core\.windows\.net/[^\s\"'<>]*", re.I),
    re.compile(r"https?://storage\.googleapis\.com/[^\s\"'<>]*", re.I),
    re.compile(r"https?://[\w.-]+\.r2\.cloudflarestorage\.com/[^\s\"'<>]*", re.I),
    re.compile(r"https?://[\w.-]+\.digitaloceanspaces\.com/[^\s\"'<>]*", re.I),
]

SOCIAL_HOSTS = (
    "twitter.com", "x.com", "facebook.com", "linkedin.com", "instagram.com",
    "youtube.com", "youtu.be", "tiktok.com", "pinterest.com", "reddit.com",
    "t.me", "telegram.me", "discord.gg", "medium.com", "snapchat.com",
)
GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "gitea.com", "codeberg.org")

ENDPOINT_RE = re.compile(
    r"""(?<![\w/])(/(?:api|v[0-9]{1,2}|rest|graphql|internal|admin|private|services?)/[\w./\-?=&%:+]+)""",
    re.I,
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
# Simple "First Last" style name heuristic (two capitalised words 3+ chars).
NAME_RE = re.compile(r"\b([A-Z][a-z]{2,})\s+([A-Z][a-z]{2,})\b")

MIME_SKIP = ("image/", "video/", "audio/", "font/", "application/octet-stream")


def _ext_bucket(url):
    """Return the first INTERESTING_EXT bucket this URL falls into, or None."""
    lower = url.lower().split("?", 1)[0]
    for bucket, exts in INTERESTING_EXT.items():
        for ext in exts:
            if ext.startswith(".") and lower.endswith(ext):
                return bucket
            if not ext.startswith(".") and lower.endswith(ext):
                return bucket
            # Handle VCS directories like /.git/HEAD and /.env.local
            if ext in ("/.git", "/.svn", "/.hg", "/.bzr") or ext in lower.split("/"):
                return bucket
    # fall back for .git/ etc appearing as a path segment
    for bucket, exts in INTERESTING_EXT.items():
        for ext in exts:
            if ext.startswith(".") and f"/{ext.lstrip('.')}/" in lower:
                return bucket
    return None


def _year_from_ts(ts):
    if ts and len(ts) >= 4 and ts[:4].isdigit():
        return ts[:4]
    return None


def _fmt_date(ts):
    if not ts or len(ts) < 8:
        return ts or ""
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"


class Wayback(BaseModule):
    name = "web/wayback"
    description = "Deep Wayback Machine OSINT: historical URLs, deleted content, snapshot mining"
    category = "web"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain (e.g. example.com)")
        self.add_option("MAX_URLS", "1000", False, "Hard cap on URLs pulled from CDX")
        self.add_option("YEAR_FROM", "", False, "Only include snapshots from this year (YYYY)")
        self.add_option("YEAR_TO", "", False, "Only include snapshots up to this year (YYYY)")
        self.add_option(
            "EXTRACT_CONTENT",
            "false",
            False,
            "If 'true', fetch snapshots and mine for emails/endpoints/etc. (slower)",
        )
        self.add_option(
            "FIND_DELETED",
            "true",
            False,
            "If 'true', HEAD current URLs and flag ones that used to be 200 but are now gone",
        )
        self.add_option(
            "MAX_CONTENT_FETCHES",
            "20",
            False,
            "Cap on how many snapshot bodies to download for content mining",
        )
        self.add_option("THREADS", "10", False, "Parallel workers for snapshot/HEAD fetches")
        self.add_option(
            "MIME_SCAN",
            "false",
            False,
            "If 'true', run extra CDX queries by mimetype (pdf/sql/zip) — slower but catches extensionless files",
        )

    # ------------------------------------------------------------------
    # option helpers
    # ------------------------------------------------------------------
    def _int_opt(self, name, default):
        raw = self.get_option(name)
        try:
            return int(str(raw).strip())
        except (TypeError, ValueError):
            return default

    def _bool_opt(self, name, default=False):
        raw = (self.get_option(name) or "").strip().lower()
        if raw in ("1", "true", "yes", "y", "on"):
            return True
        if raw in ("0", "false", "no", "n", "off"):
            return False
        return default

    # ------------------------------------------------------------------
    # CDX queries
    # ------------------------------------------------------------------
    def _cdx(self, params, warnings):
        """Call CDX with ``params`` (dict). Returns the parsed JSON rows or []."""
        try:
            resp = http.get(CDX_API, params=params, timeout=45)
        except Exception as exc:
            warnings.append(f"CDX request failed: {exc}")
            return []
        if resp.status_code != 200:
            warnings.append(f"CDX returned HTTP {resp.status_code}")
            return []
        try:
            data = resp.json()
        except ValueError:
            warnings.append("CDX returned non-JSON body")
            return []
        if not data or len(data) < 2:
            return []
        # data[0] is header row; return remaining rows
        return data[1:]

    def _query_all(self, target, max_urls, year_from, year_to, warnings):
        """Fetch the full URL inventory for ``target/*`` (collapsed by urlkey)."""
        params = {
            "url": f"{target}/*",
            "output": "json",
            "collapse": "urlkey",
            "fl": "original,timestamp,statuscode,mimetype",
            "limit": str(max_urls),
        }
        if year_from:
            params["from"] = str(year_from)
        if year_to:
            params["to"] = str(year_to)
        return self._cdx(params, warnings)

    def _query_by_mime(self, target, mime, limit, warnings):
        params = {
            "url": f"{target}/*",
            "output": "json",
            "collapse": "urlkey",
            "fl": "original,timestamp,statuscode,mimetype",
            "filter": f"mimetype:{mime}",
            "limit": str(limit),
        }
        return self._cdx(params, warnings)

    def _query_timeline(self, target, warnings, limit=20000):
        """One-row-per-year-ish timestamps for timeline rendering.

        Uses ``collapse=timestamp:4`` so the server keeps a single row per year
        — a massively lighter payload than pulling every snapshot.
        """
        params = {
            "url": f"{target}/*",
            "output": "json",
            "fl": "timestamp",
            "collapse": "timestamp:4",
            "limit": str(limit),
        }
        return self._cdx(params, warnings)

    # ------------------------------------------------------------------
    # Snapshot fetch + content mining
    # ------------------------------------------------------------------
    def _fetch_snapshot(self, url, timestamp):
        """Download the raw (id_) snapshot body. Returns text or None."""
        snap = WAYBACK_SNAPSHOT.format(ts=timestamp, url=url)
        try:
            resp = http.get(snap, timeout=25)
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        ctype = resp.headers.get("Content-Type", "").lower()
        if any(skip in ctype for skip in MIME_SKIP):
            return None
        try:
            return resp.text
        except Exception:
            return None

    def _mine_content(self, body, target):
        """Extract OSINT nuggets from a snapshot body."""
        found = {
            "emails": set(),
            "phones": set(),
            "names": set(),
            "endpoints": set(),
            "subdomains": set(),
            "social": set(),
            "git": set(),
            "cloud": set(),
        }
        if not body:
            return found

        for m in EMAIL_RE.findall(body):
            found["emails"].add(m.lower())

        for m in PHONE_RE.findall(body):
            digits = re.sub(r"\D", "", m)
            # keep plausible international numbers only
            if 10 <= len(digits) <= 15:
                found["phones"].add(m.strip())

        # Light-weight people-name heuristic. Full HTML tags trip this up, so
        # we work off visible text only (anything that isn't inside <...>).
        visible = re.sub(r"<[^>]+>", " ", body)
        for first, last in NAME_RE.findall(visible):
            found["names"].add(f"{first} {last}")

        for m in ENDPOINT_RE.findall(body):
            found["endpoints"].add(m.split("#", 1)[0])

        urls_in_body = URL_RE.findall(body)
        for raw in urls_in_body:
            u = raw.rstrip(".,);\"'")
            host = urlparse(u).netloc.lower()
            if not host:
                continue
            if host.endswith(target) and host != target:
                found["subdomains"].add(host)
            if any(host == s or host.endswith("." + s) for s in SOCIAL_HOSTS):
                found["social"].add(u)
            if any(host == g or host.endswith("." + g) for g in GIT_HOSTS):
                found["git"].add(u)

        for pat in CLOUD_PATTERNS:
            for m in pat.findall(body):
                found["cloud"].add(m)

        return found

    # ------------------------------------------------------------------
    # Deleted URL detection
    # ------------------------------------------------------------------
    def _check_current(self, url):
        """HEAD the live URL; return the integer status (or None on error)."""
        try:
            resp = http.head(url, timeout=12, allow_redirects=True)
            return resp.status_code
        except Exception:
            try:
                resp = http.get(url, timeout=12, stream=True)
                return resp.status_code
            except Exception:
                return None

    # ------------------------------------------------------------------
    # Rich output helpers
    # ------------------------------------------------------------------
    def _print_header(self, text):
        print()
        print(f"  {Colors.BOLD}{Colors.CYAN}{text}{Colors.RESET}")
        print(f"  {Colors.DIM}{'-' * max(len(text), 20)}{Colors.RESET}")

    def _print_kv(self, key, value, color=Colors.WHITE):
        print(f"    {Colors.DIM}{key:<22}{Colors.RESET} {color}{value}{Colors.RESET}")

    # ------------------------------------------------------------------
    # main entry
    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        started = time.time()
        target = (self.get_option("TARGET") or "").strip().lower()
        # Strip scheme & path if user pasted a URL.
        if "://" in target:
            target = urlparse(target).netloc or target
        target = target.lstrip(".").split("/")[0]

        max_urls = max(1, self._int_opt("MAX_URLS", 1000))
        year_from = (self.get_option("YEAR_FROM") or "").strip()
        year_to = (self.get_option("YEAR_TO") or "").strip()
        extract_content = self._bool_opt("EXTRACT_CONTENT", False)
        find_deleted = self._bool_opt("FIND_DELETED", True)
        mime_scan = self._bool_opt("MIME_SCAN", False)
        max_fetches = max(0, self._int_opt("MAX_CONTENT_FETCHES", 20))
        threads = max(1, self._int_opt("THREADS", 10))

        warnings = []

        print_status(f"Wayback deep OSINT on {target}", "info")
        print_status(
            f"max_urls={max_urls} years={year_from or '*'}-{year_to or '*'} "
            f"extract_content={extract_content} find_deleted={find_deleted}",
            "info",
        )

        # --------------------------------------------------------------
        # 1. Primary URL inventory
        # --------------------------------------------------------------
        rows = self._query_all(target, max_urls, year_from, year_to, warnings)
        print_status(f"CDX returned {len(rows)} rows for {target}/*", "success" if rows else "warning")

        snapshots = []
        urls_seen = {}  # url -> {"first": ts, "last": ts, "statuses": set, "mime": str}
        for row in rows:
            if len(row) < 4:
                continue
            url, ts, status, mime = row[0], row[1], row[2], row[3]
            snapshots.append({"url": url, "timestamp": ts, "status": status, "mimetype": mime})
            rec = urls_seen.setdefault(url, {"first": ts, "last": ts, "statuses": set(), "mime": mime})
            if ts < rec["first"]:
                rec["first"] = ts
            if ts > rec["last"]:
                rec["last"] = ts
            rec["statuses"].add(status)

        unique_urls = sorted(urls_seen.keys())
        unique_paths = sorted({urlparse(u).path or "/" for u in unique_urls})

        # --------------------------------------------------------------
        # 2. Timeline (year breakdown + span)
        # --------------------------------------------------------------
        # Count what we already have per-year from the main query.
        by_year = Counter()
        for s in snapshots:
            y = _year_from_ts(s["timestamp"])
            if y:
                by_year[y] += 1

        # Supplement with a lightweight year-presence probe (one row per year)
        # so we don't miss years that fell outside MAX_URLS. Only runs if the
        # main query likely truncated (returned exactly MAX_URLS rows).
        if len(snapshots) >= max_urls:
            for row in self._query_timeline(target, warnings):
                y = _year_from_ts(row[0] if row else "")
                if y and y not in by_year:
                    by_year[y] = 0  # year exists but we don't know the count

        first_archived = ""
        last_archived = ""
        if by_year:
            years_sorted = sorted(by_year)
            first_archived = f"{years_sorted[0]}-01-01"
            last_archived = f"{years_sorted[-1]}-12-31"
        if snapshots:
            all_ts = sorted(s["timestamp"] for s in snapshots if s["timestamp"])
            if all_ts:
                first_archived = _fmt_date(all_ts[0])
                last_archived = _fmt_date(all_ts[-1])

        total_snaps = sum(by_year.values()) or len(snapshots)
        year_span = ""
        if by_year:
            yrs = sorted(by_year)
            year_span = f"{yrs[0]}-{yrs[-1]} ({int(yrs[-1]) - int(yrs[0]) + 1} years, {total_snaps} snapshots)"

        # --------------------------------------------------------------
        # 3. Interesting files (bucketed by extension)
        # --------------------------------------------------------------
        interesting_files = defaultdict(list)
        for u in unique_urls:
            bucket = _ext_bucket(u)
            if bucket:
                interesting_files[bucket].append(u)

        # Secondary CDX pass by mimetype for things the URL extension misses
        # (PDFs served without extension, SQL dumps served as octet-stream, ...).
        # Opt-in because each mime adds a CDX round-trip (slow on huge domains).
        mime_passes = (
            ("application/pdf", "pdf"),
            ("application/sql", "sql"),
            ("application/zip", "archive"),
        ) if mime_scan else ()
        for mime, bucket in mime_passes:
            extra = self._query_by_mime(target, mime, 200, warnings)
            for row in extra:
                if len(row) < 1:
                    continue
                u = row[0]
                if u not in urls_seen:
                    urls_seen[u] = {
                        "first": row[1] if len(row) > 1 else "",
                        "last": row[1] if len(row) > 1 else "",
                        "statuses": {row[2]} if len(row) > 2 else set(),
                        "mime": mime,
                    }
                if u not in interesting_files[bucket]:
                    interesting_files[bucket].append(u)

        # --------------------------------------------------------------
        # 4. Deleted content discovery
        # --------------------------------------------------------------
        deleted_urls = []
        if find_deleted and unique_urls:
            # Only check URLs that archive ever saw as 200 (otherwise "gone" is uninteresting).
            candidates = [u for u, meta in urls_seen.items() if "200" in meta["statuses"]]
            # Keep it bounded.
            candidates = candidates[: min(len(candidates), max(200, max_urls // 2))]
            print_status(
                f"Checking {len(candidates)} archived-200 URLs for deletion ...", "info"
            )
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {pool.submit(self._check_current, u): u for u in candidates}
                for fut in as_completed(futures):
                    u = futures[fut]
                    code = fut.result()
                    if code in (404, 403, 410):
                        meta = urls_seen[u]
                        last_year = _year_from_ts(meta["last"]) or "?"
                        deleted_urls.append({
                            "url": u,
                            "current_status": code,
                            "last_archived_200": _fmt_date(meta["last"]),
                            "last_year": last_year,
                        })

        # --------------------------------------------------------------
        # 5. Content mining (optional, slower)
        # --------------------------------------------------------------
        content_mined = {
            "emails": [], "phones": [], "names": [], "endpoints": [],
            "subdomains_referenced": [], "social_links": [], "git_links": [],
            "cloud_urls": [],
        }
        title_history = []

        if extract_content and unique_urls and max_fetches > 0:
            # Pick a diverse-ish sample: html snapshots, prefer root/index/about pages.
            def _rank(u):
                lu = u.lower()
                path = urlparse(lu).path
                base_score = 0
                if path in ("", "/", "/index.html", "/index.php", "/home"):
                    base_score = 10
                for kw in ("about", "contact", "team", "staff", "privacy", "careers"):
                    if kw in path:
                        base_score = max(base_score, 7)
                if any(path.endswith(x) for x in (".html", ".htm", ".php", "/")):
                    base_score += 1
                return -base_score, u

            html_candidates = [u for u in unique_urls if _ext_bucket(u) is None]
            html_candidates.sort(key=_rank)
            sample = html_candidates[:max_fetches]

            print_status(
                f"Fetching {len(sample)} snapshots for content mining ...", "info"
            )
            agg = {k: set() for k in (
                "emails", "phones", "names", "endpoints",
                "subdomains", "social", "git", "cloud",
            )}

            # Track per-URL title (oldest + newest) while we're here.
            per_url_titles = {}

            def _task(u):
                meta = urls_seen.get(u) or {}
                first_ts = meta.get("first", "")
                last_ts = meta.get("last", "") or first_ts
                oldest = self._fetch_snapshot(u, first_ts) if first_ts else None
                newest = self._fetch_snapshot(u, last_ts) if last_ts and last_ts != first_ts else oldest
                return u, first_ts, last_ts, oldest, newest

            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {pool.submit(_task, u): u for u in sample}
                for fut in as_completed(futures):
                    try:
                        u, first_ts, last_ts, oldest, newest = fut.result()
                    except Exception as exc:
                        warnings.append(f"Snapshot fetch failed: {exc}")
                        continue

                    # Mine both versions.
                    for body in (oldest, newest):
                        if not body:
                            continue
                        pulls = self._mine_content(body, target)
                        for k in agg:
                            agg[k].update(pulls[k])

                    # Title history.
                    old_title = ""
                    new_title = ""
                    if oldest:
                        m = TITLE_RE.search(oldest)
                        if m:
                            old_title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
                    if newest:
                        m = TITLE_RE.search(newest)
                        if m:
                            new_title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
                    if old_title or new_title:
                        per_url_titles[u] = {
                            "url": u,
                            "oldest_timestamp": _fmt_date(first_ts),
                            "newest_timestamp": _fmt_date(last_ts),
                            "oldest_title": old_title,
                            "newest_title": new_title,
                            "changed": bool(old_title and new_title and old_title != new_title),
                        }

            content_mined["emails"] = sorted(agg["emails"])
            content_mined["phones"] = sorted(agg["phones"])
            content_mined["names"] = sorted(agg["names"])
            content_mined["endpoints"] = sorted(agg["endpoints"])
            content_mined["subdomains_referenced"] = sorted(agg["subdomains"])
            content_mined["social_links"] = sorted(agg["social"])
            content_mined["git_links"] = sorted(agg["git"])
            content_mined["cloud_urls"] = sorted(agg["cloud"])
            title_history = sorted(per_url_titles.values(), key=lambda r: r["url"])

        # --------------------------------------------------------------
        # 6. Pretty report
        # --------------------------------------------------------------
        self._print_header("Timeline")
        if year_span:
            self._print_kv("Archive spans", year_span, Colors.CYAN)
        if first_archived:
            self._print_kv("First archived", first_archived, Colors.WHITE)
        if last_archived:
            self._print_kv("Last archived", last_archived, Colors.WHITE)
        if by_year:
            top = sorted(by_year.items())[-5:]
            self._print_kv(
                "Recent years",
                ", ".join(f"{y}:{c}" for y, c in top),
                Colors.WHITE,
            )

        self._print_header("URL Inventory")
        self._print_kv("Unique URLs", str(len(unique_urls)), Colors.GREEN)
        self._print_kv("Unique paths", str(len(unique_paths)), Colors.GREEN)
        self._print_kv("Raw snapshots", str(len(snapshots)), Colors.WHITE)

        if interesting_files:
            self._print_header("Interesting Files")
            for bucket in sorted(interesting_files):
                items = interesting_files[bucket]
                if not items:
                    continue
                print(
                    f"    {Colors.YELLOW}[FILE]{Colors.RESET} "
                    f"{len(items):>4} {bucket.upper():<8} "
                    f"{Colors.DIM}e.g. {items[0][:90]}{Colors.RESET}"
                )

        if find_deleted and deleted_urls:
            self._print_header("Deleted / Removed URLs")
            for d in deleted_urls[:25]:
                print(
                    f"    {Colors.RED}[DELETED]{Colors.RESET} "
                    f"{d['url'][:100]} "
                    f"{Colors.DIM}(last 200: {d['last_year']}, now {d['current_status']}){Colors.RESET}"
                )
            if len(deleted_urls) > 25:
                print(f"    {Colors.DIM}... {len(deleted_urls) - 25} more{Colors.RESET}")

        if extract_content:
            self._print_header("Content Mining")
            buckets = [
                ("Emails", content_mined["emails"]),
                ("Phones", content_mined["phones"]),
                ("Names", content_mined["names"]),
                ("API endpoints", content_mined["endpoints"]),
                ("Subdomains", content_mined["subdomains_referenced"]),
                ("Social links", content_mined["social_links"]),
                ("Git links", content_mined["git_links"]),
                ("Cloud URLs", content_mined["cloud_urls"]),
            ]
            for label, items in buckets:
                if not items:
                    continue
                sample_items = ", ".join(items[:3])
                print(
                    f"    {Colors.GREEN}[MINE]{Colors.RESET} "
                    f"{label:<16} {len(items):>4}  "
                    f"{Colors.DIM}{sample_items[:90]}{Colors.RESET}"
                )

            changed_titles = [t for t in title_history if t["changed"]]
            if changed_titles:
                self._print_header("Title History (changed)")
                for t in changed_titles[:10]:
                    print(f"    {Colors.MAGENTA}{t['url'][:80]}{Colors.RESET}")
                    print(f"      {Colors.DIM}{t['oldest_timestamp']}:{Colors.RESET} {t['oldest_title'][:80]}")
                    print(f"      {Colors.DIM}{t['newest_timestamp']}:{Colors.RESET} {t['newest_title'][:80]}")

        duration = round(time.time() - started, 2)
        interesting_file_count = sum(len(v) for v in interesting_files.values())

        self.results = {
            "target": target,
            "urls_found": len(unique_urls),
            "unique_paths": unique_paths,
            "unique_urls": unique_urls,
            "deleted_urls": deleted_urls,
            "interesting_files": {k: v for k, v in interesting_files.items()},
            "timeline": {
                "first_archived": first_archived,
                "last_archived": last_archived,
                "by_year": dict(sorted(by_year.items())),
                "total_snapshots": total_snaps,
            },
            "content_mined": content_mined,
            "title_history": title_history,
            "snapshots": snapshots,
            "stats": {
                "total_urls": len(unique_urls),
                "deleted_count": len(deleted_urls),
                "interesting_file_count": interesting_file_count,
                "duration_sec": duration,
            },
            "warnings": warnings,
        }

        print()
        print_status(
            f"Wayback OSINT complete in {duration}s: "
            f"{len(unique_urls)} URLs, {interesting_file_count} interesting, "
            f"{len(deleted_urls)} deleted",
            "success",
        )
        return True
