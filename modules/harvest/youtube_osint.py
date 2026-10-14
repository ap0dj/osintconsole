"""YouTube OSINT - channel @handle scrape + RSS feed + bio pivot.

Zero-auth: pulls everything from the public ``/@handle`` page (og: meta tags
and embedded ``ytInitialData`` JSON) plus the public RSS/Atom feed for the
latest videos and channel ID. No API key, no login, no cookies.
"""

import re
import json
import xml.etree.ElementTree as ET
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest._social_base import (
    confidence_tier,
    print_uncertainty_box,
    build_disclaimer,
    tag_candidate,
)

# Soft import: shared variation helpers may be missing. Degrade cleanly.
try:
    from modules.harvest.username_variations import (
        generate_variations,
        extract_handles_from_bio,
    )
    _VARIATIONS_OK = True
except Exception:
    _VARIATIONS_OK = False

    def generate_variations(_u, _n=20):
        return []

    def extract_handles_from_bio(_text):
        return {}


# YouTube @handle rules: 3-30 chars, letters/digits/hyphens/dots/underscores.
# Leading '@' is stripped before validation.
_YOUTUBE_HANDLE_RE = re.compile(r"^[A-Za-z0-9._\-]{3,30}$")

# Pattern to find the ytInitialData JSON blob embedded in the page source.
_YT_INITIAL_DATA_RE = re.compile(
    r"(?:var\s+ytInitialData|window\[\"ytInitialData\"\])\s*=\s*(\{.*?\});\s*</script>",
    re.DOTALL,
)

# Atom/RSS namespace for YouTube feeds.
_ATOM_NS = "http://www.w3.org/2005/Atom"
_YT_NS = "http://www.youtube.com/xml/schemas/2015"
_MEDIA_NS = "http://search.yahoo.com/mrss/"


def _verification_hints_youtube(candidate):
    hints = [
        "Check the channel creation date against target's known online history",
        "Video upload frequency and content style should match target's known patterns",
        "Channel About section links/social handles are strong identity indicators",
        "Subscriber count and content niche should align with target's known interests",
        "YouTube channel IDs are permanent — even if handle changes the /channel/UC... URL stays",
    ]
    if candidate.get("verified"):
        hints.insert(
            0,
            "This channel has a verified badge — only established creators receive this. "
            "Unlikely to be a private individual unless they are a known public figure.",
        )
    return hints


class YoutubeOsint(BaseModule):
    name = "harvest/youtube_osint"
    description = "YouTube channel OSINT via public @handle page scrape"
    category = "harvest"
    target_type = "username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True,  "YouTube @handle (with or without @)")
        self.add_option("VARIATIONS", "true", False, "Pivot via handle variations")
        self.add_option("MAX_VARIATIONS", "15", False, "Max variations to probe")

    # ------------------------------------------------------------------ helpers

    def _clean(self, handle):
        handle = (handle or "").strip().lstrip("@")
        handle = re.sub(r"https?://(?:www\.)?youtube\.com/@", "", handle)
        return handle.strip("/").split("?")[0].split("/")[0]

    def _bool_opt(self, name, default=True):
        val = (self.get_option(name) or "").strip().lower()
        if not val:
            return default
        return val in ("true", "1", "yes", "on")

    def _int_opt(self, name, default):
        try:
            return int(self.get_option(name))
        except (TypeError, ValueError):
            return default

    # ------------------------------------------------------------------ scrape

    def _fetch_page(self, handle, path="", warnings=None):
        """GET youtube.com/@{handle}{path}. Returns (status, html) or (status, '')."""
        if warnings is None:
            warnings = []
        url = f"https://www.youtube.com/@{handle}{path}"
        try:
            resp = http.get(url, timeout=15)
            if resp.status_code == 429:
                warnings.append(f"HTTP 429 (rate-limited) for @{handle}{path}")
                return 429, ""
            return resp.status_code, resp.text or ""
        except Exception as exc:
            warnings.append(f"Page fetch error for @{handle}{path}: {exc}")
            return 0, ""

    def _parse_meta(self, html):
        """Extract og: meta tags from YouTube page HTML."""
        out = {}
        for prop, key in [
            ("og:title",       "og_title"),
            ("og:description", "og_description"),
            ("og:image",       "og_image"),
            ("og:url",         "og_url"),
        ]:
            # property="..." content="..."  OR  content="..." property="..."
            m = re.search(
                rf'<meta\s+[^>]*property=["\']({re.escape(prop)})["\'][^>]*content=["\']([^"\']*)["\']',
                html, re.IGNORECASE,
            )
            if m:
                out[key] = m.group(2).strip()
                continue
            m = re.search(
                rf'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*property=["\']({re.escape(prop)})["\']',
                html, re.IGNORECASE,
            )
            if m:
                out[key] = m.group(1).strip()
        return out

    def _parse_yt_initial_data(self, html):
        """Extract and parse the ytInitialData JSON blob. Returns dict or {}."""
        m = _YT_INITIAL_DATA_RE.search(html or "")
        if not m:
            return {}
        raw = m.group(1)
        # The greedy .*? in DOTALL mode can overshoot — try increasingly short slices
        for end in [len(raw), 500_000, 200_000, 100_000]:
            if end > len(raw):
                continue
            try:
                return json.loads(raw[:end])
            except (ValueError, json.JSONDecodeError):
                continue
        return {}

    def _extract_subscriber_count(self, html, yt_data):
        """Pull subscriber count from multiple locations."""
        # 1. ytInitialData path: header.c4TabbedHeaderRenderer.subscriberCountText
        try:
            header = (
                yt_data
                .get("header", {})
                .get("c4TabbedHeaderRenderer", {})
            )
            sc = (
                header.get("subscriberCountText", {})
                      .get("simpleText")
                or header.get("subscriberCountText", {})
                         .get("runs", [{}])[0]
                         .get("text")
            )
            if sc:
                return sc.strip()
        except (AttributeError, IndexError, TypeError):
            pass

        # 2. Raw JSON string in page source: "subscriberCountText":{"simpleText":"..."}
        m = re.search(
            r'"subscriberCountText"\s*:\s*\{"simpleText"\s*:\s*"([^"]+)"',
            html or "",
        )
        if m:
            return m.group(1).strip()

        # 3. Alternate runs format
        m = re.search(
            r'"subscriberCountText"\s*:\s*\{"runs"\s*:\s*\[\{"text"\s*:\s*"([^"]+)"',
            html or "",
        )
        if m:
            return m.group(1).strip()

        return None

    def _extract_channel_id(self, html, yt_data, meta):
        """Derive the persistent UCxxxx channel ID from multiple sources."""
        # 1. og:url — youtube.com/channel/UCxxxx
        og_url = meta.get("og_url") or ""
        m = re.search(r"/channel/(UC[A-Za-z0-9_\-]+)", og_url)
        if m:
            return m.group(1)

        # 2. Canonical link in HTML
        m = re.search(
            r'<link\s+rel="canonical"\s+href="[^"]*channel/(UC[A-Za-z0-9_\-]+)"',
            html or "", re.IGNORECASE,
        )
        if m:
            return m.group(1)

        # 3. externalId in ytInitialData
        try:
            cid = (
                yt_data
                .get("header", {})
                .get("c4TabbedHeaderRenderer", {})
                .get("channelId")
            )
            if cid and cid.startswith("UC"):
                return cid
        except (AttributeError, TypeError):
            pass

        # 4. Raw string scan: "externalId":"UCxxxx"
        m = re.search(r'"externalId"\s*:\s*"(UC[A-Za-z0-9_\-]+)"', html or "")
        if m:
            return m.group(1)

        # 5. Browse ID in metadata renderer
        m = re.search(r'"browseId"\s*:\s*"(UC[A-Za-z0-9_\-]+)"', html or "")
        if m:
            return m.group(1)

        return None

    def _extract_verified(self, yt_data, html):
        """Return True if the channel has a verified badge."""
        try:
            badges = (
                yt_data
                .get("header", {})
                .get("c4TabbedHeaderRenderer", {})
                .get("badges", [])
            )
            for badge in badges:
                badge_renderer = (badge.get("metadataBadgeRenderer") or {})
                style = badge_renderer.get("style") or ""
                icon = (badge_renderer.get("icon") or {}).get("iconType") or ""
                if "VERIFIED" in style.upper() or "VERIFIED" in icon.upper():
                    return True
        except (AttributeError, TypeError):
            pass
        if re.search(r'"VERIFIED"', html or ""):
            return True
        return False

    # ------------------------------------------------------------------ RSS feed

    def _fetch_rss(self, handle, channel_id, warnings):
        """Try to retrieve the RSS/Atom feed; returns (channel_id_from_feed, videos_list)."""
        urls_to_try = []
        if channel_id:
            urls_to_try.append(
                f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}")
        # user-based feed (legacy @handles sometimes have a matching username)
        urls_to_try.append(
            f"https://www.youtube.com/feeds/videos.xml?user={handle}")

        for feed_url in urls_to_try:
            try:
                resp = http.get(feed_url, timeout=12)
                if resp.status_code == 429:
                    warnings.append("YouTube RSS feed rate-limited (429)")
                    break
                if resp.status_code != 200 or not resp.text:
                    continue
                return self._parse_rss(resp.text, warnings)
            except Exception as exc:
                warnings.append(f"RSS fetch error: {exc}")

        return None, []

    def _parse_rss(self, xml_text, warnings):
        """Parse YouTube Atom feed. Returns (channel_id, videos_list)."""
        try:
            root = ET.fromstring(xml_text.encode("utf-8"))
        except ET.ParseError as exc:
            warnings.append(f"RSS XML parse error: {exc}")
            return None, []

        ns = {"atom": _ATOM_NS, "yt": _YT_NS, "media": _MEDIA_NS}

        # Channel ID: <yt:channelId>
        cid_el = root.find("yt:channelId", ns)
        channel_id = cid_el.text.strip() if cid_el is not None else None

        videos = []
        for entry in root.findall("atom:entry", ns)[:5]:
            title_el = entry.find("atom:title", ns)
            link_el  = entry.find("atom:link",  ns)
            title = title_el.text.strip() if title_el is not None else ""
            url   = (link_el.get("href") or "").strip() if link_el is not None else ""
            if title or url:
                videos.append({"title": title, "url": url})

        return channel_id, videos

    # ------------------------------------------------------------------ pivots

    def _probe_variation(self, candidate, base_handle, warnings_ref):
        """Probe /@{candidate}. Returns hit dict or None."""
        local_warn = []
        status, html = self._fetch_page(candidate, warnings=local_warn)
        warnings_ref.extend(local_warn)

        if status == 404:
            return None
        if status != 200 or not html:
            return None

        meta = self._parse_meta(html)

        # Accuracy > false positives: require og:title and that it isn't the YouTube
        # homepage (which returns 200 with a generic title for any unknown handle).
        og_title = (meta.get("og_title") or "").strip()
        if not og_title or og_title.lower() in ("youtube", ""):
            return None

        # og:url must contain "@" (channel pages) or "/channel/"
        og_url = meta.get("og_url") or ""
        if not (og_url and ("/@" in og_url or "/channel/" in og_url)):
            return None

        yt_data = self._parse_yt_initial_data(html)
        channel_name = og_title
        channel_id = self._extract_channel_id(html, yt_data, meta)
        sub_count = self._extract_subscriber_count(html, yt_data)
        verified = self._extract_verified(yt_data, html)

        sim = round(SequenceMatcher(
            None, base_handle.lower(), candidate.lower()).ratio(), 3)
        hit = {
            "handle": candidate,
            "url": f"https://www.youtube.com/@{candidate}",
            "channel_name": channel_name,
            "channel_id": channel_id,
            "subscriber_count": sub_count,
            "verified": verified,
            "similarity": sim,
        }
        hit["confidence_tier"] = confidence_tier(sim)
        hit["is_verified_as_target"] = False
        hit["verification_hints"] = _verification_hints_youtube(hit)
        return hit

    def _search_variations(self, handle, max_variations, warnings):
        if not _VARIATIONS_OK:
            return [], []
        raw = generate_variations(handle, max_variations * 2)
        cleaned, seen = [], set()
        for v in raw:
            v = (v or "").strip().lstrip("@")
            if not _YOUTUBE_HANDLE_RE.match(v):
                continue
            key = v.lower()
            if key == handle.lower() or key in seen:
                continue
            seen.add(key)
            cleaned.append(v)
            if len(cleaned) >= max_variations:
                break

        candidates = []
        if not cleaned:
            return cleaned, candidates

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(self._probe_variation, c, handle, warnings): c
                for c in cleaned
            }
            for fut in as_completed(futures):
                hit = fut.result()
                if hit:
                    candidates.append(hit)

        candidates.sort(key=lambda x: x["similarity"], reverse=True)
        return cleaned, candidates

    def _bio_pivots(self, text):
        if not text or not _VARIATIONS_OK:
            return {}
        try:
            return extract_handles_from_bio(text) or {}
        except Exception:
            return {}

    # ------------------------------------------------------------------ run

    def run(self):
        if not self.validate():
            return False

        handle = self._clean(self.get_option("TARGET"))
        if not _YOUTUBE_HANDLE_RE.match(handle or ""):
            print_status(
                f"Invalid YouTube handle '{handle}' "
                "(3-30 chars, alphanumeric/._-). Strip the @ before input or "
                "pass it — the module strips it automatically.",
                "error",
            )
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  YouTube OSINT: @{handle}")
        print(f"{'='*58}{Colors.RESET}\n")

        warnings = []

        # ---------------------------------------------------- 1) main page scrape
        print_status(f"Fetching https://www.youtube.com/@{handle}", "info")
        status, html = self._fetch_page(handle, warnings=warnings)

        channel_name = None
        description = None
        channel_image = None
        channel_url = None
        channel_id = None
        subscriber_count = None
        verified = False
        yt_data = {}
        direct_hit = False

        if status == 0:
            print_status("Network error during page fetch", "error")
        elif status == 404:
            print_status("Channel not found (HTTP 404)", "warning")
        elif status == 200 and html:
            print_status(f"HTTP {status}", "success")
            meta = self._parse_meta(html)
            yt_data = self._parse_yt_initial_data(html)

            og_title = (meta.get("og_title") or "").strip()
            og_url = meta.get("og_url") or ""

            # A real channel page has an og:title different from "YouTube"
            if og_title and og_title.lower() not in ("youtube", ""):
                direct_hit = True
                channel_name = og_title
                description = meta.get("og_description") or None
                channel_image = meta.get("og_image") or None
                channel_url = og_url or f"https://www.youtube.com/@{handle}"
                channel_id = self._extract_channel_id(html, yt_data, meta)
                subscriber_count = self._extract_subscriber_count(html, yt_data)
                verified = self._extract_verified(yt_data, html)

                print_status(f"Channel name: {channel_name}", "success")
                if description:
                    print_status(f"Description: {description[:120]}", "info")
                if subscriber_count:
                    print_status(f"Subscribers: {subscriber_count}", "success")
                if channel_id:
                    print_status(f"Channel ID: {channel_id}", "success")
                if verified:
                    print_status("Verified badge: yes", "success")
            else:
                print_status(
                    "Page returned but no channel-specific og:title — "
                    "handle likely does not exist or was redirected",
                    "warning",
                )
        else:
            print_status(f"Unexpected HTTP {status}", "warning")

        # ---------------------------------------------------- 2) /about tab
        if direct_hit and not description:
            print_status("Fetching /about tab for extended description...", "info")
            about_status, about_html = self._fetch_page(
                handle, "/about", warnings)
            if about_status == 200 and about_html:
                about_meta = self._parse_meta(about_html)
                if about_meta.get("og_description"):
                    description = about_meta["og_description"]
                    print_status(f"Description (from /about): {description[:120]}", "info")

        # ---------------------------------------------------- 3) RSS feed
        latest_videos = []
        rss_channel_id = None
        print_status("Fetching RSS/Atom feed...", "info")
        rss_channel_id, latest_videos = self._fetch_rss(
            handle, channel_id, warnings)
        # If the RSS gave us a channel ID and we didn't have one, use it
        if not channel_id and rss_channel_id:
            channel_id = rss_channel_id
            print_status(f"Channel ID (from RSS): {channel_id}", "success")
        if latest_videos:
            print_status(
                f"Latest videos via RSS: {len(latest_videos)} found", "success")
            for v in latest_videos[:3]:
                print_status(f"  {v.get('title', '(no title)')[:80]}", "info")
        else:
            print_status("RSS feed: no entries (channel may be @handle-only)", "info")

        # ---------------------------------------------------- 4) bio pivot
        bio_handles = self._bio_pivots(description or "")
        if bio_handles:
            parts = [f"{k}:{len(v)}" for k, v in bio_handles.items() if v]
            if parts:
                print_status(f"Bio pivots - {', '.join(parts)}", "success")

        # ---------------------------------------------------- 5) variations
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(
                f"Probing up to {max_variations} handle variations...", "info")
            variations_tried, candidates = self._search_variations(
                handle, max_variations, warnings)
            print_status(
                f"Tried {len(variations_tried)} variations, "
                f"{len(candidates)} candidate(s)",
                "success" if candidates else "info",
            )
            for c in candidates[:10]:
                tier = c.get("confidence_tier", "unknown")
                severity = (
                    "warning"
                    if tier in ("medium", "low", "very-low")
                    else "success"
                )
                note = ""
                if tier == "exact-match":
                    note = (
                        " (spelling-identical — YouTube @handles can be changed; "
                        "use channel_id to pin identity)"
                    )
                print_status(
                    f"[CANDIDATE/{tier}]  -> @{c['handle']} "
                    f"(sim={c['similarity']}) "
                    f"{(c.get('channel_name') or '')[:50]}"
                    f"{note}  — NOT CONFIRMED",
                    severity,
                )
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping pivot",
                "warning",
            )

        # ------------------------------------------------------------- results
        self.results = {
            "handle": handle,
            "channel_url": channel_url or f"https://www.youtube.com/@{handle}",
            "channel_name": channel_name,
            "description": description,
            "subscriber_count": subscriber_count,
            "channel_id": channel_id,
            "profile_image": channel_image,
            "verified": verified,
            "latest_videos": latest_videos,
            "bio_handles": bio_handles,
            "candidates": candidates,
            "variations_tried": variations_tried,
            "warnings": warnings,
            "direct_hit": direct_hit,
            "source": "youtube.com + RSS",
        }
        self.results["disclaimer"] = build_disclaimer("YouTube", len(candidates))

        # status 0 (network error) / 429 / any non-200 that is not a 404 means
        # the channel page fetch FAILED - distinguishable from a clean 404 or a
        # 200 that simply carried no channel-specific og:title.
        direct_fetch_failed = (not direct_hit) and (
            status == 0 or status == 429 or (status >= 400 and status != 404))
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status("Direct lookup INCONCLUSIVE - YouTube blocked/unreachable; "
                         "this is NOT evidence the channel is absent", "warning")

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: @{handle}")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  Link:         https://www.youtube.com/@{handle}")
        print(f"  Direct hit:   {'yes' if direct_hit else 'no'}")
        if channel_name:
            print(f"  Channel:      {channel_name}")
        if channel_id:
            print(f"  Channel ID:   {channel_id}")
        if subscriber_count:
            print(f"  Subscribers:  {subscriber_count}")
        if verified:
            print(f"  Verified:     yes")
        if channel_image:
            print(f"  Avatar:       {channel_image}")
        if latest_videos:
            print(f"  Videos (RSS): {len(latest_videos)}")
        if bio_handles:
            parts = [f"{k}:{len(v)}" for k, v in bio_handles.items() if v]
            if parts:
                print(f"  Bio pivots:   {', '.join(parts)}")
        print(f"  Candidates:   {len(candidates)} "
              f"(from {len(variations_tried)} tried)")
        if warnings:
            print(f"  Warnings:     {len(warnings)}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        if candidates:
            print_uncertainty_box("YouTube", _verification_hints_youtube({}))

        return True
