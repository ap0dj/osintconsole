"""Snapchat OSINT - public-profile scrape for a Snapchat username.

Given a Snapchat username, hits the public /add/{username} page (no cookies,
no login) and extracts everything available:

- og:* meta tags (display name, bio snippet, bitmoji/avatar)
- Deep-link confirmation via ``twitter:app:url:iphone``
- The embedded ``__NEXT_DATA__`` JSON blob which carries the real profile
  object: ``userId``, ``displayName``, ``snapcode``, subscriber count,
  Snap Minis (cognac), verified badge, recent public stories/spotlights.

Pivots: bio handle extractor + opt-in username-variation probe.
"""

import re
import json
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest._social_base import (
    confidence_tier,
    print_uncertainty_box,
    build_disclaimer,
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


# Snapchat username constraints: 3-15 chars, letters/digits/_ - . - no
# leading dash or period.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{2,14}$")
_NEXT_DATA_RE = re.compile(
    r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.DOTALL)


def _verification_hints_snapchat(candidate):
    hints = [
        "Compare the display name against target's known handles elsewhere",
        "Check the bitmoji avatar — distinctive bitmojis are a strong per-person indicator",
        "Scan the snapcode to verify the direct account URL matches",
        "If the account has a public profile, review subscriber count and story content",
        "Snap Minis (installed apps) can leak interests — compare to target's known hobbies",
        "Snapchat usernames are OFTEN reused from Instagram/TikTok — cross-check patterns",
    ]
    if candidate.get("has_public_profile") is False:
        hints.insert(0, "This account has NO public profile — only display name is visible. Minimal data for verification.")
    if candidate.get("verified_badge"):
        hints.insert(0, "This account has a verified badge — only publicly notable creators get this.")
    return hints


class SnapchatOsint(BaseModule):
    name = "harvest/snapchat_osint"
    description = "Snapchat public-profile OSINT - /add/ scrape + __NEXT_DATA__ + pivots"
    category = "harvest"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Snapchat username (without @)")
        self.add_option("VARIATIONS", "true", False, "Pivot via username variations")
        self.add_option("MAX_VARIATIONS", "15", False, "Max variations to probe")

    # ------------------------------------------------------------------ helpers

    def _clean(self, username):
        username = (username or "").strip().lstrip("@")
        username = re.sub(r"https?://(?:www\.)?snapchat\.com/add/", "", username)
        username = re.sub(r"snapchat://add/", "", username)
        return username.strip("/")

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

    def _fetch(self, username, warnings):
        """GET /add/{username}. Returns (status, html) or (status, '')."""
        try:
            resp = http.get(f"https://www.snapchat.com/add/{username}", timeout=12)
            if resp.status_code == 429:
                warnings.append(f"HTTP 429 (rate-limited) for @{username}")
                return 429, ""
            return resp.status_code, resp.text or ""
        except Exception as e:
            warnings.append(f"Fetch error for @{username}: {e}")
            return 0, ""

    def _parse_meta(self, html):
        out = {}
        m = re.search(r'<meta property="og:title" content="([^"]*)"', html)
        if m:
            out["og_title"] = m.group(1).strip()
        m = re.search(r'<meta property="og:description" content="([^"]*)"', html)
        if m:
            out["og_description"] = m.group(1).strip()
        m = re.search(r'<meta property="og:image" content="([^"]*)"', html)
        if m:
            out["og_image"] = m.group(1).strip()
        m = re.search(
            r'<meta name="twitter:app:url:iphone" content="([^"]*)"', html)
        if m:
            out["deeplink"] = m.group(1).strip()
        return out

    def _parse_next_data(self, html):
        """Pull the embedded Next.js JSON blob. Returns dict or {}."""
        m = _NEXT_DATA_RE.search(html)
        if not m:
            return {}
        try:
            return json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            return {}

    def _extract_profile(self, meta, nxt, username):
        """Normalise the mixed meta + __NEXT_DATA__ into a flat profile dict."""
        prof = {
            "username": username,
            "display_name": None,
            "bio": None,
            "user_id": None,
            "subscriber_count": None,
            "snapcode_url": None,
            "bitmoji_avatar_url": None,
            "verified_badge": False,
            "snap_mini": [],
            "stories": [],
            "spotlight": [],
            "has_public_profile": False,
        }

        # Meta fallbacks are always present when the page renders.
        og_title = meta.get("og_title") or ""
        # Snapchat sets a generic og:title "Snapchat" on 404-style pages.
        if og_title and og_title.strip().lower() != "snapchat":
            prof["display_name"] = og_title
        if meta.get("og_description"):
            prof["bio"] = meta["og_description"]
        if meta.get("og_image"):
            prof["bitmoji_avatar_url"] = meta["og_image"]

        user_profile = (
            ((nxt.get("props") or {}).get("pageProps") or {}).get("userProfile")
            or {}
        )
        if not user_profile:
            return prof

        user_info = user_profile.get("userInfo") or {}
        if user_info:
            prof["display_name"] = user_info.get("displayName") or prof["display_name"]
            prof["user_id"] = user_info.get("userId") or user_info.get("snapId")
            prof["snapcode_url"] = (
                user_info.get("snapcodeImageUrl") or user_info.get("snapcode"))
            prof["bitmoji_avatar_url"] = (
                user_info.get("bitmojiAvatarId")
                or user_info.get("bitmoji3D", {}).get("avatarImage", {}).get("url")
                or prof["bitmoji_avatar_url"]
            )

        pub = user_profile.get("publicProfileInfo") or {}
        if pub:
            prof["has_public_profile"] = True
            prof["display_name"] = pub.get("title") or prof["display_name"]
            prof["bio"] = pub.get("subtitle") or pub.get("bio") or prof["bio"]
            prof["subscriber_count"] = (
                pub.get("subscriberCount") or pub.get("subscriberCountRounded"))
            badge = pub.get("badge")
            prof["verified_badge"] = bool(badge) and badge not in (0, "0", "NONE")

            for mini in (pub.get("cognac") or []) + (pub.get("snapMinis") or []):
                prof["snap_mini"].append({
                    "name": mini.get("name") or mini.get("title"),
                    "id": mini.get("id") or mini.get("appId"),
                    "icon": mini.get("iconUrl") or mini.get("icon"),
                })

            content = pub.get("contentArea") or {}
            for s in (content.get("stories") or [])[:10]:
                prof["stories"].append({
                    "id": s.get("id") or s.get("storyId"),
                    "title": s.get("title") or s.get("snapTitle"),
                    "timestamp": s.get("timestampMs") or s.get("timestamp"),
                })
            for s in (content.get("savedStoryTiles") or [])[:10]:
                prof["stories"].append({
                    "id": s.get("storyId"),
                    "title": s.get("title"),
                    "timestamp": s.get("timestampMs"),
                })
            for s in (content.get("spotlightHighlights") or [])[:10]:
                prof["spotlight"].append({
                    "id": s.get("spotlightStoryId") or s.get("id"),
                    "title": s.get("title"),
                })

        return prof

    def _is_real_hit(self, meta, nxt):
        """Accuracy > false positives: hit requires NEXT_DATA + userProfile key."""
        og = (meta.get("og_title") or "").strip()
        if not og or og.lower() == "snapchat":
            return False
        user_profile = (
            ((nxt.get("props") or {}).get("pageProps") or {}).get("userProfile"))
        return user_profile is not None

    # ------------------------------------------------------------------ pivots

    def _probe_variation(self, candidate, base, warnings):
        status, html = self._fetch(candidate, warnings)
        if status != 200 or not html:
            return None
        meta = self._parse_meta(html)
        nxt = self._parse_next_data(html)
        if not self._is_real_hit(meta, nxt):
            return None
        prof = self._extract_profile(meta, nxt, candidate)
        sim = round(SequenceMatcher(
            None, base.lower(), candidate.lower()).ratio(), 3)
        hit = {
            "username": candidate,
            "url": f"https://www.snapchat.com/add/{candidate}",
            "display_name": prof.get("display_name"),
            "subscriber_count": prof.get("subscriber_count"),
            "has_public_profile": prof.get("has_public_profile"),
            "verified_badge": prof.get("verified_badge"),
            "similarity": sim,
        }
        hit["confidence_tier"] = confidence_tier(sim)
        hit["is_verified_as_target"] = False
        hit["verification_hints"] = _verification_hints_snapchat(hit)
        return hit

    def _search_variations(self, username, max_variations, warnings):
        if not _VARIATIONS_OK:
            return [], []
        raw = generate_variations(username, max_variations * 2)
        cleaned, seen = [], set()
        for v in raw:
            v = (v or "").strip()
            if not _USERNAME_RE.match(v) or v.startswith(("-", ".")):
                continue
            key = v.lower()
            if key == username.lower() or key in seen:
                continue
            seen.add(key)
            cleaned.append(v)
            if len(cleaned) >= max_variations:
                break

        candidates = []
        if not cleaned:
            return cleaned, candidates

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {
                pool.submit(self._probe_variation, c, username, warnings): c
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

        username = self._clean(self.get_option("TARGET"))
        if not _USERNAME_RE.match(username) or username.startswith(("-", ".")):
            print_status(
                f"Invalid Snapchat username '{username}' "
                f"(3-15 chars, alnum/_/-/., no leading - or .)",
                "error")
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Snapchat OSINT: @{username}")
        print(f"{'='*58}{Colors.RESET}\n")

        warnings = []

        # 1) Direct profile scrape
        print_status(f"Fetching https://www.snapchat.com/add/{username}", "info")
        status, html = self._fetch(username, warnings)
        if status == 0:
            print_status("Network error - aborting direct scrape", "error")
            meta, nxt, profile = {}, {}, {}
            direct_hit = False
        else:
            print_status(f"HTTP {status}", "success" if status == 200 else "warning")
            meta = self._parse_meta(html) if html else {}
            nxt = self._parse_next_data(html) if html else {}
            direct_hit = self._is_real_hit(meta, nxt)
            profile = self._extract_profile(meta, nxt, username) if html else {}

            if meta.get("deeplink"):
                print_status(f"Deep-link: {meta['deeplink']}", "info")
            if profile.get("display_name"):
                print_status(f"Display name: {profile['display_name']}", "success")
            if profile.get("bio"):
                print_status(f"Bio: {profile['bio'][:120]}", "info")
            if profile.get("has_public_profile"):
                print_status("Public profile: yes", "success")
                if profile.get("subscriber_count"):
                    print_status(
                        f"Subscribers: {profile['subscriber_count']}", "success")
                if profile.get("verified_badge"):
                    print_status("Verified badge: yes", "success")
                if profile.get("snap_mini"):
                    print_status(
                        f"Snap Minis: {len(profile['snap_mini'])}", "success")
                if profile.get("stories"):
                    print_status(
                        f"Public stories: {len(profile['stories'])}", "success")
                if profile.get("spotlight"):
                    print_status(
                        f"Spotlight: {len(profile['spotlight'])}", "success")
            elif direct_hit:
                print_status(
                    "Account exists but no public profile (creator opt-in needed)",
                    "warning")
            else:
                print_status(
                    "No valid __NEXT_DATA__ userProfile - username likely nonexistent",
                    "warning")

        # 2) Bio pivot
        bio_blob = " ".join(filter(None, [
            profile.get("bio") or "",
            profile.get("display_name") or "",
        ]))
        bio_pivots = self._bio_pivots(bio_blob)
        if bio_pivots:
            parts = [f"{k}:{len(v)}" for k, v in bio_pivots.items() if v]
            if parts:
                print_status(f"Bio pivots - {', '.join(parts)}", "success")

        # 3) Variation pivot
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(
                f"Probing up to {max_variations} username variations...", "info")
            variations_tried, candidates = self._search_variations(
                username, max_variations, warnings)
            print_status(
                f"Tried {len(variations_tried)} variations, "
                f"{len(candidates)} candidate(s)",
                "success" if candidates else "info")
            for c in candidates[:10]:
                tag = "public" if c.get("has_public_profile") else "basic"
                tier = c.get("confidence_tier", "unknown")
                severity = (
                    "warning"
                    if tier in ("medium", "low", "very-low")
                    else "success"
                )
                note = ""
                if tier == "exact-match":
                    note = (
                        " (spelling-identical to target — but Snapchat handles "
                        "are often reused across platforms by DIFFERENT people)"
                    )
                print_status(
                    f"[CANDIDATE/{tier}]  -> @{c['username']} "
                    f"(sim={c['similarity']}, {tag}) "
                    f"{(c.get('display_name') or '')[:50]}{note} "
                    f"— NOT CONFIRMED",
                    severity)
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping pivot",
                "warning")

        # ------------------------------------------------------------- results
        self.results = {
            "username": username,
            "url": f"https://www.snapchat.com/add/{username}",
            "direct_hit": direct_hit,
            "profile": profile,
            "bio_pivots": bio_pivots,
            "variations_tried": variations_tried,
            "candidates": candidates,
            "warnings": warnings,
        }
        self.results["disclaimer"] = build_disclaimer("Snapchat", len(candidates))

        # status 0 (network error) / 429 / any non-200 that is not a 404 means
        # the direct fetch FAILED - distinguishable from a clean "no such user"
        # (a 200 whose page carries no __NEXT_DATA__ userProfile, or a 404).
        direct_fetch_failed = (not direct_hit) and (
            status == 0 or status == 429 or (status >= 400 and status != 404))
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status("Direct lookup INCONCLUSIVE - Snapchat blocked/unreachable; "
                         "this is NOT evidence the account is absent", "warning")

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: @{username}")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  Link:         https://www.snapchat.com/add/{username}")
        print(f"  Direct hit:   {'yes' if direct_hit else 'no'}")
        if profile.get("display_name"):
            print(f"  Display name: {profile['display_name']}")
        if profile.get("user_id"):
            print(f"  User ID:      {profile['user_id']}")
        print(f"  Public prof:  {'yes' if profile.get('has_public_profile') else 'no'}")
        if profile.get("subscriber_count"):
            print(f"  Subscribers:  {profile['subscriber_count']}")
        if profile.get("verified_badge"):
            print(f"  Verified:     yes")
        if profile.get("snap_mini"):
            print(f"  Snap Minis:   {len(profile['snap_mini'])}")
        if profile.get("stories") or profile.get("spotlight"):
            print(f"  Content:      "
                  f"stories={len(profile.get('stories') or [])} "
                  f"spotlight={len(profile.get('spotlight') or [])}")
        if bio_pivots:
            parts = [f"{k}:{len(v)}" for k, v in bio_pivots.items() if v]
            if parts:
                print(f"  Bio pivots:   {', '.join(parts)}")
        print(f"  Candidates:   {len(candidates)} (from {len(variations_tried)} tried)")
        if warnings:
            print(f"  Warnings:     {len(warnings)}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        if candidates:
            print_uncertainty_box("Snapchat")

        return True
