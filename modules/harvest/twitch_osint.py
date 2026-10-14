"""Twitch OSINT - public profile scrape + undocumented GQL API + username variations.

Zero-auth: uses Twitch's public web client ID (embedded in their frontend) to query
the public GQL endpoint. Falls back gracefully to og: meta tags if GQL fails.
"""
import re
import json
import datetime
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

# Soft import so the base scrape keeps working even if the helper is missing.
try:
    from modules.harvest.username_variations import (
        generate_variations,
        platform_filter,
        extract_handles_from_bio,
    )
    _VARIATIONS_OK = True
except Exception:
    _VARIATIONS_OK = False

    def generate_variations(_u, _n=20):
        return []

    def platform_filter(items, _platform):
        return items

    def extract_handles_from_bio(_text):
        return {}


_TWITCH_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{4,25}$")
_TWITCH_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
# Twitch's public web client ID — embedded in their frontend JavaScript bundle.
_TWITCH_CLIENT_ID = "kimne78kx3ncx6brgo4mv6wki5h1ko"
_GQL_URL = "https://gql.twitch.tv/gql"

# og: meta tag extraction
_OG_TITLE_RE = re.compile(
    r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']*)["\']', re.I
)
_OG_TITLE_RE2 = re.compile(
    r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+property=["\']og:title["\']', re.I
)
_OG_DESC_RE = re.compile(
    r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']*)["\']', re.I
)
_OG_DESC_RE2 = re.compile(
    r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+property=["\']og:description["\']', re.I
)
_OG_IMAGE_RE = re.compile(
    r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']*)["\']', re.I
)
_OG_IMAGE_RE2 = re.compile(
    r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+property=["\']og:image["\']', re.I
)

# Live-stream signal detection in JSON-LD / structured data
_LIVE_BROADCAST_RE = re.compile(r'"isLiveBroadcast"\s*:\s*true', re.I)
_BROADCAST_SETTINGS_RE = re.compile(r'"broadcastSettings"\s*:', re.I)


# ------------------------------------------------------------------ hints


def _verification_hints_twitch(candidate):
    hints = [
        "Twitch account creation date correlates with gaming history — "
        "check against target's known online presence",
        "Stream content category (games played) is a strong interest fingerprint",
        "Channel bio often contains links to other social media",
        "Subscriber count and view count history indicate the target's "
        "prominence in gaming communities",
        "Twitch usernames are case-insensitive but unique — even old/inactive "
        "accounts block the name",
    ]
    if candidate.get("is_live"):
        hints.insert(
            0,
            "Account is currently LIVE — stream details may include "
            "location/language hints",
        )
    return hints


# ------------------------------------------------------------------ module


class TwitchOsint(BaseModule):
    name = "harvest/twitch_osint"
    description = "Twitch public profile OSINT via page scrape + undocumented API"
    category = "harvest"
    target_type = "username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Twitch username")
        self.add_option("VARIATIONS", "true", False, "Pivot via username variations")
        self.add_option("MAX_VARIATIONS", "15", False, "Max variations to probe")

    # ------------------------------------------------------------------ helpers

    def _clean(self, username):
        username = (username or "").strip().lstrip("@")
        username = re.sub(r"https?://(?:www\.)?twitch\.tv/", "", username, flags=re.I)
        return username.strip("/").split("?")[0].split("/")[0].strip()

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

    def _meta_tag(self, html, *patterns):
        """Try multiple regex patterns for the same og: tag; return first match."""
        for pat in patterns:
            m = pat.search(html or "")
            if m:
                return m.group(1).strip()
        return None

    # ------------------------------------------------------------------ page scrape

    def _scrape_profile_page(self, username):
        """Scrape twitch.tv/{username} for og: tags and live-stream signals."""
        result = {
            "display_name": None,
            "bio": None,
            "avatar": None,
            "is_live": False,
            "page_found": False,
        }
        try:
            resp = http.get(
                f"https://www.twitch.tv/{username}",
                headers={"User-Agent": _TWITCH_UA},
                timeout=15,
                allow_redirects=True,
            )
        except Exception as exc:
            self._warn.append(f"profile page fetch error: {exc}")
            self._page_blocked = True
            return result

        if resp.status_code != 200:
            # 404 is a clean "no such channel"; 403/429/5xx is a failed fetch.
            if resp.status_code != 404:
                self._page_blocked = True
            return result

        html = resp.text or ""
        result["page_found"] = True

        # og:title → "{DisplayName} - Twitch"
        raw_title = self._meta_tag(html, _OG_TITLE_RE, _OG_TITLE_RE2)
        if raw_title:
            result["display_name"] = re.sub(
                r"\s*-\s*Twitch\s*$", "", raw_title
            ).strip() or raw_title

        result["bio"] = self._meta_tag(html, _OG_DESC_RE, _OG_DESC_RE2)
        result["avatar"] = self._meta_tag(html, _OG_IMAGE_RE, _OG_IMAGE_RE2)

        # Live-stream detection via JSON-LD / structured data markers
        if _LIVE_BROADCAST_RE.search(html) or _BROADCAST_SETTINGS_RE.search(html):
            result["is_live"] = True

        return result

    # ------------------------------------------------------------------ GQL

    def _gql_post(self, payload, op_name):
        """Send a GQL payload and return parsed JSON, or {} on any failure."""
        try:
            resp = http.post(
                _GQL_URL,
                json=payload,
                headers={
                    "Client-ID": _TWITCH_CLIENT_ID,
                    "Content-Type": "application/json",
                },
                timeout=12,
            )
        except Exception as exc:
            self._warn.append(f"GQL {op_name} request error: {exc}")
            self._gql_blocked = True
            return {}

        if resp.status_code != 200:
            self._warn.append(f"GQL {op_name} returned HTTP {resp.status_code}")
            self._gql_blocked = True
            return {}

        try:
            return resp.json()
        except Exception:
            self._warn.append(f"GQL {op_name}: invalid JSON response")
            return {}

    def _gql_user_info(self, username):
        """Query Twitch GQL for UserPage_UserInfo. Returns raw user dict or {}."""
        payload = [
            {
                "operationName": "UserPage_UserInfo",
                "variables": {"login": username},
                "extensions": {
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": (
                            "8f3628981255345ca5e5453dfd84eec3f722f58d9399ee9acf1b6d52fb57d7fe"
                        ),
                    }
                },
            }
        ]
        data = self._gql_post(payload, "UserPage_UserInfo")
        try:
            if isinstance(data, list) and data:
                return (data[0].get("data") or {}).get("user") or {}
            if isinstance(data, dict):
                return (data.get("data") or {}).get("user") or {}
        except Exception:
            pass
        return {}

    def _gql_follower_count(self, username):
        """Query Twitch GQL for FollowerCount. Returns int or None."""
        payload = [
            {
                "operationName": "FollowerCount",
                "variables": {"login": username},
                "extensions": {
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": (
                            "46d9d6c43b5e8ef9f04bef84d53fddd7de4b33ffcae8e77acd1efcb31afc96a8"
                        ),
                    }
                },
            }
        ]
        data = self._gql_post(payload, "FollowerCount")
        try:
            if isinstance(data, list) and data:
                user = (data[0].get("data") or {}).get("user") or {}
            elif isinstance(data, dict):
                user = (data.get("data") or {}).get("user") or {}
            else:
                return None
            count = (user.get("followers") or {}).get("totalCount")
            if count is not None:
                return int(count)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ normalize GQL

    def _normalize_gql(self, user_data):
        """Flatten the GQL user object into a simple dict."""
        if not user_data or not isinstance(user_data, dict):
            return {}
        broadcast = user_data.get("broadcastSettings") or {}
        stream = user_data.get("stream") or {}

        result = {
            "login": user_data.get("login"),
            "display_name": user_data.get("displayName"),
            "bio": user_data.get("description"),
            "created_at": user_data.get("createdAt"),
            "stream_title": broadcast.get("title"),
            "stream_game": (broadcast.get("game") or {}).get("name"),
            "is_live": bool(stream and isinstance(stream, dict)),
            "stream_viewers": None,
            "stream_started_at": None,
        }
        if stream and isinstance(stream, dict):
            result["stream_viewers"] = stream.get("viewersCount")
            result["stream_started_at"] = stream.get("createdAt")
        return result

    # ------------------------------------------------------------------ variations

    def _probe_variation(self, candidate, base):
        """Probe twitch.tv/{candidate}. Return hit dict if a real profile responds."""
        try:
            resp = http.get(
                f"https://www.twitch.tv/{candidate}",
                headers={"User-Agent": _TWITCH_UA},
                timeout=10,
                allow_redirects=True,
            )
        except Exception:
            return None

        if resp.status_code != 200:
            return None

        html = resp.text or ""
        raw_title = self._meta_tag(html, _OG_TITLE_RE, _OG_TITLE_RE2)
        # Real Twitch profile pages carry "- Twitch" in the og:title
        if not raw_title or "- Twitch" not in raw_title:
            return None

        display_name = re.sub(r"\s*-\s*Twitch\s*$", "", raw_title).strip()
        sim = round(
            SequenceMatcher(None, base.lower(), candidate.lower()).ratio(), 3
        )
        hit = {
            "username": candidate,
            "display_name": display_name or candidate,
            "profile_url": f"https://www.twitch.tv/{candidate}",
            "similarity": sim,
            "exists": True,
            "is_live": bool(
                _LIVE_BROADCAST_RE.search(html) or _BROADCAST_SETTINGS_RE.search(html)
            ),
        }
        hit["confidence_tier"] = confidence_tier(sim)
        hit["is_verified_as_target"] = False
        hit["verification_hints"] = _verification_hints_twitch(hit)
        return hit

    def _search_variations(self, username, max_variations):
        raw = generate_variations(username, max_variations * 3)
        variations = platform_filter(raw, "twitch")
        cleaned, seen = [], set()
        for v in variations:
            if not _TWITCH_USERNAME_RE.match(v or ""):
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

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(self._probe_variation, c, username): c for c in cleaned
            }
            for fut in as_completed(futures):
                hit = fut.result()
                if hit:
                    candidates.append(hit)

        candidates.sort(key=lambda x: x.get("similarity", 0), reverse=True)
        return cleaned, candidates

    # ------------------------------------------------------------------ run

    def run(self):
        if not self.validate():
            return False

        username = self._clean(self.get_option("TARGET"))
        if not username:
            print_status("Empty TARGET after cleanup", "error")
            return False

        if not _TWITCH_USERNAME_RE.match(username):
            print_status(
                f"Username '{username}' doesn't match Twitch rules "
                "(4-25 chars, alphanumeric + underscore)",
                "error",
            )
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))
        self._warn = []
        self._page_blocked = False
        self._gql_blocked = False

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 58}")
        print(f"  Twitch OSINT: {username}")
        print(f"{'=' * 58}{Colors.RESET}\n")

        # Step 1 — og: meta scrape
        print_status("Scraping Twitch profile page...", "info")
        page_data = self._scrape_profile_page(username)

        if not page_data["page_found"]:
            print_status(
                "Profile page not accessible (404, blocked, or user doesn't exist)",
                "warning",
            )
        else:
            print_status(
                f"Page found: display_name={page_data.get('display_name')!r}  "
                f"live={page_data.get('is_live')}",
                "success",
            )

        # Step 2 — GQL user info
        print_status("Querying Twitch GQL endpoint...", "info")
        raw_gql = self._gql_user_info(username)
        gql_data = {}
        if raw_gql:
            gql_data = self._normalize_gql(raw_gql)
            print_status(
                f"GQL hit: login={gql_data.get('login')!r}  "
                f"created={gql_data.get('created_at')}  "
                f"live={gql_data.get('is_live')}",
                "success",
            )
            if gql_data.get("stream_title"):
                print_status(
                    f"Stream: {gql_data['stream_title']!r}  "
                    f"({gql_data.get('stream_game') or 'unknown game'})",
                    "info",
                )
            if gql_data.get("stream_viewers") is not None:
                print_status(f"Viewers: {gql_data['stream_viewers']:,}", "info")
        else:
            print_status(
                "GQL returned no user data (account may not exist or GQL changed)",
                "warning",
            )

        # Step 3 — Follower count (separate GQL query)
        followers = None
        if raw_gql:
            print_status("Fetching follower count via GQL...", "info")
            followers = self._gql_follower_count(username)
            if followers is not None:
                print_status(f"Followers: {followers:,}", "success")
            else:
                print_status("Follower count unavailable from GQL", "warning")

        # Merge: GQL is authoritative; page data fills any gaps
        display_name = gql_data.get("display_name") or page_data.get("display_name")
        bio = gql_data.get("bio") or page_data.get("bio") or ""
        avatar = page_data.get("avatar")
        is_live = bool(
            gql_data.get("is_live") or page_data.get("is_live")
        )
        created_at = gql_data.get("created_at")

        # Step 4 — Bio handle pivot
        bio_handles = {}
        if _VARIATIONS_OK and bio:
            try:
                bio_handles = extract_handles_from_bio(bio) or {}
            except Exception:
                bio_handles = {}
            bio_handles = {k: v for k, v in bio_handles.items() if v}
            if bio_handles:
                counts = ", ".join(
                    f"{k}:{len(v)}" for k, v in bio_handles.items()
                )
                print_status(f"Bio pivots found - {counts}", "success")

        # Step 5 — Variation probe
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(
                f"Probing up to {max_variations} username variations...", "info"
            )
            variations_tried, candidates = self._search_variations(
                username, max_variations
            )
            print_status(
                f"Tried {len(variations_tried)} variations, "
                f"{len(candidates)} candidate(s)",
                "success" if candidates else "info",
            )
            for c in candidates[:10]:
                tier = c.get("confidence_tier") or confidence_tier(
                    c.get("similarity") or 0
                )
                sev = (
                    "warning"
                    if tier in ("medium", "low", "very-low")
                    else "success"
                )
                print_status(
                    f"  [CANDIDATE/{tier}] -> {c['username']} "
                    f"(sim={c.get('similarity')}) — NOT CONFIRMED",
                    sev,
                )
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping pivot", "warning"
            )

        # ------------------------------------------------------------- results
        account_found = bool(page_data["page_found"] or raw_gql)
        self.results = {
            "username": username,
            "profile_url": f"https://www.twitch.tv/{username}",
            "display_name": display_name,
            "bio": bio,
            "avatar": avatar,
            "followers": followers,
            "created_at": created_at,
            "is_live": is_live,
            "stream_title": gql_data.get("stream_title"),
            "stream_game": gql_data.get("stream_game"),
            "stream_viewers": gql_data.get("stream_viewers"),
            "stream_started_at": gql_data.get("stream_started_at"),
            "bio_handles": bio_handles,
            "candidates": candidates,
            "warnings": self._warn,
            "source": "twitch.tv page scrape + GQL (public client ID, no auth)",
            "disclaimer": build_disclaimer("Twitch", len(candidates)),
        }

        # Both the page scrape AND GQL had to be blocked (429/403/5xx/network)
        # with no account resolved for this to be a FETCH FAILURE. A nonexistent
        # user returns a clean 404/empty GQL, which stays a genuine negative.
        direct_fetch_failed = (
            not account_found and self._page_blocked and self._gql_blocked)
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status("Direct lookup INCONCLUSIVE - Twitch page and GQL both "
                         "blocked/unreachable; this is NOT evidence the account is "
                         "absent", "warning")

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'=' * 58}")
        print(f"  Summary: {username}")
        print(f"{'-' * 58}{Colors.RESET}")
        print(f"  Profile URL:  https://www.twitch.tv/{username}")
        if account_found:
            print(f"  Account:      found")
            if display_name:
                print(f"  Display Name: {display_name}")
            if created_at:
                print(f"  Created:      {created_at}")
            if followers is not None:
                print(f"  Followers:    {followers:,}")
            if bio:
                print(f"  Bio:          {bio[:120]}")
            if is_live:
                print(f"  LIVE NOW:     yes")
                if gql_data.get("stream_title"):
                    print(
                        f"  Stream:       {gql_data['stream_title']!r}  "
                        f"({gql_data.get('stream_game') or 'unknown game'})"
                    )
                if gql_data.get("stream_viewers") is not None:
                    print(f"  Viewers:      {gql_data['stream_viewers']:,}")
            if avatar:
                print(f"  Avatar:       {avatar[:70]}")
        else:
            print(
                f"  Account:      {Colors.YELLOW}not found or inaccessible{Colors.RESET}"
            )
        if bio_handles:
            parts = [f"{k}:{len(v)}" for k, v in bio_handles.items()]
            print(f"  Bio pivots:   {', '.join(parts)}")
        print(f"  Candidates:   {len(candidates)} (from {len(variations_tried)} tried)")
        if self._warn:
            print(
                f"  {Colors.DIM}{len(self._warn)} warning(s): "
                f"{'; '.join(self._warn[:3])}{Colors.RESET}"
            )
        print(f"{Colors.GREEN}{'=' * 58}{Colors.RESET}\n")

        if candidates:
            print_uncertainty_box("Twitch", _verification_hints_twitch({}))

        return True
