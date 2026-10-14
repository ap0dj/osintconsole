"""Steam OSINT - public profile scrape (no API key required).

Steam community profiles are public by default. Accepts two target formats:
  - Vanity URL:  "gaben"  or  "https://steamcommunity.com/id/gaben"
  - SteamID64:  "76561197960287930"  or  "https://steamcommunity.com/profiles/..."
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


_STEAM_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_STEAMID64_RE = re.compile(r"^\d{17}$")
# Steam vanity names: 2-32 alphanumeric + underscore + hyphen
_VANITY_RE = re.compile(r"^[A-Za-z0-9_\-]{2,32}$")

# --- og: meta tag extraction (both attribute-order variants) ---
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

# --- profile data patterns ---
_DATA_STEAMID_RE = re.compile(r'data-steamid=["\'](\d{17})["\']')
_DATA_MINIPROFILE_RE = re.compile(r'data-miniprofile=["\'](\d+)["\']')
# VAC ban indicators
_VAC_RE = re.compile(r"(vac_banned|VAC Ban|ban notice)", re.I)
# Real name inside persona block
_ACTUAL_NAME_RE = re.compile(
    r'class="actual_persona_name"[^>]*>\s*([^<]+?)\s*<', re.I
)
# Steam level
_LEVEL_RE = re.compile(
    r'class="friendPlayerLevelNum"[^>]*>\s*(\d+)\s*<', re.I
)
# Member since date
_MEMBER_SINCE_RE = re.compile(r"Member since\s+([A-Za-z]+ \d{1,2},? \d{4})", re.I)
# Location (inside header_real_name block)
_LOCATION_RE = re.compile(
    r'class="header_real_name"[^>]*>.*?<bdi>([^<]+)</bdi>', re.I | re.DOTALL
)
# Privacy signals
_PRIVATE_PROFILE_RE = re.compile(r"(This profile is private|profile_private|friendBlocked)", re.I)
_FRIENDS_ONLY_RE = re.compile(r"(Only friends can see|friends_only)", re.I)
# Games embedded JSON array
_RGGAMES_RE = re.compile(r"var rgGames\s*=\s*(\[.*?\]);", re.DOTALL)
# Rough game-count string ("X games" visible in heading)
_GAME_COUNT_RE = re.compile(r"(\d[\d,]*)\s+games?", re.I)


# ------------------------------------------------------------------ hints


def _verification_hints_steam(candidate):
    return [
        "SteamID64 is a permanent unique identifier — it never changes even if "
        "the display name or vanity URL does",
        "Account creation date and early game library build-up is a reliable "
        "timeline anchor",
        "Game genres, playtime patterns, and achievement profiles reveal "
        "detailed interests",
        "VAC bans are permanent flags worth noting in an identity profile",
        "Real name display (when enabled) is a direct identity link",
    ]


# ------------------------------------------------------------------ module


class SteamOsint(BaseModule):
    name = "harvest/steam_osint"
    description = "Steam public profile OSINT via web scrape (no API key required)"
    category = "harvest"
    target_type = "username"
    intrusive = False

    def _register_options(self):
        self.add_option(
            "TARGET", "", True,
            "Steam vanity username or SteamID64 (17-digit number)"
        )
        self.add_option("VARIATIONS", "true", False, "Pivot via username variations")
        self.add_option("MAX_VARIATIONS", "15", False, "Max variations to probe")

    # ------------------------------------------------------------------ helpers

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

    def _parse_target(self, raw):
        """Return (profile_url, identifier, is_steamid64)."""
        raw = (raw or "").strip()
        # Strip URL prefix if present
        raw = re.sub(
            r"^https?://steamcommunity\.com/(id|profiles)/", "", raw, flags=re.I
        )
        raw = raw.strip("/").split("?")[0].strip()
        if _STEAMID64_RE.match(raw):
            return (f"https://steamcommunity.com/profiles/{raw}", raw, True)
        return (f"https://steamcommunity.com/id/{raw}", raw, False)

    def _meta_tag(self, html, *patterns):
        """Try multiple regex patterns for the same meta property; return first match."""
        for pat in patterns:
            m = pat.search(html or "")
            if m:
                return m.group(1).strip()
        return None

    def _steam_get(self, url):
        """http.get with Steam UA; returns Response or None on exception."""
        try:
            return http.get(
                url,
                headers={"User-Agent": _STEAM_UA},
                timeout=15,
                allow_redirects=True,
            )
        except Exception as exc:
            self._warn.append(f"HTTP error ({url}): {exc}")
            return None

    def _safe_text(self, resp):
        if resp is None or resp.status_code >= 400:
            return None
        return resp.text or ""

    # ------------------------------------------------------------------ page validation

    def _detect_page_valid(self, html):
        """Return True if the HTML looks like a real Steam profile (not error/redirect)."""
        if not html:
            return False
        raw_title = self._meta_tag(html, _OG_TITLE_RE, _OG_TITLE_RE2)
        if not raw_title:
            return False
        # Steam's generic error / store pages have bare "Steam" or "Steam Community" titles
        if raw_title.strip().lower() in ("steam", "steam community", ""):
            return False
        return True

    # ------------------------------------------------------------------ profile extract

    def _extract_profile(self, html):
        """Parse Steam profile HTML into a flat dict."""
        result = {
            "display_name": None,
            "real_name": None,
            "bio": None,
            "avatar": None,
            "steamid64": None,
            "level": None,
            "location": None,
            "member_since": None,
            "vac_banned": False,
            "profile_visibility": "public",
        }
        if not html:
            return result

        result["display_name"] = self._meta_tag(html, _OG_TITLE_RE, _OG_TITLE_RE2)
        result["bio"] = self._meta_tag(html, _OG_DESC_RE, _OG_DESC_RE2)
        result["avatar"] = self._meta_tag(html, _OG_IMAGE_RE, _OG_IMAGE_RE2)

        # SteamID64 from data attribute
        m = _DATA_STEAMID_RE.search(html)
        if m:
            result["steamid64"] = m.group(1)

        # Real name (shown only when user enables it)
        m = _ACTUAL_NAME_RE.search(html)
        if m:
            val = m.group(1).strip()
            result["real_name"] = val or None

        # Steam level
        m = _LEVEL_RE.search(html)
        if m:
            try:
                result["level"] = int(m.group(1))
            except ValueError:
                pass

        # Member since date
        m = _MEMBER_SINCE_RE.search(html)
        if m:
            result["member_since"] = m.group(1).strip()

        # Location (within header_real_name <bdi> block)
        m = _LOCATION_RE.search(html)
        if m:
            result["location"] = m.group(1).strip()

        # VAC ban check
        if _VAC_RE.search(html):
            result["vac_banned"] = True

        # Profile visibility
        if _PRIVATE_PROFILE_RE.search(html):
            result["profile_visibility"] = "private"
        elif _FRIENDS_ONLY_RE.search(html):
            result["profile_visibility"] = "friends_only"

        return result

    # ------------------------------------------------------------------ games page

    def _scrape_games_page(self, profile_url):
        """Scrape /games/?tab=all for game count and top-5 played games.
        Returns (game_count_or_None, list_of_game_dicts).
        """
        games_url = profile_url.rstrip("/") + "/games/?tab=all"
        resp = self._steam_get(games_url)
        html = self._safe_text(resp)
        if not html:
            return None, []

        # Private or friends-only profiles redirect to the main profile page
        if _PRIVATE_PROFILE_RE.search(html) or _FRIENDS_ONLY_RE.search(html):
            self._warn.append("Games page hidden (non-public profile)")
            return None, []

        game_count = None
        top_games = []

        # Total count from page heading ("X games")
        m = _GAME_COUNT_RE.search(html)
        if m:
            try:
                game_count = int(m.group(1).replace(",", ""))
            except ValueError:
                pass

        # rgGames JS array contains full owned-game data
        m = _RGGAMES_RE.search(html)
        if m:
            try:
                games_list = json.loads(m.group(1))
                if isinstance(games_list, list):
                    # Derive a sort key from hours_forever (string like "12.3")
                    def _hours(g):
                        try:
                            return float(str(g.get("hours_forever") or "0").replace(",", ""))
                        except (ValueError, TypeError):
                            return 0.0

                    games_list.sort(key=_hours, reverse=True)
                    for g in games_list[:5]:
                        name = (g.get("name") or "").strip()
                        if name:
                            top_games.append({
                                "name": name,
                                "appid": g.get("appid"),
                                "hours": g.get("hours_forever"),
                            })
                    # Use JS array length as count if heading didn't give one
                    if game_count is None:
                        game_count = len(games_list)
            except (ValueError, TypeError):
                pass

        return game_count, top_games

    # ------------------------------------------------------------------ variations

    def _probe_variation(self, candidate, base):
        """Check steamcommunity.com/id/{candidate}. Return hit dict or None."""
        try:
            resp = self._steam_get(f"https://steamcommunity.com/id/{candidate}")
        except Exception:
            return None
        html = self._safe_text(resp)
        if not html or not self._detect_page_valid(html):
            return None

        display_name = self._meta_tag(html, _OG_TITLE_RE, _OG_TITLE_RE2) or candidate
        steamid64 = None
        mid = _DATA_STEAMID_RE.search(html)
        if mid:
            steamid64 = mid.group(1)

        sim = round(
            SequenceMatcher(None, base.lower(), candidate.lower()).ratio(), 3
        )
        hit = {
            "username": candidate,
            "display_name": display_name,
            "profile_url": f"https://steamcommunity.com/id/{candidate}",
            "steamid64": steamid64,
            "similarity": sim,
            "exists": True,
        }
        hit["confidence_tier"] = confidence_tier(sim)
        hit["is_verified_as_target"] = False
        hit["verification_hints"] = _verification_hints_steam(hit)
        return hit

    def _search_variations(self, username, max_variations):
        """Generate and probe username variations. Skips for SteamID64 targets."""
        if _STEAMID64_RE.match(username):
            return [], []

        raw = generate_variations(username, max_variations * 3)
        variations = platform_filter(raw, "steam")
        cleaned, seen = [], set()
        for v in variations:
            v = (v or "").strip()
            if not _VANITY_RE.match(v):
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

        with ThreadPoolExecutor(max_workers=5) as pool:
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

        raw_target = self.get_option("TARGET") or ""
        profile_url, target_id, is_steamid64 = self._parse_target(raw_target)

        if not target_id:
            print_status("TARGET resolved to empty identifier", "error")
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))
        self._warn = []

        id_label = (
            f"SteamID64={target_id}" if is_steamid64 else f"vanity={target_id}"
        )
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 58}")
        print(f"  Steam OSINT: {target_id}")
        print(f"{'=' * 58}{Colors.RESET}\n")
        print_status(f"Target: {id_label}  |  URL: {profile_url}", "info")

        # Step 1 — Scrape profile page
        print_status("Fetching Steam profile page...", "info")
        resp = self._steam_get(profile_url)
        html = self._safe_text(resp)
        page_valid = self._detect_page_valid(html)

        profile = {}
        if page_valid:
            profile = self._extract_profile(html)
            print_status(
                f"Profile found: display_name={profile.get('display_name')!r}  "
                f"visibility={profile.get('profile_visibility')}",
                "success",
            )
            if profile.get("steamid64"):
                print_status(f"SteamID64: {profile['steamid64']}", "success")
            if profile.get("real_name"):
                print_status(f"Real name: {profile['real_name']}", "success")
            if profile.get("level") is not None:
                print_status(f"Level: {profile['level']}", "info")
            if profile.get("member_since"):
                print_status(f"Member since: {profile['member_since']}", "info")
            if profile.get("location"):
                print_status(f"Location: {profile['location']}", "info")
            if profile.get("vac_banned"):
                print_status("VAC BANNED", "warning")
            if profile.get("bio"):
                print_status(f"Bio: {profile['bio'][:120]}", "info")
        else:
            if resp is not None and resp.status_code == 200:
                print_status(
                    "Page returned 200 but appears generic (vanity URL may not exist)",
                    "warning",
                )
            else:
                status_code = resp.status_code if resp is not None else "N/A"
                print_status(
                    f"Profile page not accessible (HTTP {status_code})", "warning"
                )

        # Resolve SteamID64 — use what the page gave us, or the TARGET if it was one
        steamid64 = profile.get("steamid64") or (target_id if is_steamid64 else None)

        # Step 2 — Games page (public profiles only)
        game_count, top_games = None, []
        if page_valid:
            visibility = profile.get("profile_visibility", "public")
            if visibility == "public":
                print_status("Fetching games page...", "info")
                game_count, top_games = self._scrape_games_page(profile_url)
                if game_count is not None:
                    print_status(f"Games: {game_count:,} in library", "success")
                else:
                    print_status("Game count not available from page", "info")
                if top_games:
                    print_status(
                        f"Top games: "
                        f"{', '.join(g['name'] for g in top_games[:3])}",
                        "info",
                    )
            else:
                print_status(
                    f"Skipping games page (profile visibility={visibility})", "info"
                )

        # Step 3 — Bio handle pivot
        bio_handles = {}
        bio_text = profile.get("bio") or ""
        if _VARIATIONS_OK and bio_text:
            try:
                bio_handles = extract_handles_from_bio(bio_text) or {}
            except Exception:
                bio_handles = {}
            bio_handles = {k: v for k, v in bio_handles.items() if v}
            if bio_handles:
                counts = ", ".join(
                    f"{k}:{len(v)}" for k, v in bio_handles.items()
                )
                print_status(f"Bio pivots found - {counts}", "success")

        # Step 4 — Variation probe
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK and not is_steamid64:
            print_status(
                f"Probing up to {max_variations} username variations...", "info"
            )
            variations_tried, candidates = self._search_variations(
                target_id, max_variations
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
        elif do_variations and is_steamid64:
            print_status("Target is SteamID64 - skipping variation probe", "info")
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping pivot", "warning"
            )

        # ------------------------------------------------------------- results
        self.results = {
            "username": target_id,
            "profile_url": profile_url,
            "steamid64": steamid64,
            "display_name": profile.get("display_name"),
            "real_name": profile.get("real_name"),
            "bio": bio_text,
            "avatar": profile.get("avatar"),
            "level": profile.get("level"),
            "location": profile.get("location"),
            "member_since": profile.get("member_since"),
            "vac_banned": profile.get("vac_banned", False),
            "profile_visibility": profile.get("profile_visibility", "unknown"),
            "game_count": game_count,
            "top_games": top_games,
            "bio_handles": bio_handles,
            "candidates": candidates,
            "warnings": self._warn,
            "source": "steamcommunity.com web scrape (public, no API key)",
            "disclaimer": build_disclaimer("Steam", len(candidates)),
        }

        # Steam serves a 200 generic page for a nonexistent vanity (a clean
        # negative) and 404 for a dead profile; a None response (network error)
        # or a 403/429/5xx is a FETCH FAILURE, not "account not found".
        status_code = resp.status_code if resp is not None else 0
        direct_fetch_failed = (not page_valid) and status_code not in (200, 404)
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status("Direct lookup INCONCLUSIVE - Steam blocked/unreachable "
                         f"(HTTP {status_code or 'none'}); this is NOT evidence the "
                         "account is absent", "warning")

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'=' * 58}")
        print(f"  Summary: {target_id}")
        print(f"{'-' * 58}{Colors.RESET}")
        print(f"  Profile URL:  {profile_url}")
        if page_valid:
            print(f"  Account:      found")
            if profile.get("display_name"):
                print(f"  Display Name: {profile['display_name']}")
            if profile.get("real_name"):
                print(f"  Real Name:    {profile['real_name']}")
            if steamid64:
                print(f"  SteamID64:    {steamid64}")
            if profile.get("level") is not None:
                print(f"  Level:        {profile['level']}")
            if profile.get("member_since"):
                print(f"  Member Since: {profile['member_since']}")
            if profile.get("location"):
                print(f"  Location:     {profile['location']}")
            print(f"  Visibility:   {profile.get('profile_visibility', 'unknown')}")
            if profile.get("vac_banned"):
                print(f"  {Colors.YELLOW}VAC BANNED:   yes{Colors.RESET}")
            if game_count is not None:
                print(f"  Games:        {game_count:,}")
            if top_games:
                names = ", ".join(g["name"] for g in top_games[:5])
                print(f"  Top Games:    {names}")
            if bio_text:
                print(f"  Bio:          {bio_text[:120]}")
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
            print_uncertainty_box("Steam", _verification_hints_steam({}))

        return True
