"""TikTok OSINT - public profile scrape + bio pivot + username variations.

Zero-auth: pulls everything from the embedded __UNIVERSAL_DATA_FOR_REHYDRATION__
JSON on the public profile page. No cookies, no login, no API keys.
"""
import re
import json
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest._social_base import (
    confidence_tier,
    print_uncertainty_box,
    build_disclaimer,
)

# Soft import so the base scrape keeps working even if the helper is missing.
try:
    from modules.harvest.username_variations import (
        generate_variations,
        platform_filter,
        detect_birth_year,
        extract_handles_from_bio,
    )
    _VARIATIONS_OK = True
except Exception:
    _VARIATIONS_OK = False

    def generate_variations(_u, _n=20):
        return []

    def platform_filter(items, _platform):
        return items

    def detect_birth_year(_u):
        return None

    def extract_handles_from_bio(_text):
        return {}


_UNIVERSAL_RE = re.compile(
    r'<script[^>]+id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>',
    re.DOTALL,
)
_TIKTOK_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{2,24}$")
# A redirect to tiktok.com/?lang=... is TikTok's "user not found" signal
_NOT_FOUND_URL_RE = re.compile(r"https?://www\.tiktok\.com/\?lang=", re.I)


def _tiktok_real_signals(user_data, stats_data):
    """Count 'real account' signals. More signals = higher confidence."""
    user_data = user_data or {}
    stats_data = stats_data or {}
    signature = user_data.get("signature") or ""
    try:
        video_count = int(stats_data.get("videoCount") or 0)
    except (TypeError, ValueError):
        video_count = 0
    try:
        heart_count = int(stats_data.get("heartCount") or stats_data.get("heart") or 0)
    except (TypeError, ValueError):
        heart_count = 0

    signals = {
        "has_user_id": bool(user_data.get("id")),
        "has_sec_uid": bool(user_data.get("secUid")),
        "has_create_time": bool(user_data.get("createTime")),  # strong signal
        "has_nickname": bool(user_data.get("nickname")),
        "has_signature": bool(signature.strip()),
        "has_avatar_larger": bool(user_data.get("avatarLarger")),
        "has_region": bool(user_data.get("region")),
        "has_follower_count": stats_data.get("followerCount") is not None,
        "has_video_count": video_count > 0,  # posted at least one video
        "has_heart_count": heart_count > 0,
    }
    score = sum(1 for v in signals.values() if v)
    return signals, score


def _detect_account_state(user_data, stats_data):
    """Classify an account as active/empty/restricted/private/unknown."""
    user_data = user_data or {}
    stats_data = stats_data or {}
    try:
        followers = int(stats_data.get("followerCount") or 0)
    except (TypeError, ValueError):
        followers = 0
    try:
        videos = int(stats_data.get("videoCount") or 0)
    except (TypeError, ValueError):
        videos = 0
    try:
        hearts = int(stats_data.get("heartCount") or stats_data.get("heart") or 0)
    except (TypeError, ValueError):
        hearts = 0

    if user_data.get("ftc") or user_data.get("secret"):
        return "restricted"
    if user_data.get("privateAccount"):
        return "private"
    if videos == 0 and followers == 0 and hearts == 0:
        return "empty"
    nickname = (user_data.get("nickname") or "").strip().lower()
    unique_id = (user_data.get("uniqueId") or "").strip().lower()
    if videos > 0 or followers > 0:
        return "active"
    if nickname and unique_id and nickname == unique_id and videos == 0:
        return "empty"
    return "unknown"


def _verification_hints_tiktok(candidate):
    hints = [
        "Check creation date (TikTok exposes it in createTime) — match to target's known TikTok timeline",
        "Check region (TikTok exposes country code) — mismatch is a strong signal this isn't the target",
        "Compare nickname, bio, and bio_link against target's known patterns",
        "Review recent video content — language, voice, face, and location clues",
        "Follower count can validate: a 'real person' target usually has <5k followers unless they're a known creator",
        "Verified badge: if the target isn't publicly notable, a verified account is probably NOT them",
    ]
    if candidate.get("verified"):
        hints.insert(0, "This account is VERIFIED (TikTok blue check) — only publicly notable creators get this. Likely NOT your target unless they're a known public figure.")
    if candidate.get("private"):
        hints.insert(0, "This account is PRIVATE — public data is limited to the shown fields.")
    region = candidate.get("region")
    if region:
        hints.append(f"Account region: {region} — does this match the target's known country?")
    return hints


class TiktokOsint(BaseModule):
    name = "harvest/tiktok_osint"
    description = "TikTok deep OSINT - public profile JSON + bio pivot + username variations"
    category = "harvest"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True, "TikTok username (with or without @)")
        self.add_option("VARIATIONS", "true", False, "Pivot via username variations")
        self.add_option("MAX_VARIATIONS", "15", False, "Max variations to probe")

    # ------------------------------------------------------------------ helpers

    def _clean(self, username):
        username = (username or "").strip().lstrip("@")
        username = re.sub(r"https?://(?:www\.)?tiktok\.com/@", "", username)
        return username.strip("/").split("?")[0].split("/")[0]

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

    def _to_iso(self, ts):
        try:
            n = int(ts)
            if n <= 0:
                return None
            return datetime.datetime.utcfromtimestamp(n).isoformat() + "Z"
        except (TypeError, ValueError):
            return None

    # ------------------------------------------------------------------ parse

    def _parse_universal(self, html):
        """Return the parsed __UNIVERSAL_DATA_FOR_REHYDRATION__ JSON, or {}."""
        m = _UNIVERSAL_RE.search(html or "")
        if not m:
            return {}
        try:
            return json.loads(m.group(1).strip())
        except (ValueError, TypeError):
            return {}

    def _user_info(self, data):
        """Dig out userInfo from the parsed universal blob."""
        try:
            scope = data.get("__DEFAULT_SCOPE__", {})
            detail = scope.get("webapp.user-detail", {})
            info = detail.get("userInfo") or {}
            return info if isinstance(info, dict) else {}
        except AttributeError:
            return {}

    def _node_share(self, username):
        """Fallback: tiktok.com/node/share/user sometimes returns JSON directly."""
        try:
            resp = http.get(
                f"https://www.tiktok.com/node/share/user/@{username}", timeout=12
            )
            if resp.status_code == 429:
                self._warn.append("node/share rate-limited (429)")
                return {}
            if resp.status_code != 200:
                return {}
            # Response is sometimes JSON, sometimes an HTML wrapper
            try:
                payload = resp.json()
            except ValueError:
                data = self._parse_universal(resp.text)
                return self._user_info(data)
            if isinstance(payload, dict):
                return (
                    payload.get("userInfo")
                    or payload.get("data", {}).get("userInfo")
                    or {}
                )
        except Exception as exc:
            self._warn.append(f"node/share error: {exc}")
        return {}

    def _fetch_profile(self, username):
        """Grab the HTML profile page and return (userInfo dict, exists bool).

        Sets self._direct_blocked when the fetch itself failed (429 / non-200 /
        network error) so run() can tell a block apart from a clean 'not found'
        (404 or the ?lang= redirect)."""
        try:
            resp = http.get(f"https://www.tiktok.com/@{username}", timeout=15,
                            allow_redirects=True)
        except Exception as exc:
            self._warn.append(f"profile fetch error: {exc}")
            self._direct_blocked = True
            return {}, False

        if resp.status_code == 429:
            self._warn.append("tiktok.com rate-limited (429)")
            self._direct_blocked = True
            return {}, False
        if resp.status_code == 404:
            return {}, False
        # Redirect to tiktok.com/?lang=... means username doesn't exist
        final_url = getattr(resp, "url", "") or ""
        if _NOT_FOUND_URL_RE.match(final_url):
            return {}, False
        if resp.status_code != 200:
            self._direct_blocked = True
            return {}, False

        data = self._parse_universal(resp.text)
        info = self._user_info(data)
        if not info:
            # Try the fallback endpoint before giving up
            info = self._node_share(username)
        return info, bool(info)

    # ------------------------------------------------------------------ shape

    def _normalize(self, info):
        """Turn raw userInfo into the module's flat profile dict."""
        user = (info.get("user") or {}) if isinstance(info, dict) else {}
        stats = (info.get("stats") or info.get("statsV2") or {}) if isinstance(info, dict) else {}
        bio_link = user.get("bioLink") or {}
        if not isinstance(bio_link, dict):
            bio_link = {}

        def _n(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0

        return {
            "id": user.get("id"),
            "sec_uid": user.get("secUid"),
            "username": user.get("uniqueId"),
            "nickname": user.get("nickname"),
            "bio": user.get("signature") or "",
            "bio_link": {
                "link": bio_link.get("link"),
                "risk": bio_link.get("risk"),
            } if bio_link.get("link") else None,
            "verified": bool(user.get("verified")),
            "private": bool(user.get("privateAccount")),
            "ftc": bool(user.get("ftc")),
            "tt_seller": bool(user.get("ttSeller")),
            "region": user.get("region"),
            "created_at": self._to_iso(user.get("createTime")),
            "avatar_url": user.get("avatarLarger") or user.get("avatarMedium")
                          or user.get("avatarThumb"),
            "avatars": {
                "large": user.get("avatarLarger"),
                "medium": user.get("avatarMedium"),
                "thumb": user.get("avatarThumb"),
            },
            "stats": {
                "followers": _n(stats.get("followerCount")),
                "following": _n(stats.get("followingCount")),
                "hearts": _n(stats.get("heartCount") or stats.get("heart")),
                "videos": _n(stats.get("videoCount")),
                "friends": _n(stats.get("friendCount")),
            },
        }

    # ------------------------------------------------------------------ pivots

    def _probe_variation(self, candidate, base):
        """Probe tiktok.com/@{candidate}. Return hit dict only on real match."""
        try:
            resp = http.get(f"https://www.tiktok.com/@{candidate}", timeout=10,
                            allow_redirects=True)
        except Exception:
            return None
        if resp.status_code == 429:
            self._warn.append(f"probe rate-limited (429) on {candidate}")
            return None
        if resp.status_code != 200:
            return None
        final_url = getattr(resp, "url", "") or ""
        if _NOT_FOUND_URL_RE.match(final_url):
            return None
        # Accuracy > false positives: require UNIVERSAL_DATA AND a non-empty userInfo
        if "__UNIVERSAL_DATA_FOR_REHYDRATION__" not in resp.text:
            return None
        data = self._parse_universal(resp.text)
        info = self._user_info(data)
        user = info.get("user") if isinstance(info, dict) else None
        if not user or not user.get("uniqueId"):
            return None
        stats = info.get("stats") or info.get("statsV2") or {}

        # Signal check: real accounts fire multiple signals
        signals, signals_count = _tiktok_real_signals(user, stats)
        if signals_count < 4:
            return None

        sim = round(SequenceMatcher(None, base.lower(),
                                    candidate.lower()).ratio(), 3)
        try:
            followers = int(stats.get("followerCount") or 0)
        except (TypeError, ValueError):
            followers = 0
        hit = {
            "username": user.get("uniqueId"),
            "nickname": user.get("nickname") or "",
            "similarity": sim,
            "followers": followers,
            "verified": bool(user.get("verified")),
            "private": bool(user.get("privateAccount")),
            "ftc": bool(user.get("ftc")),
            "region": user.get("region"),
            "exists": True,
            "signals": signals,
            "signals_count": signals_count,
            "confidence": round(signals_count / 10.0, 2),
            "account_state": _detect_account_state(user, stats),
        }
        hit["confidence_tier"] = confidence_tier(sim)
        hit["is_verified_as_target"] = False
        hit["verification_hints"] = _verification_hints_tiktok(hit)
        return hit

    def _search_variations(self, username, max_variations):
        base = generate_variations(username, max_variations * 3)
        # TikTok constraints line up with Instagram - start there, then local-filter
        variations = platform_filter(base, "instagram")
        cleaned, seen = [], set()
        for v in variations:
            if not _TIKTOK_USERNAME_RE.match(v):
                continue
            if v.startswith(".") or v.endswith("."):
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
            futures = {pool.submit(self._probe_variation, c, username): c
                       for c in cleaned}
            for fut in as_completed(futures):
                hit = fut.result()
                if hit:
                    candidates.append(hit)
        candidates.sort(key=lambda x: x["similarity"], reverse=True)
        return cleaned, candidates

    # ------------------------------------------------------------------ run

    def run(self):
        if not self.validate():
            return False

        username = self._clean(self.get_option("TARGET"))
        if not username:
            print_status("Empty TARGET after cleanup", "error")
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))
        self._warn = []
        self._direct_blocked = False

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  TikTok OSINT: @{username}")
        print(f"{'='*58}{Colors.RESET}\n")

        # 1) Direct profile scrape
        print_status("Fetching public profile page...", "info")
        info, raw_exists = self._fetch_profile(username)
        profile = {
            "exists": False,
            "signals": {},
            "signals_count": 0,
            "confidence": 0.0,
            "account_state": "unknown",
        }
        exists = False
        if raw_exists:
            profile = self._normalize(info)
            user_raw = (info.get("user") or {}) if isinstance(info, dict) else {}
            stats_raw = (
                info.get("stats") or info.get("statsV2") or {}
            ) if isinstance(info, dict) else {}
            signals, signals_count = _tiktok_real_signals(user_raw, stats_raw)
            account_state = _detect_account_state(user_raw, stats_raw)
            confidence = round(signals_count / 10.0, 2)

            # REAL only if uniqueId present AND >= 4 real-account signals fire
            exists = bool(profile.get("username")) and signals_count >= 4

            profile["exists"] = exists
            profile["signals"] = signals
            profile["signals_count"] = signals_count
            profile["confidence"] = confidence
            profile["account_state"] = account_state

            if exists:
                print_status(
                    f"Hit: @{profile.get('username')} "
                    f"({profile.get('nickname') or '-'})", "success")
                print_status(
                    f"Real-account signals: {signals_count}/10 "
                    f"(confidence={confidence}, state={account_state})",
                    "success" if signals_count >= 7 else "info")
                if profile.get("verified"):
                    print_status("Verified account", "success")
                if profile.get("private"):
                    print_status("Private account", "warning")
                if profile.get("ftc"):
                    print_status("Restricted (ftc flag set)", "warning")
                s = profile.get("stats", {})
                print_status(
                    f"Stats: followers={s.get('followers')} following={s.get('following')} "
                    f"hearts={s.get('hearts')} videos={s.get('videos')}", "info")
                if profile.get("region"):
                    print_status(f"Region: {profile['region']}", "info")
                if profile.get("created_at"):
                    print_status(f"Created: {profile['created_at']}", "info")
                if profile.get("bio"):
                    print_status(f"Bio: {profile['bio'][:120]}", "info")
                if profile.get("bio_link"):
                    print_status(
                        f"Bio link: {profile['bio_link']['link']} "
                        f"(risk={profile['bio_link'].get('risk')})", "info")
            else:
                print_status(
                    f"Weak signals ({signals_count}/10) — not treating as a real "
                    f"account (likely redirect/placeholder/suspended)",
                    "warning")
        else:
            print_status(
                "No public profile (private handle, nonexistent, or blocked)",
                "warning")

        # 2) Birth-year hint
        birth_hint = None
        if _VARIATIONS_OK:
            try:
                birth_hint = detect_birth_year(username)
            except Exception:
                birth_hint = None
            if birth_hint:
                print_status(
                    f"Possible birth year: {birth_hint.get('year')} "
                    f"(confidence {birth_hint.get('confidence')}, "
                    f"base='{birth_hint.get('base')}')", "info")

        # 3) Variations pivot
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(
                f"Probing up to {max_variations} username variations...", "info")
            variations_tried, candidates = self._search_variations(
                username, max_variations)
            print_status(
                f"Tried {len(variations_tried)} variations, "
                f"{len(candidates)} candidate(s)",
                "success" if candidates else "info")
            for c in candidates[:10]:
                mark = " [verified]" if c.get("verified") else ""
                tier = c.get("confidence_tier") or confidence_tier(
                    c.get("similarity") or 0)
                severity = "warning" if tier in ("medium", "low") else "info"
                suffix = " — NOT CONFIRMED"
                if tier == "exact-match":
                    suffix += (" (exact username match — still verify this "
                               "is actually your target)")
                print_status(
                    f"[CANDIDATE/{tier}]  -> @{c['username']} "
                    f"(sim={c['similarity']}, "
                    f"followers={c['followers']}){mark}{suffix}", severity)
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping pivot",
                "warning")

        # 4) Bio pivot (bio text + structured bio link)
        bio_pivots = {}
        if _VARIATIONS_OK:
            bio_blob_parts = [profile.get("bio") or ""]
            bl = profile.get("bio_link") or {}
            if bl.get("link"):
                bio_blob_parts.append(bl["link"])
            for c in candidates:
                if c.get("nickname"):
                    bio_blob_parts.append(c["nickname"])
            bio_blob = " ".join(p for p in bio_blob_parts if p)
            try:
                bio_pivots = extract_handles_from_bio(bio_blob) or {}
            except Exception:
                bio_pivots = {}
            # Drop empty buckets so the summary stays tight
            bio_pivots = {k: v for k, v in bio_pivots.items() if v}
            if bio_pivots:
                counts = ", ".join(f"{k}:{len(v)}"
                                   for k, v in bio_pivots.items())
                print_status(f"Bio pivots found - {counts}", "success")

        # ------------------------------------------------------------- results
        self.results = {
            "username": username,
            "url": f"https://www.tiktok.com/@{username}",
            "profile": profile,
            "bio_pivots": bio_pivots,
            "birth_year_hint": birth_hint,
            "variations_tried": variations_tried,
            "candidates": candidates,
            "warnings": self._warn,
        }
        self.results["disclaimer"] = build_disclaimer("TikTok", len(candidates))

        # A 429 / non-200 / network error on the direct page is a FETCH FAILURE,
        # never a clean "account does not exist" (404 or ?lang= redirect).
        direct_fetch_failed = (not profile.get("exists")) and self._direct_blocked
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status("Direct lookup INCONCLUSIVE - TikTok blocked/rate-limited; "
                         "this is NOT evidence the account is absent", "warning")

        # ------------------------------------------------------------- summary
        direct_hit = bool(profile.get("exists"))
        signals_count = profile.get("signals_count", 0) if profile else 0
        confidence = profile.get("confidence", 0.0) if profile else 0.0
        state = profile.get("account_state", "unknown") if profile else "unknown"
        if direct_hit and state == "empty":
            direct_hit_line = (
                f"yes but EMPTY account  confidence={confidence}  state={state}  "
                f"(no videos/followers)"
            )
        elif direct_hit:
            direct_hit_line = (
                f"yes  confidence={confidence}  state={state}  "
                f"({signals_count} signals)"
            )
        else:
            direct_hit_line = "no"

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: @{username}")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  Link:         https://www.tiktok.com/@{username}")
        print(f"  Direct hit:   {direct_hit_line}")
        if direct_hit:
            print(f"  ID:           {profile.get('id')}")
            if profile.get("sec_uid"):
                print(f"  secUid:       {profile['sec_uid']}")
            if profile.get("nickname"):
                print(f"  Nickname:     {profile['nickname']}")
            if profile.get("region"):
                print(f"  Region:       {profile['region']}")
            if profile.get("created_at"):
                print(f"  Created:      {profile['created_at']}")
            s = profile.get("stats", {})
            print(f"  Followers:    {s.get('followers')}")
            print(f"  Following:    {s.get('following')}")
            print(f"  Videos:       {s.get('videos')}")
            print(f"  Hearts:       {s.get('hearts')}")
            flags = []
            if profile.get("verified"):
                flags.append("verified")
            if profile.get("private"):
                flags.append("private")
            if profile.get("ftc"):
                flags.append("ftc")
            if profile.get("tt_seller"):
                flags.append("tt_seller")
            if flags:
                print(f"  Flags:        {', '.join(flags)}")
            if (profile.get("bio_link") or {}).get("link"):
                print(f"  Bio link:     {profile['bio_link']['link']}")
        print(f"  Candidates:   {len(candidates)} "
              f"(from {len(variations_tried)} tried)")
        if bio_pivots:
            parts = [f"{k}:{len(v)}" for k, v in bio_pivots.items()]
            print(f"  Bio pivots:   {', '.join(parts)}")
        if birth_hint:
            print(f"  Birth year:   {birth_hint.get('year')} "
                  f"(conf={birth_hint.get('confidence')})")
        if self._warn:
            print(f"\n  {Colors.DIM}{len(self._warn)} warning(s): "
                  f"{'; '.join(self._warn[:3])}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        if candidates:
            print_uncertainty_box("TikTok")

        return True
