"""Discord OSINT - comprehensive public-source lookup for a Discord user.

Given a Discord username (new system) or a 17-20 digit snowflake user ID this
module decodes the snowflake, queries free lookup services (discordlookup,
japi.rest, Lanyard), optionally enriches via the official Bot API if a token
is configured, and extracts pivots (connections, bio handles, candidate
username variations).

All endpoints are hit live via core.http (proxy / retry / rate-limit aware).
No auth is required for the OSINT path; a Discord bot token under
``api_keys.discord_bot`` is used only to enrich a known ID via the official
API.  The module NEVER posts to ``discord.com/api/*/auth/*``.
"""

import re
import json
import datetime
from difflib import SequenceMatcher

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.config import Config
from core import http
from modules.harvest._social_base import (
    confidence_tier,
    print_uncertainty_box,
    build_disclaimer,
)


# Discord new-username constraints: 2-32 chars, lowercase letters / digits / _ / .
_USERNAME_RE = re.compile(r"^[a-z0-9._]{2,32}$")
_SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")

# Discord epoch in milliseconds (2015-01-01)
_DISCORD_EPOCH_MS = 1420070400000

# Public flag bitfield -> badge name (official Discord docs)
PUBLIC_FLAGS = {
    1 << 0:  "DISCORD_EMPLOYEE",
    1 << 1:  "PARTNERED_SERVER_OWNER",
    1 << 2:  "HYPESQUAD_EVENTS",
    1 << 3:  "BUG_HUNTER_LEVEL_1",
    1 << 6:  "HOUSE_BRAVERY",
    1 << 7:  "HOUSE_BRILLIANCE",
    1 << 8:  "HOUSE_BALANCE",
    1 << 9:  "EARLY_SUPPORTER",
    1 << 10: "TEAM_USER",
    1 << 14: "BUG_HUNTER_LEVEL_2",
    1 << 16: "VERIFIED_BOT",
    1 << 17: "EARLY_VERIFIED_BOT_DEVELOPER",
    1 << 18: "CERTIFIED_MODERATOR",
    1 << 19: "BOT_HTTP_INTERACTIONS",
    1 << 22: "ACTIVE_DEVELOPER",
}

# Optional shared variation helpers; fall back to local generator if absent.
try:
    from modules.harvest.username_variations import (
        generate_variations as _ext_generate_variations,
        platform_filter as _ext_platform_filter,
    )
except Exception:
    _ext_generate_variations = None
    _ext_platform_filter = None


def _sanitize_for_discord(name):
    """Shape a candidate string into Discord new-username rules."""
    name = (name or "").lower()
    name = re.sub(r"[^a-z0-9._]", "", name)
    name = re.sub(r"\.{2,}", ".", name).strip("._")
    return name if 2 <= len(name) <= 32 else ""


def _fallback_variations(username, max_count):
    """Minimal in-module generator used when the shared helper is unavailable."""
    base = username.lower().strip()
    seeds = {base, base.replace("_", ""), base.replace(".", ""),
             base.replace("-", "_"), base.replace("-", ".")}
    out = []
    for seed in list(seeds):
        for suffix in ("", "1", "2", "7", "01", "99", "_", ".real", "_real", "hq"):
            out.append(seed + suffix)
        for prefix in ("", "real", "the", "_"):
            out.append(prefix + seed)
    cleaned, seen = [], set()
    for v in out:
        v2 = _sanitize_for_discord(v)
        if v2 and v2 not in seen:
            seen.add(v2)
            cleaned.append(v2)
        if len(cleaned) >= max_count:
            break
    return cleaned


def _variations(username, max_count):
    """Prefer the shared helper if installed; otherwise fall back."""
    if _ext_generate_variations and _ext_platform_filter:
        try:
            raw = _ext_generate_variations(username, limit=max_count * 3)
            filtered = _ext_platform_filter(raw, platform="discord")
            cleaned, seen = [], set()
            for v in filtered:
                v2 = _sanitize_for_discord(v)
                if v2 and v2 not in seen:
                    seen.add(v2)
                    cleaned.append(v2)
                if len(cleaned) >= max_count:
                    break
            if cleaned:
                return cleaned
        except Exception:
            pass
    return _fallback_variations(username, max_count)


_BIO_PATTERNS = {
    "telegram":  re.compile(r"(?:t\.me/|@)([A-Za-z0-9_]{5,32})"),
    "github":    re.compile(r"github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})"),
    "twitter":   re.compile(r"(?:twitter\.com/|x\.com/)([A-Za-z0-9_]{1,15})"),
    "instagram": re.compile(r"instagram\.com/([A-Za-z0-9_.]{1,30})"),
    "steam":     re.compile(r"steamcommunity\.com/(?:id|profiles)/([A-Za-z0-9_-]+)"),
    "youtube":   re.compile(r"youtube\.com/(?:@|c/|user/)([A-Za-z0-9_-]+)"),
    "email":     re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}


def _extract_handles_from_bio(bio):
    found = {}
    if not bio:
        return found
    for platform, rx in _BIO_PATTERNS.items():
        hits = sorted(set(rx.findall(bio)))
        if hits:
            found[platform] = hits
    return found


def _verification_hints_discord(candidate):
    """Return 3-6 manual verification checks for a Discord candidate."""
    hints = [
        "Decode the snowflake ID to check account creation date - recent accounts (<30 days) are suspicious; very old accounts may not match the target's known Discord history",
        "Check connected accounts (GitHub/Steam/Spotify/etc.) if visible - these are the strongest cross-platform proof",
        "Check mutual servers / mutual friends if a user token is available",
        "Compare profile picture and banner against known target photos",
        "Read the bio and pronouns for identifying info",
        "Confirm the username pattern matches target's known conventions on OTHER platforms (same handle on Twitter/GitHub?)",
    ]
    if not candidate.get("id"):
        hints.append(
            "This candidate only has 'username confirmed to exist' status (no ID resolved). "
            "You need GUILD_ID+bot token OR USE_USER_TOKEN to get the full profile for verification.")
    return hints


class DiscordOsint(BaseModule):
    name = "harvest/discord_osint"
    description = "Discord OSINT - resolve ID/username to profile, decode snowflake, pull public links"
    category = "harvest"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Discord username or 17-20 digit snowflake user ID")
        self.add_option("VARIATIONS", "true", False,
                        "Generate username variations when TARGET is not an ID")
        self.add_option("MAX_VARIATIONS", "15", False,
                        "Max variations to probe")
        self.add_option("CHECK_RELATED", "true", False,
                        "Cross-check candidate IDs against Lanyard for live presence")
        self.add_option("GUILD_ID", "", False,
                        "Guild ID for bot-token member search (needs api_keys.discord_bot + bot in guild)")
        self.add_option("USE_USER_TOKEN", "false", False,
                        "Opt-in: use api_keys.discord_user_token for deep search (ToS violation; your account can be banned)")

    # ------------------------------------------------------------------ helpers
    def _decode_snowflake(self, snowflake):
        try:
            n = int(snowflake)
        except (TypeError, ValueError):
            return None, None
        if n <= 0:
            return None, None
        ms = (n >> 22) + _DISCORD_EPOCH_MS
        created = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
        age = (datetime.datetime.now(datetime.timezone.utc) - created).days
        return created, age

    def _decode_flags(self, public_flags):
        try:
            n = int(public_flags or 0)
        except (TypeError, ValueError):
            return []
        return [label for bit, label in PUBLIC_FLAGS.items() if n & bit]

    def _safe_json(self, resp):
        if resp is None or resp.status_code >= 400:
            return None
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError):
            return None

    # ------------------------------------------------------------------ lookups
    def _mesalytic(self, target):
        """discordlookup.mesalytic.moe (free, no auth). Accepts ID or new username."""
        try:
            resp = http.get(
                f"https://discordlookup.mesalytic.moe/v1/user/{target}", timeout=12)
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                self._warn.append("mesalytic rate-limited (429)")
                return None
            return self._safe_json(resp)
        except Exception as exc:
            self._warn.append(f"mesalytic error: {exc}")
            return None

    def _username_taken(self, username):
        """Discord's unauthenticated username-availability validator.
        Returns True/False/None (None = couldn't tell). No token, no ToS risk."""
        try:
            resp = http.post(
                "https://discord.com/api/v9/unique-username/username-attempt-unauthed",
                json={"username": username},
                headers={"Content-Type": "application/json"},
                timeout=12)
            if resp.status_code == 429:
                self._warn.append("username-attempt-unauthed rate-limited (429)")
                return None
            data = self._safe_json(resp) or {}
            taken = data.get("taken")
            return bool(taken) if taken is not None else None
        except Exception as exc:
            self._warn.append(f"username-attempt error: {exc}")
            return None

    def _japi(self, user_id):
        try:
            resp = http.get(
                f"https://japi.rest/discord/v1/user/{user_id}", timeout=12)
            if resp.status_code in (403, 404):
                return None
            if resp.status_code == 429:
                self._warn.append("japi.rest rate-limited (429)")
                return None
            return self._safe_json(resp)
        except Exception as exc:
            self._warn.append(f"japi.rest error: {exc}")
            return None

    def _lanyard(self, user_id):
        try:
            resp = http.get(
                f"https://api.lanyard.rest/v1/users/{user_id}", timeout=12)
            if resp.status_code == 404:
                return None
            data = self._safe_json(resp)
            if data and data.get("success"):
                return data.get("data")
        except Exception as exc:
            self._warn.append(f"lanyard error: {exc}")
        return None

    def _bot_api(self, user_id, token):
        """Official Discord API; ONLY used to enrich an already-known ID.
        Note: GET-only; never posts to /auth/*."""
        try:
            resp = http.get(
                f"https://discord.com/api/v9/users/{user_id}",
                headers={"Authorization": f"Bot {token}"}, timeout=12)
            if resp.status_code in (401, 403, 404):
                return None
            if resp.status_code == 429:
                self._warn.append("discord bot api rate-limited (429)")
                return None
            return self._safe_json(resp)
        except Exception as exc:
            self._warn.append(f"discord bot api error: {exc}")
            return None

    def _bot_guild_search(self, guild_id, query, token):
        """Search members of a specific guild by username/display-name.
        Requires: bot token + bot is a member of guild_id + GUILD_MEMBERS intent."""
        try:
            resp = http.get(
                f"https://discord.com/api/v10/guilds/{guild_id}/members/search",
                headers={"Authorization": f"Bot {token}"},
                params={"query": query, "limit": 10}, timeout=12)
            if resp.status_code == 401:
                self._warn.append("bot token invalid for guild search")
                return []
            if resp.status_code == 403:
                self._warn.append(f"bot lacks access to guild {guild_id} or missing GUILD_MEMBERS intent")
                return []
            if resp.status_code == 404:
                self._warn.append(f"guild {guild_id} not found by bot")
                return []
            if resp.status_code == 429:
                self._warn.append("guild member search rate-limited (429)")
                return []
            data = self._safe_json(resp) or []
            return data if isinstance(data, list) else []
        except Exception as exc:
            self._warn.append(f"guild member search error: {exc}")
            return []

    def _user_token_lookup(self, user_id, token):
        """GET /users/{id} with a USER token (ToS violation; opt-in only).
        Returns richer data than bot API in some cases."""
        try:
            resp = http.get(
                f"https://discord.com/api/v9/users/{user_id}",
                headers={"Authorization": token}, timeout=12)
            if resp.status_code in (401, 403):
                self._warn.append("user token invalid or revoked")
                return None
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                self._warn.append("user token lookup rate-limited (429)")
                return None
            return self._safe_json(resp)
        except Exception as exc:
            self._warn.append(f"user token lookup error: {exc}")
            return None

    def _user_token_profile(self, user_id, token):
        """GET /users/{id}/profile (user-token endpoint; returns bio, connected accounts, mutuals)."""
        try:
            resp = http.get(
                f"https://discord.com/api/v9/users/{user_id}/profile"
                "?with_mutual_guilds=true&with_mutual_friends_count=true",
                headers={"Authorization": token}, timeout=12)
            if resp.status_code in (401, 403, 404):
                return None
            if resp.status_code == 429:
                self._warn.append("user profile lookup rate-limited (429)")
                return None
            return self._safe_json(resp)
        except Exception as exc:
            self._warn.append(f"user profile lookup error: {exc}")
            return None

    # ----------------------------------------------------------------- shaping
    def _normalize_profile(self, mesa, bot, lanyard):
        """Merge several sources into our canonical profile dict."""
        mesa = mesa or {}
        bot = bot or {}
        lan_user = (lanyard or {}).get("discord_user") if isinstance(lanyard, dict) else {}
        lan_user = lan_user or {}

        raw = mesa.get("raw", {}) or {}
        uid = (mesa.get("id") or raw.get("id") or bot.get("id")
               or lan_user.get("id") or "")

        avatar = mesa.get("avatar") if isinstance(mesa.get("avatar"), dict) else {}
        banner = mesa.get("banner") if isinstance(mesa.get("banner"), dict) else {}

        avatar_url = (avatar.get("link")
                      or (f"https://cdn.discordapp.com/avatars/{uid}/{bot.get('avatar')}.png"
                          if bot.get("avatar") and uid else None))
        banner_url = (banner.get("link")
                      or (f"https://cdn.discordapp.com/banners/{uid}/{bot.get('banner')}.png"
                          if bot.get("banner") and uid else None))

        public_flags = (raw.get("public_flags") if "public_flags" in raw
                        else (bot.get("public_flags")
                              or lan_user.get("public_flags") or 0))

        created, age = (self._decode_snowflake(uid) if uid else (None, None))

        # Mesalytic sometimes nests profile fields under user_profile.
        up = mesa.get("user_profile") or {}

        return {
            "id": str(uid) if uid else None,
            "username": (mesa.get("username") or raw.get("username")
                         or bot.get("username") or lan_user.get("username")),
            "global_name": (mesa.get("global_name") or raw.get("global_name")
                            or bot.get("global_name") or lan_user.get("global_name")),
            "discriminator": (raw.get("discriminator") or bot.get("discriminator")
                              or lan_user.get("discriminator") or "0"),
            "tag": mesa.get("tag"),
            "avatar_url": avatar_url,
            "banner_url": banner_url,
            "accent_color": raw.get("accent_color") or (banner.get("color") if banner else None),
            "created_at": created.isoformat().replace("+00:00", "Z") if created else None,
            "account_age_days": age,
            "public_flags": int(public_flags or 0),
            "flags": self._decode_flags(public_flags),
            "badges": mesa.get("badges") or [],
            "bio": up.get("bio") or mesa.get("bio"),
            "pronouns": up.get("pronouns") or mesa.get("pronouns"),
            "is_bot": bool(raw.get("bot") or bot.get("bot") or lan_user.get("bot")),
        }

    def _extract_connections(self, mesa):
        conns = []
        for key in ("connections", "connected_accounts"):
            raw = (mesa or {}).get(key)
            if isinstance(raw, list):
                for c in raw:
                    if not isinstance(c, dict):
                        continue
                    conns.append({
                        "type": c.get("type") or c.get("provider"),
                        "name": c.get("name") or c.get("display_name"),
                        "id": c.get("id"),
                        "url": c.get("url"),
                        "verified": bool(c.get("verified", False)),
                    })
        return conns

    # --------------------------------------------------------------- resolution
    def _resolve_from_id(self, uid):
        print_status(f"Querying discordlookup for id {uid}...", "info")
        mesa = self._mesalytic(uid)
        print_status(f"Querying japi.rest for id {uid}...", "info")
        japi = self._japi(uid)
        config = Config()
        bot_token = config.get("api_keys.discord_bot")
        bot = None
        if bot_token:
            print_status("Enriching via Discord Bot API...", "info")
            bot = self._bot_api(uid, bot_token)
        # Opt-in user-token enrichment (ToS violation; prints a loud warning).
        user_token = None
        if self.get_option("USE_USER_TOKEN").lower() == "true":
            user_token = config.get("api_keys.discord_user_token")
            if user_token:
                print_status(
                    "USE_USER_TOKEN=true - using user token "
                    "(VIOLATES Discord ToS; your account can be banned)", "warning")
                print_status("Fetching /users/{id}/profile with user token...", "info")
                up = self._user_token_profile(uid, user_token)
                if up:
                    # Merge connected_accounts + bio into mesa-shaped payload.
                    mesa = mesa or {}
                    if up.get("connected_accounts"):
                        mesa.setdefault("connections", []).extend(up["connected_accounts"])
                    user_obj = up.get("user") or {}
                    if user_obj.get("bio") and not mesa.get("bio"):
                        mesa["bio"] = user_obj["bio"]
                    if up.get("user_profile", {}).get("pronouns"):
                        mesa.setdefault("user_profile", {})["pronouns"] = (
                            up["user_profile"]["pronouns"])
                    mesa["mutual_guilds"] = up.get("mutual_guilds", [])
                    mesa["mutual_friends_count"] = up.get("mutual_friends_count", 0)
            else:
                print_status(
                    "USE_USER_TOKEN=true but api_keys.discord_user_token is empty; skipping",
                    "warning")
        lanyard = None
        if self.get_option("CHECK_RELATED").lower() == "true":
            print_status("Checking Lanyard for live presence...", "info")
            lanyard = self._lanyard(uid)
        # If mesa failed but japi returned a nested data payload, fold it in.
        if not mesa and isinstance(japi, dict) and japi.get("data"):
            mesa = japi.get("data")
        return mesa, bot, lanyard

    def _probe_variation(self, candidate, target):
        """Try to resolve a username variation to a real account."""
        data = self._mesalytic(candidate)
        if not isinstance(data, dict):
            return None
        raw = data.get("raw", {}) or {}
        uid = data.get("id") or raw.get("id")
        if not uid:
            return None
        username = data.get("username") or raw.get("username") or candidate
        created, _ = self._decode_snowflake(uid)
        sim = SequenceMatcher(None, target.lower(), username.lower()).ratio()
        cand = {
            "username": username,
            "global_name": data.get("global_name") or raw.get("global_name"),
            "id": str(uid),
            "similarity": round(sim, 3),
            "created_at": created.isoformat().replace("+00:00", "Z") if created else None,
        }
        cand["confidence_tier"] = confidence_tier(sim)
        cand["is_verified_as_target"] = False
        cand["verification_hints"] = _verification_hints_discord(cand)
        return cand

    # ------------------------------------------------------------------- entry
    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip().lstrip("@")
        try:
            max_variations = max(1, int(self.get_option("MAX_VARIATIONS") or 15))
        except (TypeError, ValueError):
            max_variations = 15
        want_variations = (self.get_option("VARIATIONS") or "true").lower() == "true"

        self._warn = []
        is_id = bool(_SNOWFLAKE_RE.match(target))
        input_type = "id" if is_id else "username"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Discord OSINT: {target}  ({input_type})")
        print(f"{'='*58}{Colors.RESET}\n")

        profile = {}
        connections = []
        resolved_id = None
        candidates = []
        tried = []
        lanyard_data = None

        if is_id:
            mesa, bot, lanyard_data = self._resolve_from_id(target)
            if not any((mesa, bot, lanyard_data)):
                print_status("No public record found for that ID", "warning")
            else:
                profile = self._normalize_profile(mesa, bot, lanyard_data)
                connections = self._extract_connections(mesa)
                resolved_id = profile.get("id") or target

        else:
            # Build the full candidate list first (self + variations).
            all_names = []
            if _USERNAME_RE.match(target.lower()):
                all_names.append(target.lower())
            if want_variations:
                for v in _variations(target, max_variations):
                    if v not in all_names:
                        all_names.append(v)

            # STEP 1: Discord's own unauthenticated availability check.
            # Confirms whether each candidate exists without any token.
            taken_names = []
            print_status(
                f"Checking existence of {len(all_names)} candidate(s) via "
                "Discord's unauthenticated validator...", "info")
            for name in all_names:
                tried.append(name)
                is_taken = self._username_taken(name)
                if is_taken is True:
                    taken_names.append(name)
                    print_status(f"[taken] {name}", "success")
                elif is_taken is False:
                    pass  # free - skip
                else:
                    # Rate-limited or error; still try the lookup services below
                    taken_names.append(name)

            # STEP 2: For each confirmed-taken name, resolve to ID+profile via mesalytic/japi.
            for name in taken_names:
                hit = self._probe_variation(name, target)
                if hit:
                    hit["source"] = "mesalytic"
                    if hit["similarity"] >= 0.99:
                        hit["note"] = (
                            "exact-match username - most likely the intended handle, "
                            "but confirm the account OWNER before trusting.")
                    candidates.append(hit)
                    tier = hit.get("confidence_tier", "?")
                    print_status(
                        f"[CANDIDATE/{tier}] {hit['username']} (id {hit['id']}, "
                        f"sim={hit['similarity']}) - NOT CONFIRMED",
                        "warning" if tier in ("medium", "low", "very-low") else "info")
                else:
                    # Known-exists but no ID resolution path -> add as "unresolved" candidate
                    sim = SequenceMatcher(None, target.lower(), name.lower()).ratio()
                    taken_cand = {
                        "username": name,
                        "id": None,
                        "similarity": round(sim, 3),
                        "source": "username-taken",
                        "note": "username confirmed to exist; ID requires shared guild / user token",
                    }
                    taken_cand["confidence_tier"] = confidence_tier(sim)
                    taken_cand["is_verified_as_target"] = False
                    taken_cand["verification_hints"] = _verification_hints_discord(taken_cand)
                    candidates.append(taken_cand)

            # Bot-token guild member search (only when both GUILD_ID + bot token set).
            config = Config()
            guild_id = (self.get_option("GUILD_ID") or "").strip()
            bot_token = config.get("api_keys.discord_bot")
            if guild_id and bot_token:
                print_status(
                    f"Searching guild {guild_id} members via bot token...", "info")
                members = self._bot_guild_search(guild_id, target, bot_token)
                for m in members:
                    user_obj = m.get("user") or {}
                    uid_m = user_obj.get("id")
                    uname_m = user_obj.get("username") or user_obj.get("global_name")
                    if not uid_m:
                        continue
                    sim_m = SequenceMatcher(
                        None, target.lower(), (uname_m or "").lower()).ratio()
                    cand_id_set = {c["id"] for c in candidates}
                    if uid_m in cand_id_set:
                        continue
                    created_m, _ = self._decode_snowflake(uid_m)
                    guild_cand = {
                        "username": uname_m,
                        "global_name": user_obj.get("global_name"),
                        "id": str(uid_m),
                        "similarity": round(sim_m, 3),
                        "source": "guild_search",
                        "nick": m.get("nick"),
                        "created_at": (created_m.isoformat().replace("+00:00", "Z")
                                       if created_m else None),
                    }
                    guild_cand["confidence_tier"] = confidence_tier(sim_m)
                    guild_cand["is_verified_as_target"] = False
                    guild_cand["verification_hints"] = _verification_hints_discord(guild_cand)
                    if sim_m >= 0.99:
                        guild_cand["note"] = (
                            "exact-match username - most likely the intended handle, "
                            "but confirm the account OWNER before trusting.")
                    candidates.append(guild_cand)
                    tier_m = guild_cand["confidence_tier"]
                    print_status(
                        f"[CANDIDATE/{tier_m}] {uname_m} (id {uid_m}, "
                        f"sim={sim_m:.2f}) - NOT CONFIRMED",
                        "warning" if tier_m in ("medium", "low", "very-low") else "info")

            # Promote the strongest candidate to a full profile if confident AND we have an ID.
            candidates.sort(key=lambda c: c["similarity"], reverse=True)
            top_with_id = next((c for c in candidates
                                if c["similarity"] >= 0.85 and c.get("id")), None)
            if top_with_id:
                resolved_id = top_with_id["id"]
                print_status(
                    f"Resolving top candidate {resolved_id} for full profile...",
                    "info")
                mesa, bot, lanyard_data = self._resolve_from_id(resolved_id)
                profile = self._normalize_profile(mesa, bot, lanyard_data)
                connections = self._extract_connections(mesa)
            elif candidates and not any(c.get("id") for c in candidates):
                print_status(
                    f"{len([c for c in candidates if c.get('source')=='username-taken'])} "
                    "username(s) confirmed existing but ID resolution needs "
                    "GUILD_ID+bot or USE_USER_TOKEN. See the candidates list.", "info")
            elif not candidates:
                print_status(
                    "No candidate matched. Discord no longer exposes username->ID "
                    "publicly. To do real username search you need ONE of:", "warning")
                print_status(
                    "  (1) set GUILD_ID + apikeys set discord_bot <TOKEN> "
                    "(bot must be in that guild with GUILD_MEMBERS intent)", "info")
                print_status(
                    "  (2) apikeys set discord_user_token <TOKEN> + set USE_USER_TOKEN true "
                    "(ToS violation; ban risk)", "info")
                print_status(
                    "  (3) feed the 17-20 digit snowflake ID directly as TARGET", "info")

        bio_pivots = _extract_handles_from_bio(profile.get("bio") or "")

        self.results = {
            "target": target,
            "input_type": input_type,
            "resolved_id": resolved_id,
            "profile": profile,
            "connections": connections,
            "bio_pivots": bio_pivots,
            "lanyard": ({
                "active": True,
                "status": (lanyard_data or {}).get("discord_status"),
                "activities": [a.get("name") for a in (lanyard_data or {}).get("activities", [])
                               if isinstance(a, dict) and a.get("name")],
            } if lanyard_data else {"active": False}),
            "variations_tried": tried,
            "candidates": candidates,
            "warnings": self._warn,
        }
        self.results["disclaimer"] = build_disclaimer("Discord", len(candidates))

        self._print_summary(profile, connections, candidates, bio_pivots)
        return True

    # ----------------------------------------------------------------- summary
    def _print_summary(self, profile, connections, candidates, bio_pivots):
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary")
        print(f"{'-'*58}{Colors.RESET}")
        if profile.get("id"):
            print(f"  ID:          {profile['id']}")
            name_line = profile.get("username") or "-"
            if profile.get("global_name"):
                name_line += f"  (Global: {profile['global_name']})"
            print(f"  Username:    {name_line}")
            if profile.get("created_at"):
                print(f"  Created:     {profile['created_at']}  "
                      f"({profile.get('account_age_days')} days ago)")
            if profile.get("flags"):
                print(f"  Badges:      {', '.join(profile['flags'])}")
            if profile.get("avatar_url"):
                print(f"  Avatar:      {profile['avatar_url']}")
            if profile.get("banner_url"):
                print(f"  Banner:      {profile['banner_url']}")
            if profile.get("bio"):
                print(f"  Bio:         {profile['bio'][:120]}")
            if profile.get("pronouns"):
                print(f"  Pronouns:    {profile['pronouns']}")
            if profile.get("is_bot"):
                print(f"  {Colors.YELLOW}Account type: BOT{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}No profile resolved{Colors.RESET}")

        if connections:
            print(f"\n  {Colors.BOLD}Connections ({len(connections)}){Colors.RESET}")
            for c in connections:
                mark = f"{Colors.GREEN}+{Colors.RESET}" if c.get("verified") else "-"
                print(f"    {mark} {str(c.get('type') or '?'):<10} "
                      f"{c.get('name') or ''}  {c.get('url') or ''}")

        if bio_pivots:
            print(f"\n  {Colors.BOLD}Bio pivots{Colors.RESET}")
            for plat, handles in bio_pivots.items():
                print(f"    {plat:<10} {', '.join(handles)}")

        if candidates:
            print(f"\n  {Colors.BOLD}Username candidates{Colors.RESET}")
            for c in candidates[:10]:
                print(f"    sim={c['similarity']:.2f}  "
                      f"{str(c['username']):<24} id={c['id']}")

        if candidates:
            print_uncertainty_box("Discord")

        if self._warn:
            print(f"\n  {Colors.DIM}{len(self._warn)} warning(s): "
                  f"{'; '.join(self._warn[:3])}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")
