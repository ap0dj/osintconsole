import re
import hashlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# Soft import: parallel agent is building username_variations. Degrade cleanly
# if it is missing at runtime so the base scrape keeps working.
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


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{7,}\d")
HASHTAG_RE = re.compile(r"#\w+")
MENTION_RE = re.compile(r"@\w{4,}")


# ---------------------------------------------------------------------------
# Real-account vs. generic-placeholder detectors
#
# t.me/{username} returns HTTP 200 with a page titled
# "Telegram: Contact @{username}" for EVERY username — real, nonexistent, or
# private. So HTTP 200 alone is NOT a hit. We decide "this is a real account"
# by scanning the page for multiple positive signals (custom title, non-default
# avatar, description, member count, tgme_page_action button, extra text).
# ---------------------------------------------------------------------------

_DEFAULT_TG_IMAGE_PATHS = (
    "telegram.org/img/t_logo",
    "telegram.org/img/tg_logo",
    "cdn-telegram.org/file/placeholder",
)


def _is_default_telegram_image(url):
    if not url:
        return True
    low = url.lower()
    return any(p in low for p in _DEFAULT_TG_IMAGE_PATHS)


def _is_generic_telegram_title(title, username):
    """Telegram defaults to 'Telegram: Contact @{username}' for every URL.
    A REAL profile has a different title (user's name, channel title, bot name)."""
    if not title:
        return True
    normalized = title.strip().lower()
    uname = (username or "").strip().lstrip("@").lower()
    generic_patterns = (
        f"telegram: contact @{uname}",
        f"telegram: contact {uname}",
        f"telegram - contact @{uname}",
        f"telegram contact @{uname}",
    )
    return normalized in generic_patterns


def _real_profile_signals(html_text, username):
    """Count how many 'this is a real account' signals we see in the page.
    Return (signals_dict, confidence 0.0 - 1.0)."""
    signals = {
        "has_custom_title": False,
        "has_description": False,
        "has_custom_avatar": False,
        "has_member_count": False,
        "has_tgme_page_extra": False,
        "has_tgme_page_action": False,
        "has_bio_text": False,
    }
    if not html_text:
        return signals, 0.0

    m = re.search(r'<meta property="og:title" content="([^"]*)"', html_text)
    title = m.group(1).strip() if m else ""
    if title and not _is_generic_telegram_title(title, username):
        signals["has_custom_title"] = True

    m = re.search(r'<meta property="og:description" content="([^"]*)"', html_text)
    description = m.group(1).strip() if m else ""
    if description:
        signals["has_description"] = True

    m = re.search(r'<meta property="og:image" content="([^"]*)"', html_text)
    photo = m.group(1).strip() if m else ""
    if photo and not _is_default_telegram_image(photo):
        signals["has_custom_avatar"] = True

    if re.search(r'[\d][\d\s,]*\s*(members|subscribers)', html_text):
        signals["has_member_count"] = True

    if "tgme_page_extra" in html_text:
        signals["has_tgme_page_extra"] = True

    if "tgme_page_action" in html_text:
        signals["has_tgme_page_action"] = True

    if "tgme_page_description" in html_text:
        signals["has_bio_text"] = True

    count = sum(1 for v in signals.values() if v)
    # 0 signals -> 0.0, >=5 signals -> ~1.0
    confidence = round(min(1.0, count / 5.0), 3)
    return signals, confidence


def _detect_account_type(html_text):
    """Classify the preview as 'user' | 'channel' | 'group' | 'bot' | 'unknown'."""
    if not html_text:
        return "unknown"
    low = html_text.lower()

    # Bot: tgme_page_additional often holds "@BotFather" or a /bot_ hint
    if "tgme_page_additional" in low:
        extra = re.search(r'tgme_page_additional[^>]*>([^<]+)<', low)
        if extra:
            etext = extra.group(1)
            if "@botfather" in etext or re.search(r'/bot[_a-z0-9]', etext):
                return "bot"

    if "view channel" in low or re.search(r'[\d][\d\s,]*\s*subscribers', low):
        return "channel"
    if "add to group" in low or re.search(r'[\d][\d\s,]*\s*members', low):
        return "group"
    if "send message" in low:
        return "user"
    return "unknown"


def _verification_hints_telegram(candidate):
    """Return 3-6 manual verification checks for a Telegram candidate.
    These are things a human should look at to confirm or reject a candidate."""
    hints = [
        "Check the account's join/creation date (very old or very new both suggest it may not be the target)",
        "Compare the profile photo against known photos of the target (use reverse image search)",
        "Read the bio and recent posts for identifying info (location, language, interests)",
        "Check mutual contacts / shared channels with people linked to the target",
        "Verify the username pattern matches the target's known conventions (does the real target use this platform?)",
    ]
    if candidate.get("members"):
        hints.append(
            f"The account has {candidate['members']} members/subscribers — a group/channel, not a personal account. "
            "The owner is likely NOT the person named here.")
    return hints


class TelegramOsint(BaseModule):
    name = "harvest/telegram_osint"
    description = "Telegram deep OSINT - preview + Bot API + username pivot + bio handles"
    category = "harvest"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Telegram username/channel (without @)")
        self.add_option("FETCH_POSTS", "true", False, "Scrape recent public posts")
        self.add_option("VARIATIONS", "true", False, "Pivot via username variations")
        self.add_option("MAX_VARIATIONS", "20", False, "Max variations to probe")
        self.add_option("FETCH_PHOTO_HASH", "true", False, "Download og:image and hash it")

    # ------------------------------------------------------------------ helpers

    def _clean(self, username):
        username = username.strip().lstrip("@")
        username = re.sub(r"https?://t\.me/", "", username)
        username = re.sub(r"https?://telegram\.me/", "", username)
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

    def _parse_preview_html(self, html):
        """Extract og:* + members/subscribers + extra from a t.me page body."""
        info = {}
        m = re.search(r'<meta property="og:title" content="([^"]*)"', html)
        if m:
            info["title"] = m.group(1).strip()
        m = re.search(r'<meta property="og:description" content="([^"]*)"', html)
        if m:
            info["description"] = m.group(1).strip()
        m = re.search(r'<meta property="og:image" content="([^"]*)"', html)
        if m:
            info["photo"] = m.group(1).strip()

        members = re.search(r'([\d\s,]+)\s*(members|subscribers)', html)
        if members:
            info["members"] = members.group(1).strip()
            info["members_label"] = members.group(2)

        if "tgme_page_extra" in html:
            extra = re.search(r'tgme_page_extra">([^<]+)<', html)
            if extra:
                info["extra"] = extra.group(1).strip()

        low = html.lower()
        info["type"] = ("channel" if "subscribers" in low
                        else "group" if "members" in low
                        else "user/unknown")
        return info

    def _scrape_preview(self, username):
        """Public channel/user preview at t.me/{username}.

        Telegram serves a generic placeholder page for ANY username (real,
        nonexistent, or private), so HTTP 200 is NOT a hit on its own. We
        inspect the page for multiple real-account signals and set:
            exists (bool)         - True only when the page looks like a real account
            confidence (float)    - 0.0 - 1.0 score derived from the signals
            signals (dict)        - which individual signals fired
            signals_count (int)   - count of fired signals
            has_custom_avatar (bool)
            account_type (str)    - 'user' | 'channel' | 'group' | 'bot' | 'unknown'
            reason (str)          - set when exists=False
        """
        try:
            resp = http.get(f"https://t.me/{username}", timeout=12)
        except Exception as e:
            print_status(f"Preview scrape error: {e}", "warning")
            return {
                "exists": False,
                "confidence": 0.0,
                "signals": {},
                "signals_count": 0,
                "has_custom_avatar": False,
                "account_type": "unknown",
                "reason": f"request error: {e}",
            }

        if resp.status_code != 200:
            return {
                "exists": False,
                "confidence": 0.0,
                "signals": {},
                "signals_count": 0,
                "has_custom_avatar": False,
                "account_type": "unknown",
                "reason": f"http {resp.status_code}",
            }

        html = resp.text or ""
        info = self._parse_preview_html(html)
        signals, confidence = _real_profile_signals(html, username)
        signals_count = sum(1 for v in signals.values() if v)
        account_type = _detect_account_type(html)

        # Real-account rule:
        #   - og:title must NOT be the generic 'Telegram: Contact @{username}'
        #     OR there's a description, OR there's a tgme_page_action button.
        #   - og:image must NOT be the default telegram.org/img/t_logo* placeholder
        #     OR the page shows members/subscribers.
        title_ok = (signals["has_custom_title"]
                    or signals["has_description"]
                    or signals["has_tgme_page_action"])
        photo_ok = signals["has_custom_avatar"] or signals["has_member_count"]
        exists = bool(title_ok and photo_ok)

        info["exists"] = exists
        info["confidence"] = confidence
        info["signals"] = signals
        info["signals_count"] = signals_count
        info["has_custom_avatar"] = signals["has_custom_avatar"]
        info["account_type"] = account_type
        if not exists:
            info["reason"] = "generic placeholder page"
        return info

    def _scrape_posts(self, username):
        posts = []
        try:
            resp = http.get(f"https://t.me/s/{username}", timeout=12)
            if resp.status_code != 200:
                return posts
            raw_posts = re.findall(
                r'tgme_widget_message_text[^>]*>(.*?)</div>', resp.text, re.DOTALL)
            for raw in raw_posts[-15:]:
                text = re.sub(r"<[^>]+>", "", raw)
                text = re.sub(r"\s+", " ", text).strip()
                if text:
                    posts.append(text[:280])
        except Exception:
            pass
        return posts

    def _bot_api(self, username, token):
        try:
            resp = http.get(f"https://api.telegram.org/bot{token}/getChat",
                            params={"chat_id": f"@{username}"})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    chat = data["result"]
                    return {
                        "id": chat.get("id"),
                        "type": chat.get("type"),
                        "title": chat.get("title"),
                        "username": chat.get("username"),
                        "bio": chat.get("bio") or chat.get("description"),
                    }
        except Exception:
            pass
        return {}

    # ------------------------------------------------------------------ pivots

    def _probe_variation(self, candidate, base):
        """Probe t.me/{candidate}. Only report if the page passes the
        real-account check (exists=True); generic placeholders are dropped."""
        try:
            info = self._scrape_preview(candidate)
            if not info or not info.get("exists"):
                return None
            sim = round(SequenceMatcher(None, base.lower(),
                                        candidate.lower()).ratio(), 3)
            return {
                "username": candidate,
                "url": f"https://t.me/{candidate}",
                "title": info.get("title"),
                "members": info.get("members"),
                "type": info.get("type"),
                "account_type": info.get("account_type"),
                "photo": info.get("photo"),
                "description": info.get("description", "")[:200],
                "similarity": sim,
                "confidence": info.get("confidence", 0.0),
                "signals": info.get("signals", {}),
                "signals_count": info.get("signals_count", 0),
                "has_custom_avatar": info.get("has_custom_avatar", False),
                "exists": True,
            }
        except Exception:
            return None

    def _search_variations(self, username, max_variations):
        variations = generate_variations(username, max_variations)
        variations = platform_filter(variations, "telegram")
        # Telegram-specific: lowercase alnum + underscore, >= 5 chars.
        cleaned, seen = [], set()
        for v in variations:
            v = re.sub(r"[^a-z0-9_]", "", (v or "").lower())
            if len(v) >= 5 and v != username.lower() and v not in seen:
                seen.add(v)
                cleaned.append(v)
            if len(cleaned) >= max_variations:
                break

        candidates = []
        if not cleaned:
            return cleaned, candidates

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(self._probe_variation, c, username): c
                       for c in cleaned}
            for fut in as_completed(futures):
                hit = fut.result()
                if hit:
                    candidates.append(hit)
        for candidate_dict in candidates:
            similarity = candidate_dict["similarity"]
            candidate_dict["confidence_tier"] = confidence_tier(similarity)
            candidate_dict["is_verified_as_target"] = False  # never auto-confirmed
            candidate_dict["verification_hints"] = _verification_hints_telegram(candidate_dict)
        candidates.sort(key=lambda x: x["similarity"], reverse=True)
        return cleaned, candidates

    def _photo_md5(self, url):
        try:
            resp = http.get(url, timeout=10)
            if resp.status_code == 200 and resp.content:
                return hashlib.md5(resp.content).hexdigest()
        except Exception:
            pass
        return None

    def _bio_pivots(self, text):
        handles = {}
        if _VARIATIONS_OK:
            try:
                handles = extract_handles_from_bio(text) or {}
            except Exception:
                handles = {}
        emails = sorted(set(EMAIL_RE.findall(text)))
        phones = sorted({re.sub(r"\s+", " ", p).strip()
                         for p in PHONE_RE.findall(text)})
        return handles, {"emails": emails, "phones": phones}

    def _posts_summary(self, posts):
        if not posts:
            return [], []
        joined = "\n".join(posts)
        hashtags = [t.lower() for t in HASHTAG_RE.findall(joined)]
        mentions = [m.lower() for m in MENTION_RE.findall(joined)]
        top_h = [t for t, _ in Counter(hashtags).most_common(10)]
        top_m = [m for m, _ in Counter(mentions).most_common(10)]
        return top_h, top_m

    # ------------------------------------------------------------------ run

    def run(self):
        if not self.validate():
            return False

        username = self._clean(self.get_option("TARGET"))
        fetch_posts = self._bool_opt("FETCH_POSTS", True)
        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 20))
        fetch_hash = self._bool_opt("FETCH_PHOTO_HASH", True)
        config = Config()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Telegram OSINT: @{username}")
        print(f"{'='*58}{Colors.RESET}\n")

        # 1) Direct preview
        print_status("Scraping public preview...", "info")
        preview = self._scrape_preview(username)
        if not preview:
            print_status("No public preview (private, nonexistent, or user)", "warning")
        elif preview.get("exists"):
            if preview.get("title"):
                print_status(f"Title: {preview['title']}", "success")
                print_status(
                    f" [CANDIDATE/exact-match] @{username} - exact username match "
                    f"(confidence {preview.get('confidence', 0.0):.2f}, "
                    f"{preview.get('signals_count', 0)} real-account signals, "
                    f"type={preview.get('account_type', 'unknown')}) - "
                    f"most likely the intended handle, still verify the account OWNER manually.",
                    "info")
            if preview.get("members"):
                print_status(
                    f"{preview.get('members_label','members').title()}: {preview['members']}",
                    "success")
            if preview.get("description"):
                print_status(f"Description: {preview['description'][:120]}", "info")
            if preview.get("photo"):
                print_status(f"Photo: {preview['photo']}", "info")
        else:
            print_status(
                f"t.me/{username} returned a page, but it's the generic placeholder - "
                f"this username likely does NOT exist on Telegram, OR the account is "
                f"deeply private and exposes no public info.",
                "warning")

        # 2) Posts
        posts = []
        if fetch_posts:
            print_status("Fetching recent public posts...", "info")
            posts = self._scrape_posts(username)
            print_status(f"Collected {len(posts)} post(s)",
                         "success" if posts else "warning")
        top_hashtags, top_mentions = self._posts_summary(posts)

        # 3) Bot API
        bot = {}
        token = config.get("api_keys.telegram_bot")
        if token:
            print_status("Querying Bot API...", "info")
            bot = self._bot_api(username, token)
            if bot:
                print_status(f"Bot API: id={bot.get('id')} type={bot.get('type')}",
                             "success")

        # 4) Birth-year hint
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

        # 5) Variations pivot
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(f"Probing up to {max_variations} username variations...", "info")
            variations_tried, candidates = self._search_variations(
                username, max_variations)
            print_status(
                f"Tried {len(variations_tried)} variations, {len(candidates)} candidate(s)",
                "success" if candidates else "info")
            for c in candidates[:10]:
                tier = c.get("confidence_tier", "unknown")
                members_str = c.get("members") or "none"
                status_level = "info" if tier in ("exact-match", "high") else "warning"
                print_status(
                    f" [CANDIDATE/{tier}] @{c['username']} - {(c.get('title') or '')[:60]} "
                    f"(members: {members_str}, sim={c['similarity']}, "
                    f"conf={c.get('confidence', 0.0):.2f}, "
                    f"type={c.get('account_type', 'unknown')})  NOT CONFIRMED",
                    status_level)
        elif do_variations and not _VARIATIONS_OK:
            print_status("username_variations module unavailable - skipping pivot",
                         "warning")

        # 6) Bio pivot + contacts (only from REAL direct hit + bot API bio + candidate descriptions)
        bio_blob_parts = []
        if preview.get("exists"):
            bio_blob_parts.extend([
                preview.get("description", ""),
                preview.get("title", ""),
                preview.get("extra", ""),
            ])
        bio_blob_parts.append(bot.get("bio") or "")
        for c in candidates:
            bio_blob_parts.append(c.get("description", ""))
        bio_blob = "\n".join(p for p in bio_blob_parts if p)
        bio_pivots, bio_contacts = self._bio_pivots(bio_blob)
        if bio_pivots:
            counts = ", ".join(f"{k}:{len(v)}" for k, v in bio_pivots.items() if v)
            if counts:
                print_status(f"Bio pivots found - {counts}", "success")
        if bio_contacts["emails"] or bio_contacts["phones"]:
            print_status(
                f"Bio contacts - emails:{len(bio_contacts['emails'])} "
                f"phones:{len(bio_contacts['phones'])}", "success")

        # 7) Photo hash (only for custom avatars; hashing the Telegram logo
        #    placeholder for every miss is pointless noise)
        photo_md5 = None
        if (fetch_hash and preview.get("photo")
                and preview.get("has_custom_avatar")):
            print_status("Hashing profile photo...", "info")
            photo_md5 = self._photo_md5(preview["photo"])
            if photo_md5:
                print_status(f"photo_md5: {photo_md5}", "success")

        # ------------------------------------------------------------- results
        self.results = {
            "username": username,
            "url": f"https://t.me/{username}",
            "preview": preview,
            "recent_posts": posts,
            "bot_api": bot,
            "variations_tried": variations_tried,
            "candidates": candidates,
            "birth_year_hint": birth_hint,
            "bio_pivots": bio_pivots,
            "bio_contacts": bio_contacts,
            "top_hashtags": top_hashtags,
            "top_mentions": top_mentions,
            "photo_md5": photo_md5,
        }
        self.results["disclaimer"] = build_disclaimer("Telegram", len(candidates))

        # ------------------------------------------------------------- summary
        preview_exists = bool(preview.get("exists"))
        direct_hit = preview_exists or bool(bot)

        # t.me answers EVERY username with a 200 placeholder, so "generic
        # placeholder page" is a genuine negative. A request error or a non-200
        # (429/403/5xx, but not 404/410) means the fetch FAILED and must not be
        # read as "username does not exist".
        reason = preview.get("reason") or ""
        preview_failed = (not preview_exists) and (
            reason.startswith("request error")
            or (reason.startswith("http ")
                and reason not in ("http 404", "http 410")))
        direct_fetch_failed = (not direct_hit) and preview_failed
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status("Direct lookup INCONCLUSIVE - t.me blocked/unreachable; "
                         "this is NOT evidence the username is absent", "warning")

        if preview_exists:
            direct_hit_line = (f"yes (confidence "
                               f"{preview.get('confidence', 0.0):.2f}, "
                               f"type={preview.get('account_type', 'unknown')})")
        elif bot:
            direct_hit_line = "yes (via Bot API)"
        else:
            direct_hit_line = "no (generic placeholder)"
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: @{username}")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  Link:         https://t.me/{username}")
        print(f"  Direct hit:   {direct_hit_line}")
        if preview.get("members"):
            print(f"  {preview.get('members_label','members').title():<13} "
                  f"{preview['members']}")
        print(f"  Posts:        {len(posts)} collected")
        if top_hashtags:
            print(f"  Top hashtags: {', '.join(top_hashtags[:5])}")
        if top_mentions:
            print(f"  Top mentions: {', '.join(top_mentions[:5])}")
        print(f"  Candidates:   {len(candidates)} (from {len(variations_tried)} tried)")
        if bio_pivots:
            parts = [f"{k}:{len(v)}" for k, v in bio_pivots.items() if v]
            if parts:
                print(f"  Bio pivots:   {', '.join(parts)}")
        if bio_contacts["emails"] or bio_contacts["phones"]:
            print(f"  Contacts:     emails={len(bio_contacts['emails'])} "
                  f"phones={len(bio_contacts['phones'])}")
        if birth_hint:
            print(f"  Birth year:   {birth_hint.get('year')} "
                  f"(conf={birth_hint.get('confidence')})")
        if photo_md5:
            print(f"  Photo MD5:    {photo_md5}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        if candidates:
            print_uncertainty_box("Telegram")

        return True
