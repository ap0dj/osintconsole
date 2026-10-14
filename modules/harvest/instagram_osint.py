"""Instagram OSINT - public-endpoint profile lookup, bio pivot, username variations.

Hits public Instagram endpoints with no cookies / no login:
  * https://www.instagram.com/{username}/                      -> HTML + og:*
  * https://www.instagram.com/{username}/?__a=1&__d=dis        -> JSON (sometimes)
  * https://i.instagram.com/api/v1/users/web_profile_info/     -> web_profile_info JSON

Instagram actively blocks scraping, so 429 and empty payloads are common. We
collect whatever we can, record warnings, and never fake data.
"""

import re
import json
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

# Soft import - username_variations is a shared helper and may not be present.
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

    def extract_handles_from_bio(_t):
        return {}


# Public web-app id Instagram embeds in its own HTML; required by web_profile_info.
IG_APP_ID = "936619743392459"
LOGIN_PATH = "/accounts/login"

_SHARED_DATA_RE = re.compile(
    r'<script[^>]*>\s*window\._sharedData\s*=\s*(\{.*?\});\s*</script>', re.DOTALL)
_ADDITIONAL_RE = re.compile(
    r'window\.__additionalDataLoaded\(\s*[\'"][^\'"]+[\'"]\s*,\s*(\{.*?\})\s*\)\s*;',
    re.DOTALL)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")


def _og(html, prop):
    m = re.search(
        rf'<meta[^>]+property="{re.escape(prop)}"[^>]+content="([^"]*)"', html)
    if not m:
        m = re.search(
            rf'<meta[^>]+content="([^"]*)"[^>]+property="{re.escape(prop)}"', html)
    return m.group(1).strip() if m else None


def _verification_hints_instagram(candidate):
    hints = [
        "Check follower count and following patterns - fake/scrape accounts often have odd ratios",
        "Compare profile picture against known target photos (reverse image search works for this)",
        "Read the bio and external_url for identifying info (location, business, cross-platform handles)",
        "Check if the account is business/creator - type matches target's known public role",
        "Look at tagged photos / recent posts (if public) for context clues",
        "Instagram often reserves usernames of banned users - a 'taken' username may lead to an inactive stub",
    ]
    if candidate.get("is_private"):
        hints.insert(0, "This account is PRIVATE - you can only see the display name and profile pic. Verify from those plus bio.")
    if candidate.get("is_verified"):
        hints.insert(0, "This account has a verified badge - if the target isn't publicly notable, this is probably NOT them.")
    return hints


# ------------------------------------------------------------- real-account detectors
def _is_instagram_login_redirect(resp):
    """Instagram often 302s to /accounts/login/ for anonymous requests."""
    if resp is None:
        return True
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = (resp.headers.get("location")
               or resp.headers.get("Location") or "").lower()
        return "/accounts/login" in loc or "/accounts/emailsignup" in loc
    return False


def _is_generic_instagram_page(html, username=None):
    """A nonexistent IG profile serves a 'Sorry, this page isn't available' or similar.
    A real existing profile has structured JSON with user data."""
    if not html:
        return True
    low = html.lower()
    not_available_markers = (
        "sorry, this page isn't available",
        "the link you followed may be broken",
        "page not found",
        "this page isn't available",
    )
    return any(m in low for m in not_available_markers)


def _extract_structured_json(html):
    """Pull the JSON blob Instagram embeds. Returns None if not found."""
    if not html:
        return None
    m = re.search(r'window\._sharedData\s*=\s*({.+?});</script>', html, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    m = re.search(r'<script type="application/json"[^>]*>({[^<]+})</script>', html)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return None


def _real_profile_signals(html, structured_data, username, profile=None):
    """Count 'real account' signals. Returns dict of booleans."""
    signals = {
        "has_user_id": False,          # obfuscated or numeric ID
        "has_full_name": False,         # not just the username
        "has_bio_text": False,          # non-empty biography
        "has_external_url": False,
        "has_follower_count": False,    # from embedded JSON or OG description
        "has_profile_pic_hd": False,    # not the default IG avatar
        "has_posts_count": False,
        "is_verified_or_business": False,
    }

    # 1) Normalized profile dict (richest when API endpoints responded)
    if profile:
        if profile.get("id") or profile.get("obfuscated_id"):
            signals["has_user_id"] = True
        fn = (profile.get("full_name") or "").strip()
        if fn and fn.lower() != (username or "").lower():
            signals["has_full_name"] = True
        if (profile.get("biography") or "").strip():
            signals["has_bio_text"] = True
        if (profile.get("external_url") or "").strip():
            signals["has_external_url"] = True
        if profile.get("follower_count") is not None:
            signals["has_follower_count"] = True
        pic_hd = profile.get("profile_pic_url_hd") or ""
        if pic_hd and "default_profile" not in pic_hd.lower():
            signals["has_profile_pic_hd"] = True
        if profile.get("posts_count") is not None:
            signals["has_posts_count"] = True
        if profile.get("is_verified") or profile.get("is_business"):
            signals["is_verified_or_business"] = True

    # 2) HTML og:* fallbacks (works when API endpoints are login-walled but HTML loads)
    if html:
        og_desc = _og(html, "og:description") or ""
        og_title = _og(html, "og:title") or ""
        og_image = _og(html, "og:image") or ""
        if not signals["has_follower_count"]:
            if re.search(r"[\d,.]+[KMB]?\s+Followers", og_desc, re.IGNORECASE):
                signals["has_follower_count"] = True
        if not signals["has_posts_count"]:
            if re.search(r"[\d,.]+[KMB]?\s+Posts", og_desc, re.IGNORECASE):
                signals["has_posts_count"] = True
        if not signals["has_bio_text"]:
            tail = re.sub(
                r"[\d,.KMB]+\s+(followers|following|posts)[,\s]*",
                "", og_desc, flags=re.IGNORECASE)
            tail = re.sub(r"see instagram photos and videos.*", "",
                          tail, flags=re.IGNORECASE)
            tail = tail.strip(" -:–—")
            if tail and len(tail) >= 10 and not tail.lower().startswith("instagram"):
                signals["has_bio_text"] = True
        if not signals["has_full_name"]:
            stripped = og_title.lower()
            stripped = re.sub(r'@?' + re.escape((username or "").lower()),
                              '', stripped)
            stripped = re.sub(r'instagram photos and videos', '', stripped)
            stripped = re.sub(r'[^a-z0-9 ]', ' ', stripped).strip()
            if stripped and len(stripped) >= 3:
                signals["has_full_name"] = True
        if not signals["has_profile_pic_hd"]:
            if og_image and "default_profile" not in og_image.lower() \
                    and "rsrc.php" not in og_image.lower():
                signals["has_profile_pic_hd"] = True

    # 3) Structured JSON fallbacks
    if structured_data:
        try:
            raw = json.dumps(structured_data)
            if not signals["has_user_id"] and re.search(r'"id"\s*:\s*"?\d{4,}',
                                                       raw):
                signals["has_user_id"] = True
            if not signals["is_verified_or_business"]:
                if '"is_verified":true' in raw \
                        or '"is_business_account":true' in raw:
                    signals["is_verified_or_business"] = True
            if not signals["has_external_url"]:
                if re.search(r'"external_url"\s*:\s*"https?://', raw):
                    signals["has_external_url"] = True
        except Exception:
            pass

    return signals


def _score_signals(signals):
    """Return (count, confidence_0_to_1) from a signals dict."""
    count = sum(1 for v in signals.values() if v)
    total = max(1, len(signals))
    confidence = round(min(1.0, count / float(total)), 2)
    return count, confidence


class InstagramOsint(BaseModule):
    name = "harvest/instagram_osint"
    description = "Instagram OSINT - public profile scrape + bio pivot + username variations"
    category = "harvest"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Instagram username (with or without @)")
        self.add_option("VARIATIONS", "true", False, "Probe username variations")
        self.add_option("MAX_VARIATIONS", "15", False, "Max variations to probe")
        self.add_option("FETCH_POSTS", "true", False, "Extract recent public posts")

    # ------------------------------------------------------------------ helpers
    def _clean(self, username):
        username = (username or "").strip().lstrip("@")
        username = re.sub(r"https?://(www\.)?instagram\.com/", "", username)
        return username.strip("/").split("?")[0]

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

    def _safe_json(self, resp):
        if resp is None or resp.status_code >= 400:
            return None
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError):
            return None

    # ----------------------------------------------------------------- fetchers
    def _fetch_html(self, username):
        """Direct HTML page; 302 -> /accounts/login means private/blocked, not missing."""
        try:
            resp = http.get(
                f"https://www.instagram.com/{username}/",
                allow_redirects=False,
                headers={"Accept-Language": "en-US,en;q=0.9"},
                timeout=12)
        except Exception as exc:
            self._warn.append(f"html fetch error: {exc}")
            return None, None
        if resp.status_code == 429:
            self._warn.append("instagram.com HTML rate-limited (429)")
            return None, "rate_limited"
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = (resp.headers.get("Location") or "")
            if LOGIN_PATH in loc:
                return None, "login_redirect"
            return None, f"redirect:{loc[:80]}"
        if resp.status_code == 404:
            return None, "not_found"
        if resp.status_code != 200:
            return None, f"status:{resp.status_code}"
        return resp.text, "ok"

    def _parse_html(self, html):
        info = {
            "og_title": _og(html, "og:title"),
            "og_description": _og(html, "og:description"),
            "og_image": _og(html, "og:image"),
            "og_url": _og(html, "og:url"),
        }
        shared = None
        m = _SHARED_DATA_RE.search(html)
        if m:
            try:
                shared = json.loads(m.group(1))
            except (ValueError, json.JSONDecodeError):
                shared = None
        if not shared:
            m = _ADDITIONAL_RE.search(html)
            if m:
                try:
                    shared = json.loads(m.group(1))
                except (ValueError, json.JSONDecodeError):
                    shared = None
        info["shared_data"] = shared
        return info

    def _fetch_a1(self, username):
        try:
            resp = http.get(
                f"https://www.instagram.com/{username}/",
                params={"__a": "1", "__d": "dis"},
                headers={"X-IG-App-ID": IG_APP_ID,
                         "Accept": "application/json"},
                allow_redirects=False,
                timeout=12)
        except Exception as exc:
            self._warn.append(f"__a=1 error: {exc}")
            return None
        if resp.status_code == 429:
            self._warn.append("__a=1 rate-limited (429)")
            return None
        if resp.status_code in (301, 302, 303, 307, 308):
            self._warn.append("__a=1 redirected (needs login)")
            return None
        if resp.status_code in (401, 403, 404):
            return None
        return self._safe_json(resp)

    def _fetch_web_profile_info(self, username):
        try:
            resp = http.get(
                "https://i.instagram.com/api/v1/users/web_profile_info/",
                params={"username": username},
                headers={"X-IG-App-ID": IG_APP_ID,
                         "Accept": "application/json",
                         "Referer": f"https://www.instagram.com/{username}/"},
                allow_redirects=False,
                timeout=12)
        except Exception as exc:
            self._warn.append(f"web_profile_info error: {exc}")
            return None
        if resp.status_code == 429:
            self._warn.append("web_profile_info rate-limited (429)")
            return None
        if resp.status_code in (401, 403):
            self._warn.append(f"web_profile_info auth-walled ({resp.status_code})")
            return None
        if resp.status_code == 404:
            return None
        data = self._safe_json(resp)
        if not isinstance(data, dict):
            return None
        return (data.get("data") or {}).get("user") or data.get("user") or data

    # --------------------------------------------------------------- normalize
    def _dig_user(self, blob):
        """Pull a user-ish dict out of whatever shape the endpoint returned."""
        if not isinstance(blob, dict):
            return {}
        # web_profile_info already-flat shape
        if "username" in blob and ("edge_followed_by" in blob
                                   or "edge_follow" in blob
                                   or "profile_pic_url" in blob):
            return blob
        for path in (("graphql", "user"), ("data", "user"), ("user",)):
            cur = blob
            for key in path:
                cur = cur.get(key) if isinstance(cur, dict) else None
                if cur is None:
                    break
            if isinstance(cur, dict) and cur.get("username"):
                return cur
        # _sharedData entry
        try:
            page = (blob.get("entry_data", {})
                        .get("ProfilePage", [{}])[0]
                        .get("graphql", {})
                        .get("user"))
            if isinstance(page, dict):
                return page
        except Exception:
            pass
        return {}

    def _count(self, d, *keys):
        for k in keys:
            v = d.get(k) if isinstance(d, dict) else None
            if isinstance(v, dict) and "count" in v:
                return v["count"]
            if isinstance(v, (int, float)):
                return int(v)
        return None

    def _normalize_profile(self, html_info, a1_blob, wpi_blob):
        user = {}
        for blob in (wpi_blob, a1_blob, (html_info or {}).get("shared_data")):
            u = self._dig_user(blob)
            if u:
                # merge non-null fields; first (richest) source wins per key
                for k, v in u.items():
                    user.setdefault(k, v)

        return {
            "id": user.get("id") or user.get("pk"),
            "username": user.get("username"),
            "full_name": user.get("full_name"),
            "biography": user.get("biography"),
            "external_url": user.get("external_url"),
            "follower_count": self._count(user, "edge_followed_by", "follower_count"),
            "following_count": self._count(user, "edge_follow", "following_count"),
            "posts_count": self._count(user, "edge_owner_to_timeline_media",
                                       "media_count"),
            "is_private": bool(user.get("is_private")),
            "is_verified": bool(user.get("is_verified")),
            "is_business": bool(user.get("is_business_account")
                                or user.get("is_business")),
            "profile_pic_url": user.get("profile_pic_url"),
            "profile_pic_url_hd": user.get("profile_pic_url_hd"),
            "category": user.get("category_name") or user.get("category"),
            "connected_fb_page": user.get("connected_fb_page")
                                 or user.get("fb_page"),
            "obfuscated_id": user.get("fbid_v2") or user.get("fbid"),
        }, user

    def _extract_posts(self, raw_user):
        posts = []
        edges = (((raw_user or {}).get("edge_owner_to_timeline_media")
                  or {}).get("edges") or [])
        for e in edges[:12]:
            node = e.get("node") if isinstance(e, dict) else None
            if not isinstance(node, dict):
                continue
            caption_edges = (node.get("edge_media_to_caption") or {}).get("edges") or []
            caption = ""
            if caption_edges and isinstance(caption_edges[0], dict):
                caption = (caption_edges[0].get("node") or {}).get("text") or ""
            shortcode = node.get("shortcode") or node.get("code")
            likes = self._count(node, "edge_liked_by", "edge_media_preview_like")
            posts.append({
                "caption": (caption or "")[:280],
                "url": f"https://www.instagram.com/p/{shortcode}/" if shortcode else None,
                "likes": likes,
                "is_video": bool(node.get("is_video")),
            })
        return posts

    # --------------------------------------------------------- variations pivot
    def _probe_variation(self, candidate, base):
        """HTML-only probe. Real hit requires 2+ real-account signals AND
        no login redirect / generic 'not available' page."""
        try:
            resp = http.get(
                f"https://www.instagram.com/{candidate}/",
                allow_redirects=False,
                headers={"Accept-Language": "en-US,en;q=0.9"},
                timeout=10)
        except Exception:
            return None
        if resp.status_code == 429:
            self._warn.append(f"variation {candidate} rate-limited (429)")
            return None
        if _is_instagram_login_redirect(resp):
            # Can't verify anything anonymously - skip (do not count as a hit).
            return None
        if resp.status_code in (301, 302, 303, 307, 308):
            return None
        if resp.status_code != 200:
            return None
        html = resp.text or ""
        if _is_generic_instagram_page(html, candidate):
            return None
        title = _og(html, "og:title")
        if not title:
            return None
        structured = _extract_structured_json(html)
        signals = _real_profile_signals(html, structured, candidate, profile=None)
        signals_count, confidence = _score_signals(signals)
        if signals_count < 2:
            # Instagram returned a page but we can't prove it's a real account.
            return None
        desc = _og(html, "og:description") or ""
        followers = None
        m = re.search(r"([\d,.]+[KM]?)\s+Followers", desc)
        if m:
            followers = m.group(1)
        sim = round(SequenceMatcher(None, base.lower(),
                                    candidate.lower()).ratio(), 3)
        return {
            "username": candidate,
            "verified_exists": True,
            "exists": True,
            "confidence": confidence,
            "signals": signals,
            "signals_count": signals_count,
            "similarity": sim,
            "og_title": title,
            "follower_hint": followers,
            "url": f"https://www.instagram.com/{candidate}/",
        }

    def _search_variations(self, username, max_variations):
        raw = generate_variations(username, max_variations * 3)
        raw = platform_filter(raw, "instagram")
        cleaned, seen = [], set()
        for v in raw:
            v = (v or "").lower()
            v = re.sub(r"[^a-z0-9._]", "", v).strip("._")
            if v and _USERNAME_RE.match(v) and v != username.lower() and v not in seen:
                seen.add(v)
                cleaned.append(v)
            if len(cleaned) >= max_variations:
                break
        candidates = []
        if not cleaned:
            return cleaned, candidates
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(self._probe_variation, c, username): c
                       for c in cleaned}
            for fut in as_completed(futures):
                hit = fut.result()
                if hit:
                    candidates.append(hit)
        candidates.sort(key=lambda c: c["similarity"], reverse=True)
        return cleaned, candidates

    # --------------------------------------------------------------------- run
    def run(self):
        if not self.validate():
            return False

        username = self._clean(self.get_option("TARGET"))
        if not username:
            print_status("TARGET resolved to empty username", "error")
            return False
        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))
        fetch_posts = self._bool_opt("FETCH_POSTS", True)

        self._warn = []

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Instagram OSINT: @{username}")
        print(f"{'='*58}{Colors.RESET}\n")

        # 1) HTML scrape
        print_status("Fetching instagram.com HTML...", "info")
        html, html_state = self._fetch_html(username)
        html_info = self._parse_html(html) if html else {}
        if html_state == "ok":
            if html_info.get("og_title"):
                print_status(f"og:title: {html_info['og_title']}", "success")
            if html_info.get("og_description"):
                print_status(f"og:description: {html_info['og_description'][:120]}",
                             "info")
        elif html_state == "login_redirect":
            print_status(
                "HTML redirected to /accounts/login/ - Instagram is blocking "
                "unauth scraping for this profile right now", "warning")
        elif html_state == "not_found":
            print_status("HTML returned 404 - username not found", "warning")
        elif html_state == "rate_limited":
            print_status("HTML returned 429 - rate limited", "warning")
        else:
            print_status(f"HTML state: {html_state}", "warning")

        # 2) ?__a=1 JSON
        print_status("Trying ?__a=1&__d=dis JSON endpoint...", "info")
        a1 = self._fetch_a1(username)
        print_status("__a=1 returned data" if a1 else "__a=1 empty",
                     "success" if a1 else "warning")

        # 3) web_profile_info (richest when it works)
        print_status("Trying i.instagram.com web_profile_info...", "info")
        wpi = self._fetch_web_profile_info(username)
        print_status("web_profile_info returned data" if wpi else "web_profile_info empty",
                     "success" if wpi else "warning")

        profile, raw_user = self._normalize_profile(html_info, a1, wpi)

        # ---------- real-account signal evaluation (direct target) ----------
        structured = _extract_structured_json(html) if html else None
        is_login_redirect = html_state == "login_redirect"
        is_generic = _is_generic_instagram_page(html, username) if html else True
        signals = _real_profile_signals(html, structured, username,
                                        profile=profile if profile.get("username") else None)
        signals_count, confidence = _score_signals(signals)
        exists = (
            html_state == "ok"
            and not is_login_redirect
            and not is_generic
            and signals_count >= 2
        )
        profile["exists"] = bool(exists)
        profile["confidence"] = confidence if exists else 0.0
        profile["signals"] = signals
        profile["signals_count"] = signals_count

        if exists:
            print_status(
                f"Resolved: id={profile.get('id')} "
                f"followers={profile.get('follower_count')} "
                f"private={profile.get('is_private')} "
                f"verified={profile.get('is_verified')} "
                f"signals={signals_count}/8 conf={confidence}", "success")
        elif profile.get("username") and signals_count < 2:
            print_status(
                f"Instagram returned a page but only {signals_count} real-account "
                f"signal(s) fired - not treating as a confirmed real account.",
                "warning")
        elif is_login_redirect:
            print_status(
                "No real-account signals: Instagram login-redirected us "
                "(cannot distinguish private/nonexistent anonymously).",
                "warning")
        elif is_generic:
            print_status(
                "Instagram served the generic 'page isn't available' response "
                "- treating as nonexistent / deleted.", "warning")
        else:
            print_status("Could not resolve a profile from any endpoint",
                         "warning")

        # 4) Recent posts (public only, and only when we trust the account)
        recent_posts = []
        if fetch_posts and exists and raw_user and not profile.get("is_private"):
            recent_posts = self._extract_posts(raw_user)
            print_status(f"Collected {len(recent_posts)} recent post(s)",
                         "success" if recent_posts else "info")
        elif fetch_posts and exists and profile.get("is_private"):
            print_status("Profile is private - skipping posts", "info")

        # 5) Bio pivot
        bio_text = " ".join(filter(None, [
            profile.get("biography"), profile.get("full_name"),
            profile.get("category"), html_info.get("og_description") or "",
        ]))
        bio_pivots = {}
        if _VARIATIONS_OK:
            try:
                bio_pivots = extract_handles_from_bio(bio_text) or {}
            except Exception:
                bio_pivots = {}
        if bio_pivots:
            counts = ", ".join(f"{k}:{len(v)}"
                               for k, v in bio_pivots.items() if v)
            if counts:
                print_status(f"Bio pivots - {counts}", "success")

        # 6) Variation search
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(f"Probing up to {max_variations} username variations...",
                         "info")
            variations_tried, candidates = self._search_variations(
                username, max_variations)
            # Enforce exists=True (defense in depth; _probe_variation already filters).
            candidates = [c for c in candidates if c.get("exists")]
            for c in candidates:
                c["confidence_tier"] = confidence_tier(c.get("similarity", 0.0))
                c["is_verified_as_target"] = False
                c["verification_hints"] = _verification_hints_instagram(c)
            print_status(
                f"Tried {len(variations_tried)}, {len(candidates)} real-signal "
                f"candidate hit(s) (NOT confirmed as target)",
                "success" if candidates else "info")
            for c in candidates[:10]:
                hint = f" ({c['follower_hint']} followers)" if c.get("follower_hint") else ""
                tier = c.get("confidence_tier", "very-low")
                severity = "warning" if tier in ("medium", "low", "very-low") else "success"
                print_status(
                    f"  [CANDIDATE/{tier}] -> @{c['username']} "
                    f"sim={c['similarity']} conf={c.get('confidence', 0.0)} "
                    f"({c.get('signals_count', 0)} signals){hint} - NOT CONFIRMED",
                    severity)
        elif do_variations and not _VARIATIONS_OK:
            print_status("username_variations unavailable - skipping pivot",
                         "warning")

        # ------------------------------------------------------------- results
        self.results = {
            "username": username,
            "url": f"https://www.instagram.com/{username}/",
            "profile": profile,
            "recent_posts": recent_posts,
            "bio_pivots": bio_pivots,
            "external_url": profile.get("external_url"),
            "variations_tried": variations_tried,
            "candidates": [{
                "username": c["username"],
                "verified_exists": c["verified_exists"],
                "exists": bool(c.get("exists")),
                "confidence": c.get("confidence", 0.0),
                "signals": c.get("signals", {}),
                "signals_count": c.get("signals_count", 0),
                "similarity": c["similarity"],
                "confidence_tier": c.get("confidence_tier",
                                         confidence_tier(c.get("similarity", 0.0))),
                "is_verified_as_target": False,
                "is_private": None,
                "follower_count": c.get("follower_hint"),
                "verification_hints": c.get("verification_hints")
                                      or _verification_hints_instagram(c),
            } for c in candidates],
            "warnings": self._warn,
        }
        self.results["disclaimer"] = build_disclaimer("Instagram", len(candidates))
        if exists:
            self.results["direct_hit_note"] = (
                "exact-match username with real-account signals - most likely the "
                "intended handle, but confirm the account OWNER before trusting."
            )
            self.results["profile"]["is_verified_as_target"] = False
            self.results["profile"]["confidence_tier"] = "exact-match"

        # A blocked/rate-limited fetch must be distinguishable from "account does
        # not exist". We only have a clean negative when the HTML loaded (ok) or
        # returned a real 404; a 429 / login-wall / 5xx / network error with no
        # data from any endpoint is an inconclusive FETCH FAILURE, not an absence.
        direct_fetch_failed = (
            not exists
            and html_state not in ("ok", "not_found")
            and not a1 and not wpi
        )
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status(
                "Direct lookup INCONCLUSIVE - Instagram blocked/rate-limited "
                "anonymous access; this is NOT evidence the account is absent",
                "warning")

        # ------------------------------------------------------------- summary
        direct_hit = bool(exists)
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: @{username}")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  Link:         https://www.instagram.com/{username}/")
        if direct_hit:
            print(f"  Direct hit:   yes [CANDIDATE/exact-match] "
                  f"confidence={confidence}  ({signals_count} signals)")
            fired = [k for k, v in signals.items() if v]
            if fired:
                print(f"  Signals:      {', '.join(fired)}")
            if profile.get("id"):
                print(f"  ID:           {profile['id']}")
            if profile.get("full_name"):
                print(f"  Full name:    {profile['full_name']}")
            if profile.get("follower_count") is not None:
                print(f"  Followers:    {profile['follower_count']}")
            if profile.get("following_count") is not None:
                print(f"  Following:    {profile['following_count']}")
            if profile.get("posts_count") is not None:
                print(f"  Posts (API):  {profile['posts_count']}")
            flags = []
            if profile.get("is_private"):   flags.append("private")
            if profile.get("is_verified"):  flags.append("verified")
            if profile.get("is_business"):  flags.append("business")
            if flags:
                print(f"  Flags:        {', '.join(flags)}")
            if profile.get("category"):
                print(f"  Category:     {profile['category']}")
            if profile.get("external_url"):
                print(f"  External URL: {profile['external_url']}")
            if profile.get("profile_pic_url"):
                print(f"  Avatar:       {profile['profile_pic_url'][:70]}")
            if profile.get("biography"):
                bio = profile['biography'].replace("\n", " ")
                print(f"  Bio:          {bio[:120]}")
            print(f"  {Colors.YELLOW}Note: exact-match username with real-account "
                  f"signals - most likely the intended handle, but confirm the "
                  f"account OWNER before trusting.{Colors.RESET}")
        else:
            print(f"  Direct hit:   no - Instagram returned a page but with no "
                  f"real-account signals")
            print(f"  {Colors.YELLOW}(nonexistent username, deleted account, or "
                  f"Instagram blocked anonymous access){Colors.RESET}")
            if signals_count:
                fired = [k for k, v in signals.items() if v]
                print(f"  {Colors.DIM}Partial signals ({signals_count}/8): "
                      f"{', '.join(fired)}{Colors.RESET}")
        print(f"  Posts shown:  {len(recent_posts)}")
        if bio_pivots:
            parts = [f"{k}:{len(v)}" for k, v in bio_pivots.items() if v]
            if parts:
                print(f"  Bio pivots:   {', '.join(parts)}")
        print(f"  Candidates:   {len(candidates)} (from {len(variations_tried)} tried)")
        if self._warn:
            print(f"  {Colors.DIM}{len(self._warn)} warning(s): "
                  f"{'; '.join(self._warn[:3])}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        if candidates:
            print_uncertainty_box("Instagram")

        return True
