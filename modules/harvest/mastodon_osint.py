"""Mastodon/Fediverse OSINT - public profile lookup via instance API + WebFinger.

Mastodon exposes a fully public API for profile data without authentication:
  * /.well-known/webfinger  -- confirms account existence and resolves ActivityPub ID
  * /api/v1/accounts/lookup -- full public account data by username
  * /api/v1/accounts/{id}/statuses -- public timeline (recent posts)

All Mastodon-compatible instances (Mastodon, Pleroma, Akkoma, Misskey via API bridge)
return these endpoints, though field availability varies by software.

Data collected:
  * Account metadata: id, username, display name, bio (HTML → plain), avatar, header,
    followers/following/post counts, creation date, bot flag, locked flag
  * Custom profile fields (links, verification URLs, self-declared identities)
  * Recent public statuses (up to 5) with content, counts, and timestamps
  * WebFinger ActivityPub URL (confirms existence on the fediverse)
  * Bio handle pivot via extract_handles_from_bio()
  * Username variation probing on the same instance (optional)
"""

import re
import time
from difflib import SequenceMatcher
from html.parser import HTMLParser

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest._social_base import (
    confidence_tier,
    print_uncertainty_box,
    build_disclaimer,
    tag_candidate,
)

try:
    from modules.harvest.username_variations import generate_variations, extract_handles_from_bio
    _VARIATIONS_OK = True
except Exception:
    _VARIATIONS_OK = False

    def generate_variations(_u, _n=20):
        return []

    def extract_handles_from_bio(_text):
        return {}


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,30}$")
_DEFAULT_INSTANCE = "mastodon.social"


# ------------------------------------------------------------------ HTML helpers

class _StripHTMLParser(HTMLParser):
    """Minimal HTML tag stripper that preserves text content."""
    def __init__(self):
        super().__init__()
        self._parts = []

    def handle_data(self, data):
        self._parts.append(data)

    def get_text(self):
        return " ".join(p.strip() for p in self._parts if p.strip())


def _strip_html(html_text):
    """Return plain text with HTML tags stripped."""
    if not html_text:
        return ""
    parser = _StripHTMLParser()
    try:
        parser.feed(html_text)
        return parser.get_text()
    except Exception:
        # Fallback: crude regex strip
        return re.sub(r"<[^>]+>", " ", html_text).strip()


# ------------------------------------------------------------------ hints

def _verification_hints_mastodon(candidate):
    """Manual verification checks specific to a Mastodon candidate."""
    return [
        "Mastodon accounts are tied to a specific instance — verify the instance "
        "matches the target's known community",
        "Account creation date and early posts are strong identity anchors",
        "Custom profile fields (links, verification URLs) often point to other platforms",
        "Bot flag means the account may be automated — less reliable for identity attribution",
        "Cross-instance account moves preserve followers but change the handle — "
        "check for Move notices",
    ]


# ------------------------------------------------------------------ module

class MastodonOsint(BaseModule):
    name = "harvest/mastodon_osint"
    description = "Mastodon/Fediverse public profile OSINT via instance API + WebFinger"
    category = "harvest"
    target_type = "username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Mastodon handle: user@instance.tld  (or just username, assumes mastodon.social)")
        self.add_option("VARIATIONS", "true", False,
                        "Probe username variations against the same instance")
        self.add_option("MAX_VARIATIONS", "15", False,
                        "Maximum number of username variations to probe")

    # ------------------------------------------------------------------ helpers

    def _parse_target(self, raw):
        """Split user@instance into (user, instance).
        If no @ present, use the default instance."""
        raw = (raw or "").strip().lstrip("@")
        if "@" in raw:
            parts = raw.split("@", 1)
            return parts[0].strip(), parts[1].strip().lower()
        return raw, _DEFAULT_INSTANCE

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
        except Exception:
            return None

    # ------------------------------------------------------------------ fetchers

    def _webfinger(self, user, instance):
        """Confirm account existence via WebFinger and return the ActivityPub self URL.
        Returns (activitypub_url or None, status_str)."""
        url = f"https://{instance}/.well-known/webfinger"
        resource = f"acct:{user}@{instance}"
        try:
            resp = http.get(
                url,
                params={"resource": resource},
                headers={"Accept": "application/json"},
                timeout=12,
            )
        except Exception as exc:
            self._warn.append(f"WebFinger error ({instance}): {exc}")
            return None, "error"

        if resp.status_code == 404:
            return None, "not_found"
        if resp.status_code == 410:
            return None, "gone"
        if resp.status_code == 429:
            self._warn.append("WebFinger rate-limited (429)")
            return None, "rate_limited"
        if resp.status_code != 200:
            return None, f"status:{resp.status_code}"

        data = self._safe_json(resp)
        if not isinstance(data, dict):
            return None, "bad_json"

        # Find the "self" link with type application/activity+json
        ap_url = None
        for link in (data.get("links") or []):
            if not isinstance(link, dict):
                continue
            if (link.get("rel") == "self"
                    and link.get("type") == "application/activity+json"):
                ap_url = link.get("href")
                break

        if not ap_url:
            # Accept any "self" link as a fallback
            for link in (data.get("links") or []):
                if isinstance(link, dict) and link.get("rel") == "self":
                    ap_url = link.get("href")
                    break

        return ap_url, "ok"

    def _lookup_account(self, user, instance):
        """Fetch account data via /api/v1/accounts/lookup.
        Returns (account_dict or None, status_str)."""
        url = f"https://{instance}/api/v1/accounts/lookup"
        try:
            resp = http.get(
                url,
                params={"acct": user},
                timeout=12,
            )
        except Exception as exc:
            self._warn.append(f"accounts/lookup error ({instance}): {exc}")
            return None, "error"

        if resp.status_code == 404:
            return None, "not_found"
        if resp.status_code == 401:
            return None, "unauthorized"
        if resp.status_code == 429:
            self._warn.append("accounts/lookup rate-limited (429)")
            return None, "rate_limited"
        if resp.status_code != 200:
            return None, f"status:{resp.status_code}"

        data = self._safe_json(resp)
        if not isinstance(data, dict):
            return None, "bad_json"
        return data, "ok"

    def _fetch_statuses(self, account_id, instance):
        """Fetch recent public statuses; return list of up to 5 dicts."""
        url = f"https://{instance}/api/v1/accounts/{account_id}/statuses"
        try:
            resp = http.get(
                url,
                params={
                    "limit": 10,
                    "exclude_replies": "true",
                    "exclude_reblogs": "true",
                },
                timeout=12,
            )
        except Exception as exc:
            self._warn.append(f"accounts/{account_id}/statuses error: {exc}")
            return []

        if resp.status_code != 200:
            if resp.status_code == 429:
                self._warn.append("statuses endpoint rate-limited (429)")
            return []

        data = self._safe_json(resp)
        if not isinstance(data, list):
            return []

        posts = []
        for item in data:
            if not isinstance(item, dict):
                continue
            content_html = item.get("content") or ""
            content_plain = _strip_html(content_html)
            if not content_plain:
                continue
            posts.append({
                "content":          content_plain[:280],
                "created_at":       item.get("created_at"),
                "favourites_count": item.get("favourites_count"),
                "reblogs_count":    item.get("reblogs_count"),
            })
            if len(posts) >= 5:
                break
        return posts

    # --------------------------------------------------------------- variations

    def _probe_variation_account(self, variation, instance):
        """Check whether a username exists on an instance via accounts/lookup.
        Returns a candidate dict on 200, None otherwise."""
        time.sleep(0.4)
        url = f"https://{instance}/api/v1/accounts/lookup"
        try:
            resp = http.get(
                url,
                params={"acct": variation},
                timeout=10,
            )
        except Exception:
            return None

        if resp.status_code == 429:
            self._warn.append(f"variation probe rate-limited (429) for {variation}")
            return None

        if resp.status_code == 200:
            data = self._safe_json(resp) or {}
            return {
                "username": variation,
                "instance": instance,
                "exists":   True,
                "id":       data.get("id"),
                "display_name": data.get("display_name"),
                "followers": data.get("followers_count"),
                "url":      data.get("url") or f"https://{instance}/@{variation}",
            }
        return None

    def _search_variations(self, username, instance, max_variations):
        """Generate and probe username variations against the same instance."""
        raw = generate_variations(username, max_variations * 3)
        cleaned, seen = [], set()
        for v in raw:
            v = (v or "").strip()
            if (v
                    and _USERNAME_RE.match(v)
                    and v.lower() != username.lower()
                    and v.lower() not in seen):
                seen.add(v.lower())
                cleaned.append(v)
            if len(cleaned) >= max_variations:
                break

        candidates = []
        for v in cleaned:
            hit = self._probe_variation_account(v, instance)
            if hit:
                sim = round(
                    SequenceMatcher(None, username.lower(), v.lower()).ratio(),
                    3)
                hit["similarity"] = sim
                tag_candidate(hit, "mastodon", sim, _verification_hints_mastodon)
                candidates.append(hit)
        candidates.sort(key=lambda c: c.get("similarity", 0), reverse=True)
        return cleaned, candidates

    # --------------------------------------------------------------------- run

    def run(self):
        if not self.validate():
            return False

        raw_target = self.get_option("TARGET") or ""
        user, instance = self._parse_target(raw_target)

        if not user:
            print_status("TARGET resolved to empty username", "error")
            return False

        if not _USERNAME_RE.match(user):
            print_status(
                f"Username '{user}' does not match Mastodon rules "
                "(1-30 chars, [A-Za-z0-9_-])", "error")
            return False

        if not instance:
            print_status("Instance could not be determined from TARGET", "error")
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))

        self._warn = []

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Mastodon OSINT: @{user}@{instance}")
        print(f"{'='*60}{Colors.RESET}\n")

        # Step 1 — Validate via WebFinger
        print_status(
            f"WebFinger lookup: acct:{user}@{instance}...", "info")
        ap_url, wf_status = self._webfinger(user, instance)

        if wf_status == "not_found":
            print_status(
                "WebFinger 404 — account not found on this instance", "warning")
        elif wf_status == "gone":
            print_status("WebFinger 410 — account deleted/moved", "warning")
        elif wf_status == "rate_limited":
            print_status("WebFinger rate-limited (429)", "warning")
        elif wf_status == "error":
            print_status(
                "WebFinger request failed — instance may be unreachable", "warning")
        elif wf_status == "ok":
            if ap_url:
                print_status(f"WebFinger confirmed. ActivityPub ID: {ap_url}", "success")
            else:
                print_status(
                    "WebFinger responded but no self link found (non-standard instance)",
                    "warning")

        # Step 2 — Account lookup
        print_status("Fetching account data via Mastodon API...", "info")
        account_raw, lookup_status = self._lookup_account(user, instance)

        if lookup_status == "not_found":
            print_status(
                "accounts/lookup 404 — account not found or instance not public",
                "warning")
        elif lookup_status == "rate_limited":
            print_status("accounts/lookup rate-limited (429)", "warning")
        elif lookup_status == "unauthorized":
            print_status(
                "accounts/lookup returned 401 — instance may require authentication",
                "warning")
        elif lookup_status != "ok":
            print_status(f"accounts/lookup status: {lookup_status}", "warning")

        account = {}
        account_id = None
        if account_raw and isinstance(account_raw, dict):
            account_id = account_raw.get("id")
            note_html = account_raw.get("note") or ""
            bio_plain = _strip_html(note_html)

            fields_raw = account_raw.get("fields") or []
            fields = []
            for f in fields_raw:
                if not isinstance(f, dict):
                    continue
                fields.append({
                    "name":  f.get("name") or "",
                    "value": _strip_html(f.get("value") or ""),
                })

            account = {
                "id":             account_id,
                "username":       account_raw.get("username") or user,
                "acct":           account_raw.get("acct"),
                "display_name":   account_raw.get("display_name"),
                "bio":            bio_plain,
                "bio_html":       note_html,
                "avatar":         account_raw.get("avatar"),
                "header":         account_raw.get("header"),
                "followers":      account_raw.get("followers_count"),
                "following":      account_raw.get("following_count"),
                "posts_count":    account_raw.get("statuses_count"),
                "created_at":     account_raw.get("created_at"),
                "bot":            bool(account_raw.get("bot")),
                "locked":         bool(account_raw.get("locked")),
                "fields":         fields,
                "url":            account_raw.get("url"),
            }

            flags = []
            if account["bot"]:
                flags.append("BOT")
            if account["locked"]:
                flags.append("LOCKED")

            print_status(
                f"Account found: followers={account['followers']}  "
                f"following={account['following']}  "
                f"posts={account['posts_count']}"
                + (f"  flags={flags}" if flags else ""),
                "success")

            if account["bot"]:
                print_status("Account is marked as BOT — automated account", "warning")
            if fields:
                print_status(
                    f"Custom fields: {len(fields)} field(s) detected", "info")

        # Step 3 — Recent statuses
        recent_posts = []
        if account_id:
            print_status("Fetching recent public statuses...", "info")
            recent_posts = self._fetch_statuses(account_id, instance)
            print_status(f"Collected {len(recent_posts)} post(s)",
                         "success" if recent_posts else "info")

        # Step 4 — Bio handle pivot (bio + fields)
        bio_handles = {}
        bio_text = account.get("bio") or ""
        # Also scan custom field values for handles/links
        field_text = " ".join(
            f.get("value") or "" for f in (account.get("fields") or [])
        )
        combined_text = (bio_text + " " + field_text).strip()

        if _VARIATIONS_OK and combined_text:
            try:
                bio_handles = extract_handles_from_bio(combined_text) or {}
            except Exception:
                bio_handles = {}
        if bio_handles:
            counts = ", ".join(f"{k}:{len(v)}" for k, v in bio_handles.items() if v)
            if counts:
                print_status(f"Bio/field handles found: {counts}", "success")

        # Step 5 — Variation probe on same instance
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(
                f"Probing up to {max_variations} variations on {instance}...", "info")
            variations_tried, candidates = self._search_variations(
                user, instance, max_variations)
            print_status(
                f"Tried {len(variations_tried)}, "
                f"{len(candidates)} candidate hit(s) (NOT confirmed as target)",
                "success" if candidates else "info")
            for c in candidates[:10]:
                tier = c.get("confidence_tier", "very-low")
                sev = "warning" if tier in ("medium", "low", "very-low") else "success"
                print_status(
                    f"  [CANDIDATE/{tier}] -> @{c['username']}@{instance}  "
                    f"sim={c.get('similarity')}  "
                    f"followers={c.get('followers')} - NOT CONFIRMED",
                    sev)
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping variation pivot",
                "warning")

        # ------------------------------------------------------------- results
        self.results = {
            "username":     account.get("username") or user,
            "instance":     instance,
            "profile_url":  account.get("url") or f"https://{instance}/@{user}",
            "activitypub_url": ap_url,
            "display_name": account.get("display_name"),
            "bio":          account.get("bio"),
            "avatar":       account.get("avatar"),
            "header":       account.get("header"),
            "followers":    account.get("followers"),
            "following":    account.get("following"),
            "posts_count":  account.get("posts_count"),
            "created_at":   account.get("created_at"),
            "bot":          account.get("bot"),
            "locked":       account.get("locked"),
            "fields":       account.get("fields") or [],
            "recent_posts": recent_posts,
            "bio_handles":  bio_handles,
            "candidates":   [
                {
                    "username":              c["username"],
                    "instance":              instance,
                    "exists":                True,
                    "display_name":          c.get("display_name"),
                    "followers":             c.get("followers"),
                    "url":                   c.get("url"),
                    "similarity":            c.get("similarity"),
                    "confidence_tier":       c.get("confidence_tier",
                                                    confidence_tier(c.get("similarity", 0.0))),
                    "is_verified_as_target": False,
                    "verification_hints":    (
                        c.get("verification_hints")
                        or _verification_hints_mastodon(c)
                    ),
                }
                for c in candidates
            ],
            "warnings":     self._warn,
            "disclaimer":   build_disclaimer("Mastodon", len(candidates)),
            "source":       (
                f"https://{instance} Mastodon public API v1 + WebFinger "
                "(no auth required)"
            ),
        }

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}")
        print(f"  Summary: @{user}@{instance}")
        print(f"{'-'*60}{Colors.RESET}")
        print(f"  Profile URL:  {self.results['profile_url']}")

        if account_raw:
            print(f"  Account:      found")
            if account.get("created_at"):
                print(f"  Created:      {account['created_at']}")
            if account.get("display_name"):
                print(f"  Display name: {account['display_name']}")
            if account.get("followers") is not None:
                print(f"  Followers:    {account['followers']}  "
                      f"Following: {account['following']}  "
                      f"Posts: {account['posts_count']}")
            flags = []
            if account.get("bot"):
                flags.append(f"{Colors.YELLOW}BOT{Colors.RESET}")
            if account.get("locked"):
                flags.append("LOCKED")
            if flags:
                print(f"  Flags:        {', '.join(flags)}")
            if account.get("bio"):
                print(f"  Bio:          {account['bio'][:120]}")
            if account.get("fields"):
                for fld in account["fields"][:4]:
                    print(f"  Field:        {fld.get('name')}: {fld.get('value', '')[:60]}")
            if account.get("avatar"):
                print(f"  Avatar:       {account['avatar'][:70]}")
        else:
            print(f"  Account:      {Colors.YELLOW}not found or instance "
                  f"unreachable{Colors.RESET}")

        if ap_url:
            print(f"  ActivityPub:  {ap_url[:70]}")

        if bio_handles:
            parts = [f"{k}:{len(v)}" for k, v in bio_handles.items() if v]
            if parts:
                print(f"  Bio handles:  {', '.join(parts)}")

        print(f"  Posts shown:  {len(recent_posts)}")
        print(f"  Candidates:   {len(candidates)} (from {len(variations_tried)} tried)")

        if self._warn:
            print(f"  {Colors.DIM}{len(self._warn)} warning(s): "
                  f"{'; '.join(self._warn[:3])}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*60}{Colors.RESET}\n")

        if candidates:
            print_uncertainty_box("Mastodon", _verification_hints_mastodon({}))

        return True
