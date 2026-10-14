"""Bluesky/AT Protocol OSINT - public profile lookup via the AT Protocol public API.

Bluesky exposes a fully public API (no authentication required) through:
  * com.atproto.identity.resolveHandle  -- resolves a handle to a DID
  * app.bsky.actor.getProfile           -- full public profile data
  * app.bsky.feed.getAuthorFeed         -- public feed / recent posts

Data collected:
  * DID (permanent, non-reusable identifier)
  * Profile: display name, bio, avatar, banner, follower/following/post counts
  * Account index date (indexedAt - closest proxy for creation date)
  * Labels applied to the account (e.g. impersonation, spam flags)
  * Recent posts (up to 5) with text and creation timestamp
  * Bio handle pivot via extract_handles_from_bio()
  * Username variation probing (optional)
"""

import re
import time
from difflib import SequenceMatcher

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


# Handle part: letters, digits, hyphens; 1–63 chars per label (DNS-like)
_HANDLE_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,62}$")
_BSKY_SOCIAL_SUFFIX = ".bsky.social"
_RESOLVE_URL = "https://bsky.social/xrpc/com.atproto.identity.resolveHandle"
_PROFILE_URL = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"
_FEED_URL = "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed"


def _verification_hints_bluesky(candidate):
    """Manual verification checks specific to a Bluesky candidate."""
    return [
        "Verify the DID (did:plc:...) — it is a permanent, non-reusable identifier "
        "even if the handle changes",
        "Check the account creation date (indexedAt) against the target's known online activity",
        "Cross-reference bio handles with other platforms to confirm identity",
        "Labels/flags on the account (e.g. impersonation) are strong negative signals",
        "Post content and writing style should match target's known communication patterns",
    ]


class BlueskyOsint(BaseModule):
    name = "harvest/bluesky_osint"
    description = "Bluesky/AT Protocol public profile OSINT (no auth required)"
    category = "harvest"
    target_type = "username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Bluesky handle (e.g. alice.bsky.social or just alice)")
        self.add_option("VARIATIONS", "true", False,
                        "Probe username variations against Bluesky getProfile")
        self.add_option("MAX_VARIATIONS", "15", False,
                        "Maximum number of handle variations to probe")

    # ------------------------------------------------------------------ helpers

    def _normalize_handle(self, raw):
        """Strip leading @ and append .bsky.social if the handle has no dot."""
        handle = (raw or "").strip()
        if handle.startswith("@"):
            handle = handle[1:]
        if "." not in handle:
            handle = handle + _BSKY_SOCIAL_SUFFIX
        return handle.lower()

    def _username_part(self, handle):
        """Return the part before the first dot (the username segment)."""
        return handle.split(".")[0]

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

    def _resolve_handle(self, handle):
        """Resolve a handle to a DID via com.atproto.identity.resolveHandle.
        Returns (did_str or None, status_str)."""
        try:
            resp = http.get(
                _RESOLVE_URL,
                params={"handle": handle},
                timeout=12,
            )
        except Exception as exc:
            self._warn.append(f"resolveHandle error ({handle}): {exc}")
            return None, "error"

        if resp.status_code == 400:
            return None, "not_found"
        if resp.status_code == 429:
            self._warn.append("resolveHandle rate-limited (429)")
            return None, "rate_limited"
        if resp.status_code != 200:
            return None, f"status:{resp.status_code}"

        data = self._safe_json(resp) or {}
        did = data.get("did")
        if not did:
            return None, "no_did"
        return did, "ok"

    def _get_profile(self, handle):
        """Fetch full public profile via app.bsky.actor.getProfile.
        Returns (profile_dict or None, status_str)."""
        try:
            resp = http.get(
                _PROFILE_URL,
                params={"actor": handle},
                timeout=12,
            )
        except Exception as exc:
            self._warn.append(f"getProfile error ({handle}): {exc}")
            return None, "error"

        if resp.status_code == 400:
            return None, "not_found"
        if resp.status_code == 404:
            return None, "not_found"
        if resp.status_code == 429:
            self._warn.append("getProfile rate-limited (429)")
            return None, "rate_limited"
        if resp.status_code != 200:
            return None, f"status:{resp.status_code}"

        data = self._safe_json(resp)
        if not isinstance(data, dict):
            return None, "bad_json"
        return data, "ok"

    def _get_feed(self, handle):
        """Fetch recent public posts for a handle; return list of up to 5 dicts."""
        try:
            resp = http.get(
                _FEED_URL,
                params={"actor": handle, "limit": 10},
                timeout=12,
            )
        except Exception as exc:
            self._warn.append(f"getAuthorFeed error ({handle}): {exc}")
            return []

        if resp.status_code != 200:
            if resp.status_code == 429:
                self._warn.append("getAuthorFeed rate-limited (429)")
            return []

        data = self._safe_json(resp) or {}
        feed_items = data.get("feed") or []
        posts = []
        for item in feed_items:
            record = (item.get("post") or {}).get("record") or {}
            if not isinstance(record, dict):
                continue
            text = record.get("text") or ""
            created_at = record.get("createdAt") or ""
            if text:
                posts.append({
                    "text": text[:280],
                    "created_at": created_at,
                })
            if len(posts) >= 5:
                break
        return posts

    # --------------------------------------------------------------- variations

    def _probe_variation_handle(self, handle):
        """Check whether a handle exists on Bluesky via getProfile.
        Returns a candidate dict on 200, None otherwise."""
        time.sleep(0.4)
        try:
            resp = http.get(
                _PROFILE_URL,
                params={"actor": handle},
                timeout=10,
            )
        except Exception:
            return None

        if resp.status_code == 429:
            self._warn.append(f"variation probe rate-limited (429) for {handle}")
            return None

        if resp.status_code == 200:
            data = self._safe_json(resp) or {}
            return {
                "handle": handle,
                "exists": True,
                "did": data.get("did"),
                "display_name": data.get("displayName"),
                "followers": data.get("followersCount"),
                "url": f"https://bsky.app/profile/{handle}",
            }
        return None

    def _search_variations(self, username_part, max_variations):
        """Generate and probe handle variations against Bluesky."""
        raw = generate_variations(username_part, max_variations * 3)
        cleaned, seen = [], set()
        for v in raw:
            v = (v or "").strip()
            if (v
                    and re.match(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,62}$", v)
                    and v.lower() != username_part.lower()
                    and v.lower() not in seen):
                seen.add(v.lower())
                cleaned.append(v)
            if len(cleaned) >= max_variations:
                break

        candidates = []
        for v in cleaned:
            full_handle = v + _BSKY_SOCIAL_SUFFIX
            hit = self._probe_variation_handle(full_handle)
            if hit:
                sim = round(
                    SequenceMatcher(None,
                                    username_part.lower(),
                                    v.lower()).ratio(),
                    3)
                hit["similarity"] = sim
                tag_candidate(hit, "bluesky", sim, _verification_hints_bluesky)
                candidates.append(hit)
        candidates.sort(key=lambda c: c.get("similarity", 0), reverse=True)
        return cleaned, candidates

    # --------------------------------------------------------------------- run

    def run(self):
        if not self.validate():
            return False

        raw_target = self.get_option("TARGET") or ""
        handle = self._normalize_handle(raw_target)
        if not handle:
            print_status("TARGET resolved to empty handle", "error")
            return False

        username_part = self._username_part(handle)
        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))

        self._warn = []

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Bluesky OSINT: @{handle}")
        print(f"{'='*60}{Colors.RESET}\n")

        # Step 1 — Resolve handle to DID
        print_status(f"Resolving handle @{handle} via AT Protocol...", "info")
        did, resolve_status = self._resolve_handle(handle)

        if resolve_status == "not_found":
            print_status("Handle not found on Bluesky (resolveHandle 400)", "warning")
        elif resolve_status == "rate_limited":
            print_status("resolveHandle rate-limited (429) - try again shortly", "warning")
        elif resolve_status != "ok":
            print_status(f"resolveHandle status: {resolve_status}", "warning")
        else:
            print_status(f"Resolved DID: {did}", "success")

        # Step 2 — Fetch profile
        print_status("Fetching public profile...", "info")
        profile_raw, profile_status = self._get_profile(handle)

        if profile_status == "not_found":
            print_status("Profile not found (404/400) - account may not exist", "warning")
        elif profile_status == "rate_limited":
            print_status("getProfile rate-limited (429)", "warning")
        elif profile_status != "ok":
            print_status(f"getProfile status: {profile_status}", "warning")

        profile = {}
        if profile_raw and isinstance(profile_raw, dict):
            # Extract label values from the labels array
            labels_raw = profile_raw.get("labels") or []
            label_values = [
                lbl.get("val") for lbl in labels_raw
                if isinstance(lbl, dict) and lbl.get("val")
            ]
            # Extract associated counts
            assoc = profile_raw.get("associated") or {}

            profile = {
                "did":            profile_raw.get("did") or did,
                "handle":         profile_raw.get("handle") or handle,
                "display_name":   profile_raw.get("displayName"),
                "bio":            profile_raw.get("description") or "",
                "avatar":         profile_raw.get("avatar"),
                "banner":         profile_raw.get("banner"),
                "followers":      profile_raw.get("followersCount"),
                "following":      profile_raw.get("followsCount"),
                "posts_count":    profile_raw.get("postsCount"),
                "indexed_at":     profile_raw.get("indexedAt"),
                "labels":         label_values,
                "lists_count":    assoc.get("lists"),
                "feedgens_count": assoc.get("feedgens"),
            }

            flags = []
            if label_values:
                flags.append(f"labels=[{', '.join(label_values)}]")
            print_status(
                f"Profile found: followers={profile['followers']}  "
                f"following={profile['following']}  "
                f"posts={profile['posts_count']}"
                + (f"  flags={flags}" if flags else ""),
                "success")
            if label_values:
                print_status(
                    f"Account labels (possible flags): {', '.join(label_values)}",
                    "warning")

        # Step 3 — Recent posts
        recent_posts = []
        if profile_raw:
            print_status("Fetching recent posts...", "info")
            recent_posts = self._get_feed(handle)
            print_status(f"Collected {len(recent_posts)} post(s)",
                         "success" if recent_posts else "info")

        # Step 4 — Bio handle pivot
        bio_handles = {}
        bio_text = profile.get("bio") or ""
        if _VARIATIONS_OK and bio_text:
            try:
                bio_handles = extract_handles_from_bio(bio_text) or {}
            except Exception:
                bio_handles = {}
        if bio_handles:
            counts = ", ".join(f"{k}:{len(v)}" for k, v in bio_handles.items() if v)
            if counts:
                print_status(f"Bio handles found: {counts}", "success")

        # Step 5 — Variation probe
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(
                f"Probing up to {max_variations} handle variations (@*.bsky.social)...",
                "info")
            variations_tried, candidates = self._search_variations(
                username_part, max_variations)
            print_status(
                f"Tried {len(variations_tried)}, "
                f"{len(candidates)} candidate hit(s) (NOT confirmed as target)",
                "success" if candidates else "info")
            for c in candidates[:10]:
                tier = c.get("confidence_tier", "very-low")
                sev = "warning" if tier in ("medium", "low", "very-low") else "success"
                print_status(
                    f"  [CANDIDATE/{tier}] -> @{c['handle']}  "
                    f"sim={c.get('similarity')}  "
                    f"did={str(c.get('did') or '')[:20]}... - NOT CONFIRMED",
                    sev)
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping variation pivot",
                "warning")

        # ------------------------------------------------------------- results
        self.results = {
            "handle":       profile.get("handle") or handle,
            "did":          profile.get("did") or did,
            "profile_url":  f"https://bsky.app/profile/{handle}",
            "display_name": profile.get("display_name"),
            "bio":          profile.get("bio"),
            "avatar":       profile.get("avatar"),
            "banner":       profile.get("banner"),
            "followers":    profile.get("followers"),
            "following":    profile.get("following"),
            "posts_count":  profile.get("posts_count"),
            "indexed_at":   profile.get("indexed_at"),
            "labels":       profile.get("labels") or [],
            "recent_posts": recent_posts,
            "bio_handles":  bio_handles,
            "candidates":   [
                {
                    "handle":              c["handle"],
                    "exists":              True,
                    "did":                 c.get("did"),
                    "display_name":        c.get("display_name"),
                    "followers":           c.get("followers"),
                    "url":                 c.get("url"),
                    "similarity":          c.get("similarity"),
                    "confidence_tier":     c.get("confidence_tier",
                                                  confidence_tier(c.get("similarity", 0.0))),
                    "is_verified_as_target": False,
                    "verification_hints":  (
                        c.get("verification_hints")
                        or _verification_hints_bluesky(c)
                    ),
                }
                for c in candidates
            ],
            "warnings":     self._warn,
            "disclaimer":   build_disclaimer("Bluesky", len(candidates)),
            "source":       "public.api.bsky.app / bsky.social (AT Protocol, no auth required)",
        }

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}")
        print(f"  Summary: @{handle}")
        print(f"{'-'*60}{Colors.RESET}")
        print(f"  Profile URL:  https://bsky.app/profile/{handle}")

        if profile_raw:
            print(f"  Account:      found")
            if profile.get("did"):
                print(f"  DID:          {profile['did']}")
            if profile.get("indexed_at"):
                print(f"  Indexed at:   {profile['indexed_at']}")
            if profile.get("display_name"):
                print(f"  Display name: {profile['display_name']}")
            if profile.get("followers") is not None:
                print(f"  Followers:    {profile['followers']}  "
                      f"Following: {profile['following']}  "
                      f"Posts: {profile['posts_count']}")
            if profile.get("bio"):
                print(f"  Bio:          {profile['bio'][:120]}")
            if profile.get("labels"):
                print(f"  {Colors.YELLOW}Labels:       "
                      f"{', '.join(profile['labels'])}{Colors.RESET}")
            if profile.get("avatar"):
                print(f"  Avatar:       {profile['avatar'][:70]}")
        else:
            print(f"  Account:      {Colors.YELLOW}not found / handle does not "
                  f"exist{Colors.RESET}")

        if did and not profile_raw:
            print(f"  DID (resolved): {did}")

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
            print_uncertainty_box("Bluesky", _verification_hints_bluesky({}))

        return True
