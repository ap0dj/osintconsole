"""Twitter/X OSINT - public profile via Nitter mirrors + oembed fallback.

Zero-auth: tries a ranked list of public Nitter instances. Falls back to the
Twitter oembed API (no auth needed) for minimal confirmation. Pivots via
username variations and bio handle extraction.
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


# Twitter/X usernames: 1-50 chars, alphanumeric + underscore only.
_TWITTER_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,50}$")

# Ranked Nitter mirrors. Tried in order; first 200-response wins.
_NITTER_INSTANCES = [
    "https://nitter.net",
    "https://nitter.privacydev.net",
    "https://nitter.poast.org",
]

# Pattern used to detect Nitter's "user not found" / error page.
_NITTER_NOT_FOUND_RE = re.compile(
    r'class="error-panel"'
    r'|<title>Error'
    r'|User not found',
    re.IGNORECASE,
)


def _verification_hints_twitter(candidate):
    hints = [
        "Verify the profile picture matches known photos of the target",
        "Check join date against target's known online activity timeline",
        "Tweets content and writing style should match known target patterns",
        "Pinned tweet or bio link can confirm identity",
        "Twitter/X usernames are frequently changed — this may be a former handle",
    ]
    if candidate.get("verified"):
        hints.insert(
            0,
            "This account has a verified badge — if the target is not a notable "
            "public figure, a verified account is probably NOT them.",
        )
    return hints


class TwitterOsint(BaseModule):
    name = "harvest/twitter_osint"
    description = "Twitter/X public profile OSINT via Nitter mirrors + oembed"
    category = "harvest"
    target_type = "username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True,  "Twitter/X username (without @)")
        self.add_option("VARIATIONS", "true", False, "Pivot via username variations")
        self.add_option("MAX_VARIATIONS", "15", False, "Max variations to probe")

    # ------------------------------------------------------------------ helpers

    def _clean(self, username):
        username = (username or "").strip().lstrip("@")
        username = re.sub(r"https?://(?:www\.)?(?:twitter|x)\.com/", "", username)
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

    # ------------------------------------------------------------------ scrape

    def _fetch_nitter(self, username, warnings):
        """Try each Nitter instance in order.

        Returns (instance_base, status, html, reachable). `reachable` is True
        when at least one mirror gave a DEFINITIVE answer (a 200 with content,
        a 200 error-panel = user-not-found, or a 301/302/404 = not-found), and
        False when every mirror only 429'd / errored / was unreachable. That
        lets run() tell "all mirrors rate-limited" (a fetch failure) apart from
        "the mirrors agree the user does not exist"."""
        reachable = False
        for base in _NITTER_INSTANCES:
            url = f"{base}/{username}"
            try:
                resp = http.get(url, timeout=12)
            except Exception as exc:
                warnings.append(f"Nitter {base} error: {exc}")
                continue
            if resp.status_code == 429:
                warnings.append(f"HTTP 429 (rate-limited) from {base}")
                continue
            if resp.status_code == 200 and resp.text:
                # Nitter returns 200 even for unknown users but with an error panel
                reachable = True  # a definitive answer from this mirror
                if _NITTER_NOT_FOUND_RE.search(resp.text):
                    continue
                return base, 200, resp.text, reachable
            if resp.status_code in (301, 302, 404):
                # Hard not-found from this mirror; try next
                reachable = True
                continue
            # 403 / 5xx / anything else: a failed fetch, not a clean negative
            warnings.append(f"HTTP {resp.status_code} from {base}")
        return None, 0, "", reachable

    def _parse_meta(self, html):
        """Extract og: and twitter: meta tags from Nitter HTML."""
        out = {}
        for prop, key in [
            ("og:title",       "og_title"),
            ("og:description", "og_description"),
            ("og:image",       "og_image"),
        ]:
            m = re.search(
                rf'<meta\s+(?:property|name)=["\']({re.escape(prop)})["\'][^>]*content=["\']([^"\']*)["\']',
                html,
                re.IGNORECASE,
            )
            if not m:
                m = re.search(
                    rf'<meta\s+content=["\']([^"\']*)["\'][^>]*(?:property|name)=["\']({re.escape(prop)})["\']',
                    html,
                    re.IGNORECASE,
                )
                if m:
                    out[key] = m.group(1).strip()
                continue
            out[key] = m.group(2).strip()
        return out

    def _parse_nitter_profile(self, html, username):
        """Pull structured fields from Nitter's HTML markup."""
        prof = {
            "display_name": None,
            "bio": None,
            "location": None,
            "website": None,
            "join_date": None,
            "followers": None,
            "following": None,
            "tweets_count": None,
            "verified": False,
            "profile_image": None,
        }

        # Display name: <a class="profile-card-fullname" ...>NAME</a>
        m = re.search(
            r'class="profile-card-fullname"[^>]*>(.*?)</a>',
            html, re.DOTALL | re.IGNORECASE,
        )
        if m:
            prof["display_name"] = re.sub(r"<[^>]+>", "", m.group(1)).strip()

        # Bio: <div class="profile-bio"><p>BIO</p></div>
        m = re.search(
            r'class="profile-bio"[^>]*>.*?<p>(.*?)</p>',
            html, re.DOTALL | re.IGNORECASE,
        )
        if m:
            prof["bio"] = re.sub(r"<[^>]+>", "", m.group(1)).strip()

        # Location
        m = re.search(
            r'class="profile-location"[^>]*>.*?<span>(.*?)</span>',
            html, re.DOTALL | re.IGNORECASE,
        )
        if m:
            loc = re.sub(r"<[^>]+>", "", m.group(1)).strip()
            if loc:
                prof["location"] = loc

        # Website: first <a> inside profile-website
        m = re.search(
            r'class="profile-website"[^>]*>.*?href="([^"]+)"',
            html, re.DOTALL | re.IGNORECASE,
        )
        if m:
            prof["website"] = m.group(1).strip()

        # Join date: title attribute on profile-joindate span/div
        m = re.search(
            r'class="profile-joindate"[^>]*>.*?title="([^"]+)"',
            html, re.DOTALL | re.IGNORECASE,
        )
        if m:
            prof["join_date"] = m.group(1).strip()

        # Stats: followers, following, tweets — each in a .profile-stat-num
        # Nitter renders them in a consistent order inside a .profile-statlist
        stat_nums = re.findall(
            r'class="profile-stat-num"[^>]*>([\d,\.KMB]+)',
            html, re.IGNORECASE,
        )
        # Order in Nitter HTML: Tweets, Following, Followers, Likes
        _stat_labels = ["tweets_count", "following", "followers"]
        for i, val in enumerate(stat_nums[:3]):
            key = _stat_labels[i]
            prof[key] = val.strip()

        # Verified: presence of "verified-icon" or "verified" class near the name
        if re.search(r'class="[^"]*verified[^"]*"', html, re.IGNORECASE):
            prof["verified"] = True

        # Profile image from og:image is set by caller; also try avatar URL
        m = re.search(
            r'class="[^"]*profile-card-avatar[^"]*".*?<img[^>]+src="([^"]+)"',
            html, re.DOTALL | re.IGNORECASE,
        )
        if m:
            prof["profile_image"] = m.group(1).strip()

        return prof

    def _parse_og_profile(self, meta, username):
        """Build a minimal profile from og: tags alone (Nitter fallback)."""
        og_title = (meta.get("og_title") or "").strip()
        # Nitter formats og:title as "Display Name (@username) / Nitter"
        display_name = None
        m = re.match(r"^(.+?)\s*\(@?[A-Za-z0-9_]+\)", og_title)
        if m:
            display_name = m.group(1).strip()
        elif og_title and "nitter" not in og_title.lower():
            display_name = og_title

        return {
            "display_name": display_name,
            "bio": meta.get("og_description") or None,
            "location": None,
            "website": None,
            "join_date": None,
            "followers": None,
            "following": None,
            "tweets_count": None,
            "verified": False,
            "profile_image": meta.get("og_image") or None,
        }

    def _fetch_oembed(self, username, warnings):
        """Twitter oembed (no auth). Returns dict with author_name/author_url."""
        url = (
            "https://publish.twitter.com/oembed"
            f"?url=https%3A%2F%2Ftwitter.com%2F{username}"
        )
        try:
            resp = http.get(url, timeout=10)
            if resp.status_code == 200 and resp.text:
                try:
                    data = json.loads(resp.text)
                    return {
                        "author_name": data.get("author_name"),
                        "author_url": data.get("author_url"),
                        "html": data.get("html"),
                    }
                except (ValueError, TypeError):
                    pass
            elif resp.status_code == 404:
                return {"not_found": True}
        except Exception as exc:
            warnings.append(f"oembed fetch error: {exc}")
        return {}

    # ------------------------------------------------------------------ pivots

    def _probe_variation(self, candidate, base_username, warnings):
        """Probe a single username variation against Nitter. Return hit or None."""
        _, status, html, _ = self._fetch_nitter(candidate, warnings)
        if status != 200 or not html:
            return None

        meta = self._parse_meta(html)
        prof = self._parse_nitter_profile(html, candidate)

        # Merge og: fallback into profile where fields are missing
        if not prof["display_name"]:
            og_prof = self._parse_og_profile(meta, candidate)
            prof["display_name"] = og_prof.get("display_name")
        if not prof["profile_image"] and meta.get("og_image"):
            prof["profile_image"] = meta["og_image"]

        # Accuracy > false positives: require display_name as a minimum signal
        if not prof.get("display_name"):
            return None

        sim = round(SequenceMatcher(
            None, base_username.lower(), candidate.lower()).ratio(), 3)
        hit = {
            "username": candidate,
            "url": f"https://twitter.com/{candidate}",
            "display_name": prof.get("display_name"),
            "bio": (prof.get("bio") or "")[:200],
            "followers": prof.get("followers"),
            "verified": prof.get("verified", False),
            "similarity": sim,
        }
        hit["confidence_tier"] = confidence_tier(sim)
        hit["is_verified_as_target"] = False
        hit["verification_hints"] = _verification_hints_twitter(hit)
        return hit

    def _search_variations(self, username, max_variations, warnings):
        if not _VARIATIONS_OK:
            return [], []
        raw = generate_variations(username, max_variations * 2)
        cleaned, seen = [], set()
        for v in raw:
            v = (v or "").strip()
            if not _TWITTER_USERNAME_RE.match(v):
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
        if not _TWITTER_USERNAME_RE.match(username or ""):
            print_status(
                f"Invalid Twitter username '{username}' "
                "(1-50 chars, alphanumeric + underscore only)",
                "error",
            )
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Twitter/X OSINT: @{username}")
        print(f"{'='*58}{Colors.RESET}\n")

        warnings = []

        # --------------------------------------------------------- 1) Nitter scrape
        print_status("Trying Nitter mirrors...", "info")
        nitter_instance, nitter_status, nitter_html, nitter_reachable = \
            self._fetch_nitter(username, warnings)

        profile = {}
        nitter_source = None
        direct_hit = False

        if nitter_status == 200 and nitter_html:
            nitter_source = nitter_instance
            print_status(f"Hit via {nitter_instance}", "success")
            meta = self._parse_meta(nitter_html)
            profile = self._parse_nitter_profile(nitter_html, username)

            # Fill blanks from og: meta
            if not profile.get("display_name"):
                og_prof = self._parse_og_profile(meta, username)
                profile["display_name"] = og_prof.get("display_name")
                profile["bio"] = profile.get("bio") or og_prof.get("bio")
            if not profile.get("profile_image") and meta.get("og_image"):
                profile["profile_image"] = meta["og_image"]

            direct_hit = bool(profile.get("display_name"))

            if profile.get("display_name"):
                print_status(f"Display name: {profile['display_name']}", "success")
            if profile.get("bio"):
                print_status(f"Bio: {profile['bio'][:120]}", "info")
            if profile.get("location"):
                print_status(f"Location: {profile['location']}", "info")
            if profile.get("website"):
                print_status(f"Website: {profile['website']}", "info")
            if profile.get("join_date"):
                print_status(f"Joined: {profile['join_date']}", "info")
            if profile.get("followers"):
                print_status(f"Followers: {profile['followers']}", "success")
            if profile.get("following"):
                print_status(f"Following: {profile['following']}", "info")
            if profile.get("tweets_count"):
                print_status(f"Tweets: {profile['tweets_count']}", "info")
            if profile.get("verified"):
                print_status("Verified badge: yes", "success")
        else:
            print_status(
                "All Nitter mirrors failed or returned not-found",
                "warning",
            )

        # --------------------------------------------------------- 2) oembed fallback
        print_status("Trying Twitter oembed...", "info")
        oembed = self._fetch_oembed(username, warnings)
        oembed_hit = bool(oembed.get("author_name") or oembed.get("author_url"))

        if oembed.get("not_found"):
            print_status("oembed: user not found (404)", "warning")
        elif oembed_hit:
            print_status(
                f"oembed: author_name={oembed.get('author_name')} "
                f"url={oembed.get('author_url')}",
                "success",
            )
            direct_hit = True
            # Backfill display_name from oembed if nitter missed it
            if not profile.get("display_name") and oembed.get("author_name"):
                profile["display_name"] = oembed["author_name"]
        else:
            print_status("oembed: no data returned", "info")

        # --------------------------------------------------------- 3) bio pivot
        bio_blob = " ".join(filter(None, [
            profile.get("bio") or "",
            profile.get("display_name") or "",
        ]))
        bio_handles = self._bio_pivots(bio_blob)
        if bio_handles:
            parts = [f"{k}:{len(v)}" for k, v in bio_handles.items() if v]
            if parts:
                print_status(f"Bio pivots - {', '.join(parts)}", "success")

        # --------------------------------------------------------- 4) variations
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(
                f"Probing up to {max_variations} username variations...", "info")
            variations_tried, candidates = self._search_variations(
                username, max_variations, warnings)
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
                        " (same spelling — Twitter handles change frequently; "
                        "verify before acting)"
                    )
                print_status(
                    f"[CANDIDATE/{tier}]  -> @{c['username']} "
                    f"(sim={c['similarity']}) "
                    f"{(c.get('display_name') or '')[:50]}"
                    f"{note}  — NOT CONFIRMED",
                    severity,
                )
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping pivot",
                "warning",
            )

        # ------------------------------------------------------------- results
        source = nitter_source or ("oembed" if oembed_hit else "none")
        self.results = {
            "username": username,
            "profile_url": f"https://twitter.com/{username}",
            "display_name": profile.get("display_name"),
            "bio": profile.get("bio"),
            "location": profile.get("location"),
            "website": profile.get("website"),
            "join_date": profile.get("join_date"),
            "followers": profile.get("followers"),
            "following": profile.get("following"),
            "tweets_count": profile.get("tweets_count"),
            "verified": profile.get("verified", False),
            "profile_image": profile.get("profile_image"),
            "oembed": oembed if oembed_hit else {},
            "bio_handles": bio_handles,
            "candidates": candidates,
            "variations_tried": variations_tried,
            "warnings": warnings,
            "direct_hit": direct_hit,
            "source": source,
        }
        self.results["disclaimer"] = build_disclaimer("Twitter/X", len(candidates))

        # All Nitter mirrors 429'd/errored (none reachable) AND oembed returned
        # no data and no clean 404 => the lookup FAILED. This must not read as
        # direct_hit:False ("user not found"); it is inconclusive.
        nitter_failed = (nitter_status != 200) and not nitter_reachable
        oembed_failed = (not oembed_hit) and not oembed.get("not_found")
        direct_fetch_failed = (not direct_hit) and nitter_failed and oembed_failed
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status("Direct lookup INCONCLUSIVE - all Nitter mirrors blocked/"
                         "rate-limited and oembed returned nothing; this is NOT "
                         "evidence the account is absent", "warning")

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: @{username}")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  Link:         https://twitter.com/{username}")
        print(f"  Direct hit:   {'yes' if direct_hit else 'no'}")
        if nitter_source:
            print(f"  Nitter:       {nitter_source}")
        if profile.get("display_name"):
            print(f"  Display name: {profile['display_name']}")
        if profile.get("location"):
            print(f"  Location:     {profile['location']}")
        if profile.get("join_date"):
            print(f"  Joined:       {profile['join_date']}")
        if profile.get("followers"):
            print(f"  Followers:    {profile['followers']}")
        if profile.get("following"):
            print(f"  Following:    {profile['following']}")
        if profile.get("tweets_count"):
            print(f"  Tweets:       {profile['tweets_count']}")
        if profile.get("verified"):
            print(f"  Verified:     yes")
        if profile.get("website"):
            print(f"  Website:      {profile['website']}")
        if profile.get("profile_image"):
            print(f"  Avatar:       {profile['profile_image']}")
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
            print_uncertainty_box("Twitter/X", _verification_hints_twitter({}))

        return True
