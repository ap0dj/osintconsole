"""Reddit OSINT - public profile lookup via JSON API (no auth required).

Reddit exposes a fully public JSON API at /user/{username}/about.json,
/submitted.json, and /comments.json - no authentication needed, just
an appropriate User-Agent header to avoid the default UA block.

Data collected:
  * Account metadata: karma, age, gold, moderator status, email-verified
  * Profile subreddit: bio, subscriber count, public description
  * Top submitted posts (up to 5)
  * Recent comments (up to 5)
  * Subreddit fingerprint: unique communities the account is active in
  * Bio handle pivot via extract_handles_from_bio()
  * Username variation probing (optional)
"""

import re
import time
import datetime
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


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,20}$")
_REDDIT_UA = "OsintConsole/1.0"


def _utc_to_date(ts):
    """Convert a Unix timestamp to ISO 8601 date string."""
    try:
        return datetime.datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None


def _account_age_days(ts):
    """Return age in days from Unix timestamp."""
    try:
        created = datetime.datetime.utcfromtimestamp(float(ts))
        now = datetime.datetime.utcnow()
        return max(0, (now - created).days)
    except Exception:
        return None


def _verification_hints_reddit(candidate):
    """Manual verification checks for a Reddit candidate."""
    return [
        "Reddit account age and karma history should align with target's known online presence",
        "Subreddit activity pattern (communities they post in) is a strong interest fingerprint",
        "Cross-reference username with target's known handles on other platforms",
        "Comment writing style, vocabulary and timezone hints can confirm or rule out identity",
        "Shadowbanned accounts return 404 - absence of data doesn't mean account doesn't exist",
    ]


class RedditOsint(BaseModule):
    name = "harvest/reddit_osint"
    description = "Reddit public profile OSINT via JSON API (no auth required)"
    category = "harvest"
    target_type = "username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Reddit username (with or without u/)")
        self.add_option("VARIATIONS", "true", False,
                        "Probe username variations against Reddit about.json")
        self.add_option("MAX_VARIATIONS", "15", False,
                        "Max variations to probe")

    # ------------------------------------------------------------------ helpers

    def _clean(self, username):
        """Strip u/ prefix and full Reddit URL down to just the username."""
        username = (username or "").strip()
        username = re.sub(r"^/?u/", "", username, flags=re.IGNORECASE)
        username = re.sub(r"https?://(www\.)?reddit\.com/u(ser)?/", "", username,
                          flags=re.IGNORECASE)
        return username.strip("/").split("?")[0].strip()

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

    def _reddit_get(self, url, params=None):
        """Wrapper for Reddit JSON API with the required User-Agent header."""
        try:
            resp = http.get(
                url,
                params=params,
                headers={"User-Agent": _REDDIT_UA},
                timeout=12,
            )
            return resp
        except Exception as exc:
            self._warn.append(f"HTTP error ({url}): {exc}")
            return None

    def _safe_json(self, resp):
        if resp is None or resp.status_code >= 400:
            return None
        try:
            return resp.json()
        except Exception:
            return None

    # ------------------------------------------------------------------ fetchers

    def _fetch_about(self, username):
        """Fetch /user/{username}/about.json - returns (data dict or None, status_str)."""
        resp = self._reddit_get(f"https://www.reddit.com/user/{username}/about.json")
        if resp is None:
            return None, "error"
        if resp.status_code == 404:
            return None, "not_found"
        if resp.status_code == 403:
            return None, "suspended"
        if resp.status_code == 429:
            self._warn.append("Reddit about.json rate-limited (429)")
            return None, "rate_limited"
        if resp.status_code != 200:
            return None, f"status:{resp.status_code}"
        data = self._safe_json(resp)
        if not isinstance(data, dict):
            return None, "bad_json"
        inner = data.get("data") or {}
        kind = data.get("kind")
        if kind != "t2" and not inner.get("name"):
            return None, "unexpected_shape"
        return inner, "ok"

    def _fetch_submitted(self, username):
        """Fetch top 10 submitted posts; return list of up to 5 dicts."""
        time.sleep(1)
        resp = self._reddit_get(
            f"https://www.reddit.com/user/{username}/submitted.json",
            params={"limit": 10},
        )
        if resp is None or resp.status_code != 200:
            if resp is not None and resp.status_code == 429:
                self._warn.append("Reddit submitted.json rate-limited (429)")
            return []
        data = self._safe_json(resp)
        if not isinstance(data, dict):
            return []
        posts = []
        for child in ((data.get("data") or {}).get("children") or []):
            post = (child or {}).get("data") or {}
            if not isinstance(post, dict):
                continue
            posts.append({
                "title": (post.get("title") or "")[:200],
                "subreddit": post.get("subreddit"),
                "score": post.get("score"),
                "url": post.get("url"),
                "created_utc": _utc_to_date(post.get("created_utc")),
            })
            if len(posts) >= 5:
                break
        return posts

    def _fetch_comments(self, username):
        """Fetch recent 10 comments; return list of up to 5 dicts."""
        time.sleep(1)
        resp = self._reddit_get(
            f"https://www.reddit.com/user/{username}/comments.json",
            params={"limit": 10},
        )
        if resp is None or resp.status_code != 200:
            if resp is not None and resp.status_code == 429:
                self._warn.append("Reddit comments.json rate-limited (429)")
            return []
        data = self._safe_json(resp)
        if not isinstance(data, dict):
            return []
        comments = []
        for child in ((data.get("data") or {}).get("children") or []):
            comment = (child or {}).get("data") or {}
            if not isinstance(comment, dict):
                continue
            body = (comment.get("body") or "")[:100]
            comments.append({
                "body": body,
                "subreddit": comment.get("subreddit"),
                "score": comment.get("score"),
            })
            if len(comments) >= 5:
                break
        return comments

    # --------------------------------------------------------------- variations

    def _probe_variation(self, candidate):
        """Check whether a username variant exists on Reddit via about.json.
        Returns a candidate dict on 200, None otherwise."""
        time.sleep(0.5)
        resp = self._reddit_get(
            f"https://www.reddit.com/user/{candidate}/about.json"
        )
        if resp is None:
            return None
        if resp.status_code == 429:
            self._warn.append(f"variation probe rate-limited (429) for {candidate}")
            return None
        if resp.status_code == 200:
            data = self._safe_json(resp) or {}
            inner = data.get("data") or {}
            return {
                "username": candidate,
                "exists": True,
                "karma": inner.get("total_karma"),
                "url": f"https://www.reddit.com/u/{candidate}/",
            }
        return None

    def _search_variations(self, username, max_variations):
        """Generate and probe username variations against Reddit."""
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
            hit = self._probe_variation(v)
            if hit:
                sim = round(SequenceMatcher(None, username.lower(), v.lower()).ratio(), 3)
                hit["similarity"] = sim
                hit["confidence_tier"] = confidence_tier(sim)
                hit["is_verified_as_target"] = False
                hit["verification_hints"] = _verification_hints_reddit(hit)
                candidates.append(hit)
        candidates.sort(key=lambda c: c.get("similarity", 0), reverse=True)
        return cleaned, candidates

    # --------------------------------------------------------------------- run

    def run(self):
        if not self.validate():
            return False

        username = self._clean(self.get_option("TARGET"))
        if not username:
            print_status("TARGET resolved to empty username", "error")
            return False

        if not _USERNAME_RE.match(username):
            print_status(
                f"Username '{username}' doesn't match Reddit rules "
                "(3-20 chars, alphanumeric + underscore + hyphen)", "error")
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))

        self._warn = []

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Reddit OSINT: u/{username}")
        print(f"{'='*58}{Colors.RESET}\n")

        # 1) About (account metadata)
        print_status("Fetching Reddit about.json...", "info")
        about, status = self._fetch_about(username)

        if status == "not_found":
            print_status(
                "Reddit returned 404 - username not found or shadowbanned "
                "(shadowbanned accounts also return 404)", "warning")
        elif status == "suspended":
            print_status("Account suspended (403)", "warning")
        elif status == "rate_limited":
            print_status("Rate limited (429) - try again shortly", "warning")
        elif status != "ok":
            print_status(f"about.json status: {status}", "warning")

        profile = {}
        if about:
            created_ts = about.get("created_utc") or about.get("created")
            total_karma = (
                about.get("total_karma")
                or ((about.get("comment_karma") or 0) + (about.get("link_karma") or 0))
            )
            profile = {
                "name": about.get("name"),
                "id": about.get("id"),
                "created_date": _utc_to_date(created_ts),
                "account_age_days": _account_age_days(created_ts),
                "comment_karma": about.get("comment_karma"),
                "link_karma": about.get("link_karma"),
                "total_karma": total_karma,
                "is_gold": bool(about.get("is_gold")),
                "is_mod": bool(about.get("is_mod")),
                "has_verified_email": bool(about.get("has_verified_email")),
                "verified": bool(about.get("verified")),
                "icon_img": about.get("icon_img"),
            }
            # Profile subreddit is Reddit's meta-subreddit for the user's own profile page
            subreddit = about.get("subreddit")
            if isinstance(subreddit, dict):
                profile["bio"] = subreddit.get("public_description") or ""
                profile["display_name"] = subreddit.get("display_name")
                profile["profile_subscribers"] = subreddit.get("subscribers")
            else:
                profile["bio"] = ""
                profile["display_name"] = None
                profile["profile_subscribers"] = None

            print_status(
                f"Account found: total_karma={total_karma}  "
                f"age={profile.get('account_age_days')} days  "
                f"gold={profile.get('is_gold')}  mod={profile.get('is_mod')}",
                "success")

        # 2) Top submitted posts
        top_posts = []
        if about:
            print_status("Fetching submitted posts...", "info")
            top_posts = self._fetch_submitted(username)
            print_status(f"Collected {len(top_posts)} post(s)",
                         "success" if top_posts else "info")

        # 3) Recent comments
        recent_comments = []
        if about:
            print_status("Fetching recent comments...", "info")
            recent_comments = self._fetch_comments(username)
            print_status(f"Collected {len(recent_comments)} comment(s)",
                         "success" if recent_comments else "info")

        # 4) Subreddit fingerprint - unique communities active in
        subreddit_fingerprint = sorted(set(filter(None, [
            *[p.get("subreddit") for p in top_posts],
            *[c.get("subreddit") for c in recent_comments],
        ])))
        if subreddit_fingerprint:
            print_status(
                f"Subreddit fingerprint: {', '.join(subreddit_fingerprint[:10])}", "info")

        # 5) Bio handle pivot
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

        # 6) Username variations
        variations_tried, candidates = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(f"Probing up to {max_variations} username variations...", "info")
            variations_tried, candidates = self._search_variations(username, max_variations)
            print_status(
                f"Tried {len(variations_tried)}, "
                f"{len(candidates)} candidate hit(s) (NOT confirmed as target)",
                "success" if candidates else "info")
            for c in candidates[:10]:
                tier = c.get("confidence_tier", "very-low")
                sev = "warning" if tier in ("medium", "low", "very-low") else "success"
                print_status(
                    f"  [CANDIDATE/{tier}] -> u/{c['username']} "
                    f"sim={c.get('similarity')} karma={c.get('karma')} - NOT CONFIRMED",
                    sev)
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping variation pivot",
                "warning")

        # ------------------------------------------------------------- results
        self.results = {
            "username": username,
            "profile_url": f"https://www.reddit.com/u/{username}/",
            "id": profile.get("id"),
            "created_date": profile.get("created_date"),
            "account_age_days": profile.get("account_age_days"),
            "comment_karma": profile.get("comment_karma"),
            "link_karma": profile.get("link_karma"),
            "total_karma": profile.get("total_karma"),
            "is_gold": profile.get("is_gold"),
            "is_mod": profile.get("is_mod"),
            "verified": profile.get("verified"),
            "profile_image": profile.get("icon_img"),
            "bio": profile.get("bio"),
            "bio_handles": bio_handles,
            "top_posts": top_posts,
            "recent_comments": recent_comments,
            "subreddit_fingerprint": subreddit_fingerprint,
            "candidates": [
                {
                    "username": c["username"],
                    "exists": True,
                    "similarity": c.get("similarity"),
                    "confidence_tier": c.get("confidence_tier",
                                             confidence_tier(c.get("similarity", 0.0))),
                    "karma": c.get("karma"),
                    "url": c.get("url"),
                    "is_verified_as_target": False,
                    "verification_hints": (
                        c.get("verification_hints")
                        or _verification_hints_reddit(c)
                    ),
                }
                for c in candidates
            ],
            "warnings": self._warn,
            "source": "reddit.com JSON API (public, no auth required)",
            "disclaimer": build_disclaimer("Reddit", len(candidates)),
        }

        # 404 (not_found) and 403 (suspended) are definitive answers from Reddit;
        # a network error, a 429, bad JSON, or an unexpected status means the
        # about.json fetch FAILED and must not read as "account does not exist".
        _fail_states = ("error", "rate_limited", "bad_json", "unexpected_shape")
        direct_fetch_failed = (not about) and (
            status in _fail_states or str(status).startswith("status:"))
        self.results["fetch_failed"] = direct_fetch_failed
        if direct_fetch_failed:
            self.results["error"] = "fetch_failed"
            print_status("Direct lookup INCONCLUSIVE - Reddit blocked/unreachable "
                         f"({status}); this is NOT evidence the account is absent",
                         "warning")

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: u/{username}")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  Profile URL:  https://www.reddit.com/u/{username}/")

        if about:
            print(f"  Account:      found")
            if profile.get("created_date"):
                print(f"  Created:      {profile['created_date']}  "
                      f"({profile.get('account_age_days')} days ago)")
            if profile.get("total_karma") is not None:
                print(f"  Karma:        {profile['total_karma']}  "
                      f"(comment={profile.get('comment_karma')}  "
                      f"link={profile.get('link_karma')})")
            flags = []
            if profile.get("is_gold"):             flags.append("gold")
            if profile.get("is_mod"):              flags.append("mod")
            if profile.get("verified"):            flags.append("verified")
            if profile.get("has_verified_email"):  flags.append("email-verified")
            if flags:
                print(f"  Flags:        {', '.join(flags)}")
            if profile.get("bio"):
                print(f"  Bio:          {profile['bio'][:120]}")
            if profile.get("icon_img"):
                print(f"  Avatar:       {profile['icon_img'][:70]}")
        else:
            print(f"  Account:      {Colors.YELLOW}not found / shadowbanned / "
                  f"suspended{Colors.RESET}")

        if subreddit_fingerprint:
            print(f"  Subreddits:   {', '.join(subreddit_fingerprint[:8])}")
        if bio_handles:
            parts = [f"{k}:{len(v)}" for k, v in bio_handles.items() if v]
            if parts:
                print(f"  Bio handles:  {', '.join(parts)}")

        print(f"  Posts shown:  {len(top_posts)}    "
              f"Comments shown: {len(recent_comments)}")
        print(f"  Candidates:   {len(candidates)} (from {len(variations_tried)} tried)")

        if self._warn:
            print(f"  {Colors.DIM}{len(self._warn)} warning(s): "
                  f"{'; '.join(self._warn[:3])}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        if candidates:
            print_uncertainty_box("Reddit", _verification_hints_reddit({}))

        return True
