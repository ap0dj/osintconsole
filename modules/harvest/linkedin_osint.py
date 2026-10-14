"""LinkedIn OSINT - public profile scrape via og: meta tags + Google dork builder.

LinkedIn actively blocks most scraping. Public profiles expose og: meta tags
in HTML returned before the login wall fires. We extract whatever we can and
build Google dork URLs for manual follow-up.

Strategy:
  * Fetch https://www.linkedin.com/in/{username}/ with a browser-like UA
  * Parse og:title  -> display name + headline ("Name - Title at Company")
  * Parse og:description -> profile summary text
  * Parse og:image  -> profile picture URL
  * Build Google dork URLs (never fetched - manual use only)
  * Detect status: public (og:title contains real name), private (999 / authwall),
    not_found (404)
  * Extract handles from og:description + og:title via extract_handles_from_bio()
  * Optionally build variation dork URLs via username_variations
"""

import re

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


_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

_AUTHWALL_MARKERS = (
    "authwall",
    "join now to see",
    "sign in",
    "join linkedin",
    "be the first to see",
    "you need to sign in",
)


def _og(html, prop):
    """Extract a single og: meta tag value from HTML. Tries both attribute orders."""
    if not html:
        return None
    # property="..." content="..."
    m = re.search(
        rf'<meta[^>]+property=["\']?{re.escape(prop)}["\']?[^>]+content=["\']([^"\']*)["\']',
        html, re.IGNORECASE | re.DOTALL)
    if not m:
        # content="..." property="..."
        m = re.search(
            rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+property=["\']?{re.escape(prop)}["\']?',
            html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else None


def _parse_og_title(title):
    """Split 'Full Name - Job Title at Company' or 'Full Name | Headline' into
    (display_name, headline). Also strips the trailing '| LinkedIn' suffix."""
    if not title:
        return None, None
    # Strip trailing "| LinkedIn" or "- LinkedIn"
    title = re.sub(r"\s*[\|\-]\s*LinkedIn\s*$", "", title, flags=re.IGNORECASE).strip()
    if " - " in title:
        parts = title.split(" - ", 1)
        return parts[0].strip() or None, parts[1].strip() or None
    if " | " in title:
        parts = title.split(" | ", 1)
        return parts[0].strip() or None, parts[1].strip() or None
    return title.strip() or None, None


def _is_login_wall(html):
    """Heuristic: did LinkedIn serve a login/signup wall instead of a real profile?
    Returns True if it looks like a wall, False if we have usable profile data."""
    if not html:
        return True
    low = html.lower()
    # If we have an og:title that is clearly NOT a generic LinkedIn page title,
    # we almost certainly have a real profile even if some wall content is present.
    og_title = _og(html, "og:title") or ""
    if og_title:
        # A real profile title contains a name and usually a dash or pipe separator
        cleaned = re.sub(r"\s*[\|\-]\s*linkedin\s*$", "", og_title, flags=re.IGNORECASE)
        if " - " in cleaned or " | " in cleaned or len(cleaned) >= 5:
            # Has a separator -> looks like "Name - Headline" -> real profile content
            return False
    return any(m in low for m in _AUTHWALL_MARKERS)


def _verification_hints_linkedin(candidate):
    """Manual verification checks for a LinkedIn candidate."""
    return [
        "LinkedIn og:title format is 'Full Name - Job Title at Company' - verify both name and role",
        "Profile picture comparison is highly reliable for identity confirmation",
        "Use the Google dork URLs to find the profile via search engine cache if direct access fails",
        "LinkedIn vanity URLs can be changed - the current URL may not be the original",
        "A 999 response means the profile exists but is not publicly accessible - try via Google cache",
    ]


class LinkedinOsint(BaseModule):
    name = "harvest/linkedin_osint"
    description = "LinkedIn public profile OSINT via og: meta scrape + Google dork"
    category = "harvest"
    target_type = "username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "LinkedIn vanity URL slug or full linkedin.com/in/... URL")
        self.add_option("VARIATIONS", "true", False,
                        "Build Google dork URLs for username variations (no live probing)")
        self.add_option("MAX_VARIATIONS", "15", False,
                        "Max variations to generate dork URLs for")

    # ------------------------------------------------------------------ helpers

    def _clean(self, username):
        """Strip full LinkedIn URL down to just the vanity slug."""
        username = (username or "").strip()
        username = re.sub(
            r"https?://(www\.)?linkedin\.com/in/", "", username, flags=re.IGNORECASE)
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

    # ------------------------------------------------------------------ fetchers

    def _fetch_profile(self, username):
        """Fetch the LinkedIn profile page.
        Returns (html_text_or_None, status_str).

        Status strings:
          ok              - 200 with usable content
          blocked_999     - LinkedIn's soft-block; profile exists but private
          authwall        - got a wall response (200 or redirect)
          authwall_redirect - redirected to /authwall or /login
          not_found       - 404
          error           - network / exception
        """
        url = f"https://www.linkedin.com/in/{username}/"
        try:
            resp = http.get(
                url,
                allow_redirects=True,
                headers={
                    "User-Agent": _BROWSER_UA,
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept": (
                        "text/html,application/xhtml+xml,"
                        "application/xml;q=0.9,*/*;q=0.8"
                    ),
                },
                timeout=15,
            )
        except Exception as exc:
            self._warn.append(f"LinkedIn fetch error: {exc}")
            return None, "error"

        if resp.status_code == 404:
            return None, "not_found"

        if resp.status_code == 999:
            # LinkedIn uses 999 to soft-block automated requests; profile likely exists
            html = resp.text or ""
            return html or None, "blocked_999"

        if resp.status_code in (401, 403):
            html = resp.text or ""
            return html or None, "authwall"

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = (resp.headers.get("Location")
                   or resp.headers.get("location") or "").lower()
            if "authwall" in loc or "login" in loc or "signup" in loc or "checkpoint" in loc:
                return None, "authwall_redirect"
            return None, f"redirect:{loc[:80]}"

        if resp.status_code != 200:
            return None, f"status:{resp.status_code}"

        html = resp.text or ""
        # Even on 200, LinkedIn sometimes serves a redirect via HTML / JS
        final_url = ""
        try:
            final_url = resp.url or ""
        except Exception:
            pass
        if "authwall" in final_url.lower() or "login" in final_url.lower():
            return html or None, "authwall_redirect"

        return html, "ok"

    # --------------------------------------------------------------- dork builders

    def _build_dork_urls(self, username, extra_terms=None):
        """Build Google dork URLs for manual use (never fetched automatically)."""
        dorks = [
            f'https://www.google.com/search?q=site:linkedin.com/in/ "{username}"',
            f'https://www.google.com/search?q=site:linkedin.com "{username}" profile',
        ]
        if extra_terms:
            for term in extra_terms[:3]:
                term = (term or "").strip()
                if term and len(term) >= 3:
                    dorks.append(
                        f'https://www.google.com/search?q=site:linkedin.com/in/ "{term}"'
                    )
        return dorks

    # --------------------------------------------------------------- variations

    def _variation_dorks(self, username, max_variations):
        """Generate variation slugs and their corresponding dork URLs.
        No live network probing - purely dork-URL building for manual follow-up."""
        raw = generate_variations(username, max_variations * 2)
        slugified, seen = [], set()
        for v in raw:
            v = re.sub(r"[^A-Za-z0-9\-]", "-", (v or "")).strip("-")
            v = re.sub(r"-{2,}", "-", v)
            if (v
                    and len(v) >= 3
                    and v.lower() != username.lower()
                    and v.lower() not in seen):
                seen.add(v.lower())
                slugified.append(v)
            if len(slugified) >= max_variations:
                break
        dorks = [
            f'https://www.google.com/search?q=site:linkedin.com/in/ "{v}"'
            for v in slugified
        ]
        return slugified, dorks

    # --------------------------------------------------------------------- run

    def run(self):
        if not self.validate():
            return False

        username = self._clean(self.get_option("TARGET"))
        if not username:
            print_status("TARGET resolved to empty username/slug", "error")
            return False

        do_variations = self._bool_opt("VARIATIONS", True)
        max_variations = max(1, self._int_opt("MAX_VARIATIONS", 15))

        self._warn = []

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  LinkedIn OSINT: {username}")
        print(f"{'='*58}{Colors.RESET}\n")

        profile_url = f"https://www.linkedin.com/in/{username}/"

        # 1) Fetch profile page
        print_status("Fetching LinkedIn profile page...", "info")
        html, page_status = self._fetch_profile(username)

        display_name = None
        headline = None
        summary = None
        profile_image = None
        og_url_val = None
        status_label = "unknown"

        if page_status == "ok" and html:
            og_title = _og(html, "og:title") or ""
            og_desc = _og(html, "og:description")
            og_image = _og(html, "og:image")
            og_url_val = _og(html, "og:url")

            is_wall = _is_login_wall(html)
            if og_title and not is_wall:
                display_name, headline = _parse_og_title(og_title)
                summary = og_desc
                profile_image = og_image
                status_label = "public"
                print_status(f"Public profile found: {og_title}", "success")
                if og_desc:
                    print_status(f"Summary: {og_desc[:120]}", "info")
            elif og_title and is_wall:
                # 200 but got a login wall - still try to extract what we can
                display_name, headline = _parse_og_title(og_title)
                profile_image = og_image
                status_label = "private"
                print_status(
                    "Got 200 but LinkedIn served a login wall - "
                    "profile exists but is gated", "warning")
                if display_name:
                    print_status(f"Partial data from og:title: {og_title}", "info")
            else:
                status_label = "private"
                print_status(
                    "Could not extract profile data from the response - "
                    "LinkedIn is blocking anonymous access for this profile", "warning")

        elif page_status == "blocked_999":
            status_label = "private"
            print_status(
                "LinkedIn returned HTTP 999 - profile exists but is not "
                "publicly accessible (try via Google cache)", "warning")
            if html:
                og_title = _og(html, "og:title") or ""
                if og_title:
                    display_name, headline = _parse_og_title(og_title)
                    profile_image = _og(html, "og:image")
                    print_status(f"Partial data from 999 response: {og_title}", "info")

        elif page_status in ("authwall", "authwall_redirect"):
            status_label = "private"
            print_status(
                "LinkedIn redirected to authwall / login - profile likely exists "
                "but requires authentication to view", "warning")
            if html:
                og_title = _og(html, "og:title") or ""
                if og_title and not _is_login_wall(html):
                    display_name, headline = _parse_og_title(og_title)

        elif page_status == "not_found":
            status_label = "not_found"
            print_status("LinkedIn returned 404 - profile not found", "warning")

        elif page_status == "error":
            status_label = "error"
            print_status(
                "Network error while fetching LinkedIn profile - check connectivity",
                "warning")

        else:
            status_label = "unknown"
            print_status(f"Unexpected page status: {page_status}", "warning")

        # 2) Bio handle pivot
        bio_handles = {}
        bio_text = " ".join(filter(None, [display_name, headline, summary]))
        if _VARIATIONS_OK and bio_text:
            try:
                bio_handles = extract_handles_from_bio(bio_text) or {}
            except Exception:
                bio_handles = {}
        if bio_handles:
            counts = ", ".join(f"{k}:{len(v)}" for k, v in bio_handles.items() if v)
            if counts:
                print_status(f"Bio handles found: {counts}", "success")

        # 3) Google dork URLs (manual use only - never fetched by this module)
        extra_terms = []
        if display_name:
            extra_terms.append(display_name)
        google_dork_urls = self._build_dork_urls(username, extra_terms)
        print_status(
            f"Built {len(google_dork_urls)} Google dork URL(s) (manual use only)", "info")
        for dork in google_dork_urls[:2]:
            print_status(f"  {dork[:90]}", "info")

        # 4) Variation dorks (no live probing - just more dork URLs to follow up manually)
        variation_slugs, variation_dorks = [], []
        if do_variations and _VARIATIONS_OK:
            print_status(
                f"Building dork URLs for up to {max_variations} username variations...",
                "info")
            variation_slugs, variation_dorks = self._variation_dorks(
                username, max_variations)
            google_dork_urls.extend(variation_dorks)
            print_status(
                f"Added {len(variation_dorks)} variation dork URL(s)", "info")
        elif do_variations and not _VARIATIONS_OK:
            print_status(
                "username_variations module unavailable - skipping variation dorks",
                "warning")

        # Candidate entry for the exact slug when profile was found or exists
        candidates = []
        if status_label in ("public", "private"):
            sim = 1.0
            cand = {
                "username": username,
                "url": profile_url,
                "status": status_label,
                "display_name": display_name,
                "headline": headline,
                "similarity": sim,
                "confidence_tier": confidence_tier(sim),
                "is_verified_as_target": False,
                "verification_hints": _verification_hints_linkedin({}),
            }
            candidates.append(cand)

        # ------------------------------------------------------------- results
        self.results = {
            "username": username,
            "profile_url": profile_url,
            "status": status_label,
            "display_name": display_name,
            "headline": headline,
            "summary": summary,
            "profile_image": profile_image,
            "google_dork_urls": google_dork_urls,
            "bio_handles": bio_handles,
            "candidates": candidates,
            "warnings": self._warn,
            "source": "linkedin.com og: meta scrape (public, no auth) + Google dorks",
            "disclaimer": build_disclaimer("LinkedIn", len(candidates)),
        }

        # ------------------------------------------------------------- summary
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: {username}")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  Profile URL:  {profile_url}")

        status_color = {
            "public": Colors.GREEN,
            "private": Colors.YELLOW,
            "not_found": Colors.RED,
            "error": Colors.RED,
        }.get(status_label, Colors.DIM)
        print(f"  Status:       {status_color}{status_label}{Colors.RESET}")

        if display_name:
            print(f"  Name:         {display_name}")
        if headline:
            print(f"  Headline:     {headline[:100]}")
        if summary:
            print(f"  Summary:      {summary[:120]}")
        if profile_image:
            print(f"  Photo URL:    {profile_image[:70]}")
        if bio_handles:
            parts = [f"{k}:{len(v)}" for k, v in bio_handles.items() if v]
            if parts:
                print(f"  Bio handles:  {', '.join(parts)}")

        print(f"  Dork URLs:    {len(google_dork_urls)} built")
        print(f"\n  {Colors.YELLOW}Google dork URLs (paste into browser):{Colors.RESET}")
        for dork in google_dork_urls[:5]:
            print(f"    {dork}")
        if len(google_dork_urls) > 5:
            print(f"    ... and {len(google_dork_urls) - 5} more in self.results['google_dork_urls']")

        if self._warn:
            print(f"\n  {Colors.DIM}{len(self._warn)} warning(s): "
                  f"{'; '.join(self._warn[:3])}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        if status_label in ("public", "private"):
            print_uncertainty_box("LinkedIn", _verification_hints_linkedin({}))

        return True
