import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http


# method:
#   "status"        -> exists iff HTTP 200
#   "found_text"    -> exists iff 200 AND text present in body
#   "notfound_text" -> exists iff 200 AND text NOT in body
#   "json_notnull"  -> exists iff 200 AND body is not "null"/empty (firebase-style)
SITES = {
    "GitHub": {"url": "https://api.github.com/users/{u}", "method": "status"},
    "GitLab": {"url": "https://gitlab.com/{u}", "method": "status"},
    "Reddit": {"url": "https://www.reddit.com/user/{u}/about.json", "method": "status"},
    "HackerNews": {"url": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
                   "method": "json_notnull"},
    "Chess.com": {"url": "https://api.chess.com/pub/player/{u}", "method": "status"},
    "DevTo": {"url": "https://dev.to/api/users/by_username?url={u}", "method": "status"},
    "Keybase": {"url": "https://keybase.io/_/api/1.0/user/lookup.json?username={u}",
                "method": "found_text", "text": "\"them\""},
    "PyPI": {"url": "https://pypi.org/user/{u}/", "method": "status"},
    "NPM": {"url": "https://www.npmjs.com/~{u}", "method": "status"},
    "DockerHub": {"url": "https://hub.docker.com/v2/users/{u}/", "method": "status"},
    "Replit": {"url": "https://replit.com/@{u}", "method": "status"},
    "Gravatar": {"url": "https://gravatar.com/{u}.json", "method": "status"},
    "GitHubGist": {"url": "https://gist.github.com/{u}", "method": "status"},
    "Telegram": {"url": "https://t.me/{u}", "method": "found_text",
                 "text": "tgme_page_title"},
    "SoundCloud": {"url": "https://soundcloud.com/{u}", "method": "status"},
    "Vimeo": {"url": "https://vimeo.com/{u}", "method": "status"},
    "AboutMe": {"url": "https://about.me/{u}", "method": "status"},
    "Patreon": {"url": "https://www.patreon.com/{u}", "method": "status"},
    "Behance": {"url": "https://www.behance.net/{u}", "method": "status"},
    "Dribbble": {"url": "https://dribbble.com/{u}", "method": "status"},
    "Kaggle": {"url": "https://www.kaggle.com/{u}", "method": "status"},
    "Wordpress": {"url": "https://{u}.wordpress.com", "method": "status"},
    "Tumblr": {"url": "https://{u}.tumblr.com", "method": "status"},
    "Medium": {"url": "https://medium.com/@{u}", "method": "status"},
    "Codewars": {"url": "https://www.codewars.com/users/{u}", "method": "status"},
    "Wattpad": {"url": "https://www.wattpad.com/user/{u}", "method": "status"},
    "Twitch": {"url": "https://m.twitch.tv/{u}", "method": "status"},
    "Steam": {"url": "https://steamcommunity.com/id/{u}", "method": "notfound_text",
              "text": "The specified profile could not be found"},
    "Pinterest": {"url": "https://www.pinterest.com/{u}/", "method": "status"},
    "Flickr": {"url": "https://www.flickr.com/people/{u}", "method": "status"},

    # --- Developer / Code ---
    "Bitbucket": {"url": "https://bitbucket.org/{u}/", "method": "status"},
    "Launchpad": {"url": "https://launchpad.net/~{u}", "method": "status"},
    "SourceForge": {"url": "https://sourceforge.net/u/{u}/profile", "method": "status"},
    "Codeberg": {"url": "https://codeberg.org/{u}", "method": "status"},
    "AtCoder": {"url": "https://atcoder.jp/users/{u}", "method": "status"},
    "HackerRank": {"url": "https://www.hackerrank.com/profile/{u}", "method": "status"},
    "Codepen": {"url": "https://codepen.io/{u}", "method": "status"},
    "JSFiddle": {"url": "https://jsfiddle.net/user/{u}/", "method": "status"},

    # --- Social / Microblog ---
    "Mastodon": {"url": "https://mastodon.social/@{u}", "method": "status"},
    "Mstdn": {"url": "https://mstdn.social/@{u}", "method": "status"},
    "Bluesky": {"url": "https://bsky.app/profile/{u}.bsky.social", "method": "status"},
    "VK": {"url": "https://vk.com/{u}", "method": "notfound_text",
           "text": "Page not found"},

    # --- Content / Blog ---
    "Substack": {"url": "https://{u}.substack.com/", "method": "status"},
    "Hashnode": {"url": "https://hashnode.com/@{u}", "method": "status"},
    "Blogger": {"url": "https://{u}.blogspot.com/", "method": "status"},

    # --- Video / Streaming ---
    "YouTube": {"url": "https://www.youtube.com/@{u}", "method": "found_text",
                "text": "\"channelId\":"},
    "DailyMotion": {"url": "https://www.dailymotion.com/{u}", "method": "status"},
    "Rumble": {"url": "https://rumble.com/user/{u}", "method": "status"},
    "Odysee": {"url": "https://odysee.com/@{u}", "method": "status"},

    # --- Music ---
    "LastFm": {"url": "https://www.last.fm/user/{u}", "method": "status"},
    "Spotify": {"url": "https://open.spotify.com/user/{u}", "method": "status"},
    "Bandcamp": {"url": "https://{u}.bandcamp.com/", "method": "status"},
    "Audiomack": {"url": "https://audiomack.com/{u}", "method": "status"},

    # --- Gaming ---
    "Minecraft": {"url": "https://api.mojang.com/users/profiles/minecraft/{u}",
                  "method": "json_notnull"},
    "Lichess": {"url": "https://lichess.org/@/{u}", "method": "status"},
    "Osu": {"url": "https://osu.ppy.sh/users/{u}", "method": "status"},

    # --- Design / Art ---
    "ArtStation": {"url": "https://www.artstation.com/{u}", "method": "status"},
    "DeviantArt": {"url": "https://www.deviantart.com/{u}", "method": "status"},

    # --- Writing / Community ---
    "Instructables": {"url": "https://www.instructables.com/member/{u}/",
                      "method": "status"},

    # --- MENA / Social (region) ---
    "Snapchat": {"url": "https://www.snapchat.com/add/{u}", "method": "status"},
    "TikTok": {"url": "https://www.tiktok.com/@{u}", "method": "found_text",
               "text": "\"uniqueId\":\""},
}


class UsernameOsint(BaseModule):
    name = "harvest/username_osint"
    description = "Hunt a username across 60+ platforms with calibration (no false positives)"
    category = "harvest"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Username to hunt")
        self.add_option("THREADS", "20", False, "Concurrent requests")

    def _verdict(self, conf, resp):
        """Return 'found' / 'notfound' / 'error' for a single response.

        A fetch FAILURE (401/403/429/5xx, or any non-200 that is not a clear
        'absent' signal) maps to 'error' and must NEVER be reported as
        'notfound'. Only a 404/410, a plain-status redirect, or a clean 200
        that fails the content test counts as a real negative.
        """
        if resp is None:
            return "error"
        method = conf["method"]
        code = resp.status_code
        # 404/410 are the explicit "this user does not exist" signal for every
        # method.
        if code in (404, 410):
            return "notfound"
        if method == "status":
            if code == 200:
                return "found"
            # Redirects (rare with allow_redirects) to a home/404 page read as
            # absent; 401/403/429/5xx/anything else is a blocked/failed fetch.
            if code in (301, 302, 303):
                return "notfound"
            return "error"
        # Body-interpreting methods need a clean 200; any other status is a
        # failed fetch (blocked / rate-limited / server error), never "absent".
        if code != 200:
            return "error"
        if method == "json_notnull":
            body = (resp.text or "").strip()
            return "found" if body and body.lower() != "null" else "notfound"
        if method == "found_text":
            return "found" if conf.get("text", "") in (resp.text or "") else "notfound"
        if method == "notfound_text":
            return "notfound" if conf.get("text", "") in (resp.text or "") else "found"
        return "error"

    def _probe(self, conf, username):
        url = conf["url"].format(u=username)
        try:
            resp = http.get(url, timeout=12, allow_redirects=True)
            return self._verdict(conf, resp)
        except Exception:
            return "error"

    def _check(self, site_name, conf, username, control_user):
        """Check target; confirm with a control (random) username to kill false positives."""
        url = conf["url"].format(u=username)
        target = self._probe(conf, username)
        if target != "found":
            return site_name, url, target, None
        # Calibrate: a non-existent username must read as 'notfound' for this to be real
        control = self._probe(conf, control_user)
        return site_name, url, target, control

    def run(self):
        if not self.validate():
            return False

        username = self.get_option("TARGET").strip()
        threads = max(1, int(self.get_option("THREADS") or 20))
        control_user = "zz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Username Hunt: {username}")
        print(f"  Checking {len(SITES)} platforms (calibrated, no false positives)")
        print(f"{'='*58}{Colors.RESET}\n")

        confirmed, unreliable, not_found, errors = [], [], [], []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._check, name, conf, username, control_user): name
                       for name, conf in SITES.items()}
            for future in as_completed(futures):
                name, url, target, control = future.result()
                if target == "found" and control == "notfound":
                    confirmed.append({"site": name, "url": url})
                    print_status(f"{name}: {url}", "success")
                elif target == "found" and control == "found":
                    # Site reports found for a random user too -> unreliable, suppress
                    unreliable.append(name)
                elif target == "error":
                    errors.append(name)
                else:
                    not_found.append(name)

        confirmed.sort(key=lambda x: x["site"])

        self.results = {
            "username": username,
            "sites_checked": len(SITES),
            "found_count": len(confirmed),
            "found": confirmed,
            "not_found": sorted(not_found),
            "unreliable_suppressed": sorted(unreliable),
            "errors": sorted(errors),
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Confirmed on {len(confirmed)}/{len(SITES)} platforms")
        print(f"{'─'*58}{Colors.RESET}")
        for item in confirmed:
            print(f"  {Colors.GREEN}+{Colors.RESET} {item['site']:<14} {item['url']}")
        if unreliable:
            print(f"  {Colors.DIM}suppressed {len(unreliable)} unreliable site(s) "
                  f"(returned a hit for a random user){Colors.RESET}")
        if errors:
            print(f"  {Colors.DIM}{len(errors)} site(s) unreachable{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return True
