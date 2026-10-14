"""People search aggregator - name/email/phone -> public people-finder results.

This module queries public people-search sites. For authorized OSINT
investigations only. Many of these services have scraping restrictions,
rate-limit aggressively, or forbid automated access in their ToS - honor
your local laws and the target sites' Terms of Service before use.
"""
import re
import hashlib
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core import http
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.config import Config

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


class PeopleSearch(BaseModule):
    """Aggregate public people-search sources by name / email / phone."""

    name = "harvest/people_search"
    description = "People aggregator - ThatsThem, TruePeople, FastPeople, Pipl, DDG, Gravatar"
    category = "harvest"
    target_type = "person"

    def _register_options(self):
        self.add_option("TARGET", "", False,
                        "Shortcut: auto-routes to NAME/EMAIL/PHONE based on shape")
        self.add_option("NAME", "", False, "Full name 'First Last' or 'First M. Last'")
        self.add_option("EMAIL", "", False, "Email address to pivot on")
        self.add_option("PHONE", "", False, "Phone number (digits only, +country optional)")
        self.add_option("STATE", "", False, "US state code for people-search filtering")
        self.add_option("USE_SCRAPERS", "true", False,
                        "Allow HTML scraping of ThatsThem/TruePeople/FastPeople")
        self.add_option("THREADS", "5", False, "Threads for parallel scraping")

    # ---------- helpers ----------

    def _split_name(self, name):
        """Return (first, last, slug) for a 'First [M.] Last' string."""
        parts = [p for p in re.split(r"\s+", name.strip()) if p]
        if len(parts) == 0:
            return "", "", ""
        if len(parts) == 1:
            return parts[0], "", parts[0].lower()
        first = parts[0]
        last = parts[-1]
        slug = f"{first}-{last}".lower()
        slug = re.sub(r"[^a-z0-9\-]", "", slug)
        return first, last, slug

    def _clean_phone(self, phone):
        """Strip to digits, drop a leading country-code 1 for US."""
        digits = re.sub(r"\D", "", phone or "")
        if len(digits) == 11 and digits.startswith("1"):
            digits = digits[1:]
        return digits

    def _text(self, node, default=""):
        if node is None:
            return default
        return re.sub(r"\s+", " ", node.get_text(" ", strip=True))

    def _get(self, url, timeout=12, **kw):
        """Thin wrapper around core.http.get with a browser UA + graceful None."""
        headers = kw.pop("headers", {}) or {}
        headers.setdefault("User-Agent", Config().get("user_agent"))
        headers.setdefault(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        try:
            return http.get(url, headers=headers, timeout=timeout,
                            allow_redirects=True, **kw)
        except Exception:
            return None

    # ---------- scrapers ----------

    def _thatsthem(self, name, email, phone):
        """Scrape thatsthem.com by email, phone, or name."""
        if BeautifulSoup is None:
            return [], "bs4 not installed"
        if email:
            url = f"https://thatsthem.com/email/{urllib.parse.quote(email)}"
        elif phone:
            url = f"https://thatsthem.com/phone/{urllib.parse.quote(phone)}"
        elif name:
            _, _, slug = self._split_name(name)
            if not slug:
                return [], "empty name"
            url = f"https://thatsthem.com/name/{urllib.parse.quote(slug)}"
        else:
            return [], "no selector"

        resp = self._get(url)
        if resp is None:
            return [], "request failed"
        if resp.status_code in (403, 429):
            return [], f"blocked (HTTP {resp.status_code})"
        if resp.status_code == 404:
            return [], "no results"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"

        results = []
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            # ThatsThem markup varies; try several card selectors
            cards = (soup.select("div.person-card")
                     or soup.select("div.ThatsThemResult")
                     or soup.select("div.result-item")
                     or soup.select("div.search-result"))
            for card in cards[:15]:
                item = {
                    "name": self._text(card.select_one("h3.name, h2, h3, .name")),
                    "age": self._text(card.select_one(".age")),
                    "address": self._text(card.select_one(".address, .location")),
                    "url": url,
                    "relatives": [self._text(a) for a in card.select(".relatives a")][:8],
                }
                a = card.find("a", href=True)
                if a and a["href"].startswith("/"):
                    item["url"] = "https://thatsthem.com" + a["href"]
                if item["name"]:
                    results.append(item)
        except Exception as e:
            return [], f"parse error: {e.__class__.__name__}"

        return results, None

    def _truepeople(self, name, phone, state):
        """Scrape truepeoplesearch.com result cards."""
        if BeautifulSoup is None:
            return [], "bs4 not installed"
        params = {}
        if phone:
            url = f"https://www.truepeoplesearch.com/results?phoneno={urllib.parse.quote(phone)}"
        elif name:
            params["name"] = name
            if state:
                params["citystatezip"] = state
            url = "https://www.truepeoplesearch.com/results?" + urllib.parse.urlencode(params)
        else:
            return [], "no selector"

        resp = self._get(url)
        if resp is None:
            return [], "request failed"
        if resp.status_code in (403, 429):
            return [], f"blocked (HTTP {resp.status_code})"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"

        results = []
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            cards = (soup.select("div.card.card-body.shadow-form.card-summary")
                     or soup.select("div.card-summary")
                     or soup.select("div.card.card-body"))
            for card in cards[:15]:
                values = [self._text(v) for v in card.select(".content-value")]
                item = {
                    "name": self._text(card.select_one(".h4, h4, .name")),
                    "age": "",
                    "address": "",
                    "aka": "",
                    "url": url,
                }
                for v in values:
                    low = v.lower()
                    if "age" in low and not item["age"]:
                        item["age"] = v
                    elif re.search(r"\b[A-Z]{2}\s*\d{5}", v) and not item["address"]:
                        item["address"] = v
                    elif v and not item["aka"] and v != item["name"]:
                        item["aka"] = v
                a = card.find("a", href=True)
                if a and a["href"].startswith("/"):
                    item["url"] = "https://www.truepeoplesearch.com" + a["href"]
                if item["name"]:
                    results.append(item)
        except Exception as e:
            return [], f"parse error: {e.__class__.__name__}"

        return results, None

    def _fastpeople(self, name, phone, state):
        """Scrape fastpeoplesearch.com result cards."""
        if BeautifulSoup is None:
            return [], "bs4 not installed"
        if phone:
            digits = re.sub(r"\D", "", phone)
            url = f"https://www.fastpeoplesearch.com/{digits}"
        elif name:
            first, last, _ = self._split_name(name)
            if not (first and last):
                return [], "need first and last"
            slug = f"{first.lower()}-{last.lower()}"
            slug = re.sub(r"[^a-z0-9\-]", "", slug)
            url = f"https://www.fastpeoplesearch.com/name/{slug}"
            if state:
                url += f"_{state.lower()}"
        else:
            return [], "no selector"

        resp = self._get(url)
        if resp is None:
            return [], "request failed"
        if resp.status_code in (403, 429):
            return [], f"blocked (HTTP {resp.status_code})"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"

        results = []
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            cards = (soup.select("div.card.card-body.people-list")
                     or soup.select("div.people-list")
                     or soup.select("div.card-body"))
            for card in cards[:15]:
                item = {
                    "name": self._text(card.select_one("h2, .h4, .name, a.larger")),
                    "age": "",
                    "address": self._text(card.select_one(".col-address, .address")),
                    "url": url,
                }
                age_el = card.find(string=re.compile(r"Age\s*\d+", re.I))
                if age_el:
                    m = re.search(r"\d+", str(age_el))
                    if m:
                        item["age"] = m.group(0)
                a = card.find("a", href=True)
                if a and a["href"].startswith("/"):
                    item["url"] = "https://www.fastpeoplesearch.com" + a["href"]
                if item["name"]:
                    results.append(item)
        except Exception as e:
            return [], f"parse error: {e.__class__.__name__}"

        return results, None

    def _pipl_preview(self, name, email, phone):
        """Pipl free search returns a landing preview; parse any names/links."""
        if BeautifulSoup is None:
            return [], "bs4 not installed"
        q = email or phone or name
        if not q:
            return [], "no query"
        url = f"https://pipl.com/search/?q={urllib.parse.quote(q)}"
        resp = self._get(url)
        if resp is None:
            return [], "request failed"
        if resp.status_code in (403, 429):
            return [], f"blocked (HTTP {resp.status_code})"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"

        results = []
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for h in soup.select("h3, .result-title")[:10]:
                text = self._text(h)
                if text and q.lower() not in text.lower()[:4]:
                    results.append({"snippet": text[:160], "url": url})
            if not results:
                m = soup.find(string=re.compile(r"result", re.I))
                if m:
                    results.append({"snippet": self._text(m)[:160], "url": url})
        except Exception as e:
            return [], f"parse error: {e.__class__.__name__}"
        return results, None

    def _intelx_phonebook(self, name, email, phone):
        """IntelX phonebook search - requires api_keys.intelx."""
        key = Config().get("api_keys.intelx")
        if not key:
            return [], "no api_keys.intelx configured"
        term = email or phone or name
        if not term:
            return [], "no selector"
        try:
            search_resp = http.post(
                "https://2.intelx.io/phonebook/search",
                headers={"x-key": key, "Content-Type": "application/json",
                         "User-Agent": Config().get("user_agent")},
                json={"term": term, "maxresults": 25, "media": 0, "target": 0,
                      "timeout": 5, "terminate": []},
                timeout=15,
            )
        except Exception as e:
            return [], f"request error: {e.__class__.__name__}"
        if search_resp is None or search_resp.status_code != 200:
            code = search_resp.status_code if search_resp else "no-resp"
            return [], f"search HTTP {code}"
        try:
            sid = search_resp.json().get("id")
        except Exception:
            return [], "bad response"
        if not sid:
            return [], "no search id"
        try:
            res_resp = http.get(
                f"https://2.intelx.io/phonebook/search/result?id={sid}&limit=25",
                headers={"x-key": key, "User-Agent": Config().get("user_agent")},
                timeout=15,
            )
            if res_resp is None or res_resp.status_code != 200:
                return [], f"result HTTP {res_resp.status_code if res_resp else 'none'}"
            data = res_resp.json()
            selectors = data.get("selectors", []) or []
            return [{"selector": s.get("selectorvalue"),
                     "type": s.get("selectortype")} for s in selectors[:25]], None
        except Exception as e:
            return [], f"parse error: {e.__class__.__name__}"

    def _duckduckgo(self, name, email, phone):
        """Lightweight DDG HTML search for the subject + social dorks."""
        if BeautifulSoup is None:
            return []
        q_parts = []
        if name:
            q_parts.append(f'"{name}"')
        if email:
            q_parts.append(f'"{email}"')
        if phone:
            q_parts.append(f'"{phone}"')
        if not q_parts:
            return []
        base = " ".join(q_parts)
        queries = [
            base,
            f"{base} site:linkedin.com/in",
            f"{base} site:facebook.com",
            f"{base} site:twitter.com OR site:x.com",
            f"{base} site:instagram.com",
        ]
        results = []
        for q in queries:
            try:
                resp = self._get(
                    "https://html.duckduckgo.com/html/",
                    params={"q": q},
                    timeout=10,
                )
                if resp is None or resp.status_code != 200:
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                for res in soup.select("div.result")[:8]:
                    a = res.select_one("a.result__a")
                    snippet = res.select_one(".result__snippet")
                    if not a:
                        continue
                    href = a.get("href", "")
                    # DDG wraps outbound links via a redirector; extract uddg
                    if "uddg=" in href:
                        try:
                            href = urllib.parse.unquote(
                                href.split("uddg=", 1)[1].split("&", 1)[0]
                            )
                        except Exception:
                            pass
                    results.append({
                        "title": self._text(a)[:140],
                        "url": href,
                        "snippet": self._text(snippet)[:220],
                        "query": q,
                    })
            except Exception:
                continue
        # Dedupe by URL
        seen, uniq = set(), []
        for r in results:
            if r["url"] in seen:
                continue
            seen.add(r["url"])
            uniq.append(r)
        return uniq[:30]

    def _gravatar(self, email):
        """Reuse the Gravatar check from email_osint - hash + fetch profile."""
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        out = {"hash": email_hash, "exists": False, "email": email}
        try:
            resp = self._get(f"https://www.gravatar.com/avatar/{email_hash}?d=404", timeout=6)
            if resp is not None and resp.status_code == 200:
                out["exists"] = True
                out["avatar_url"] = f"https://www.gravatar.com/avatar/{email_hash}?s=400"
                out["profile_url"] = f"https://gravatar.com/{email_hash}"
            prof = self._get(f"https://en.gravatar.com/{email_hash}.json", timeout=6)
            if prof is not None and prof.status_code == 200:
                try:
                    entry = (prof.json().get("entry") or [{}])[0]
                except Exception:
                    entry = {}
                out["display_name"] = entry.get("displayName")
                out["about_me"] = entry.get("aboutMe")
                out["current_location"] = entry.get("currentLocation")
                out["linked_accounts"] = [
                    {"domain": a.get("domain"), "url": a.get("url"),
                     "username": a.get("username")}
                    for a in (entry.get("accounts") or [])
                ]
        except Exception:
            pass
        return out if out["exists"] else None

    def _breach_directory(self, email):
        """BreachDirectory free RapidAPI - skip gracefully if not configured."""
        key = Config().get("api_keys.breachdirectory") or Config().get("api_keys.rapidapi")
        if not key:
            return None, "no api_keys.breachdirectory configured"
        try:
            resp = http.get(
                "https://breachdirectory.p.rapidapi.com/",
                params={"func": "auto", "term": email},
                headers={
                    "x-rapidapi-key": key,
                    "x-rapidapi-host": "breachdirectory.p.rapidapi.com",
                    "User-Agent": Config().get("user_agent"),
                },
                timeout=12,
            )
            if resp is None or resp.status_code != 200:
                return None, f"HTTP {resp.status_code if resp else 'none'}"
            data = resp.json()
            return {
                "found": bool(data.get("found")),
                "count": data.get("found", 0),
                "sources": [r.get("sources") for r in (data.get("result") or [])][:10],
            }, None
        except Exception as e:
            return None, f"error: {e.__class__.__name__}"

    # ---------- dorks ----------

    def _dorks(self, name, email, phone):
        """Build Google/Bing dorks the user can run manually."""
        dorks = []
        if name:
            dorks += [
                f'"{name}" site:linkedin.com/in/',
                f'"{name}" site:facebook.com',
                f'"{name}" site:twitter.com OR site:x.com',
                f'"{name}" site:instagram.com',
                f'"{name}" "resume" filetype:pdf',
                f'"{name}" "CV" filetype:pdf',
                f'intext:"{name}" "contact" OR "email"',
            ]
        if email:
            dorks += [
                f'"{email}"',
                f'"{email}" site:pastebin.com OR site:ghostbin.com',
                f'"{email}" site:github.com',
            ]
        if phone:
            dorks += [
                f'"{phone}"',
                f'"{phone}" site:facebook.com',
                f'"{phone}" "whatsapp"',
            ]
        return dorks

    # ---------- main ----------

    def run(self):
        if not self.validate():
            return False

        name = (self.get_option("NAME") or "").strip()
        email = (self.get_option("EMAIL") or "").strip().lower()
        phone_raw = (self.get_option("PHONE") or "").strip()
        state = (self.get_option("STATE") or "").strip().upper()
        use_scrapers = (self.get_option("USE_SCRAPERS") or "true").lower() == "true"
        threads = max(1, int(self.get_option("THREADS") or 5))

        target = (self.get_option("TARGET") or "").strip()
        if target and not (name or email or phone_raw):
            if "@" in target and "." in target.split("@")[-1]:
                email = target.lower()
            elif re.search(r"\d{7,}", target):
                phone_raw = target
            else:
                name = target

        if not (name or email or phone_raw):
            print_status(
                "Set TARGET (auto-detected) OR at least one of NAME / EMAIL / PHONE.",
                "error")
            return False

        phone = self._clean_phone(phone_raw)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  People Search")
        if name:
            print(f"  Name:  {name}")
        if email:
            print(f"  Email: {email}")
        if phone:
            print(f"  Phone: {phone}")
        if state:
            print(f"  State: {state}")
        print(f"{'='*58}{Colors.RESET}\n")

        if BeautifulSoup is None:
            print_status("bs4 not available - scrapers disabled.", "warning")
            use_scrapers = False

        matches = {"thatsthem": [], "truepeople": [], "fastpeople": [],
                   "pipl_preview": [], "intelx": [], "duckduckgo": []}
        warnings = []
        sources_tried = []
        sources_failed = []

        # Parallel scrapers (ThatsThem / TruePeople / FastPeople)
        if use_scrapers:
            print_status("[1/5] Scraping people-search sites in parallel...", "info")
            scraper_jobs = {
                "thatsthem": lambda: self._thatsthem(name, email, phone),
                "truepeople": lambda: self._truepeople(name, phone, state),
                "fastpeople": lambda: self._fastpeople(name, phone, state),
            }
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(fn): src for src, fn in scraper_jobs.items()}
                for fut in as_completed(futures):
                    src = futures[fut]
                    sources_tried.append(src)
                    try:
                        rows, err = fut.result()
                    except Exception as e:
                        rows, err = [], f"exception: {e.__class__.__name__}"
                    if err:
                        warnings.append(f"{src}: {err}")
                        sources_failed.append(src)
                    matches[src] = rows
                    if rows:
                        print_status(f"{src}: {len(rows)} match(es)", "success")
                    else:
                        print_status(f"{src}: 0 matches ({err or 'empty'})", "info")
        else:
            print_status("[1/5] Scrapers disabled (USE_SCRAPERS=false)", "info")

        # Pipl preview
        print_status("[2/5] Pipl free preview...", "info")
        sources_tried.append("pipl")
        pipl_rows, pipl_err = self._pipl_preview(name, email, phone)
        if pipl_err:
            warnings.append(f"pipl: {pipl_err}")
            sources_failed.append("pipl")
        matches["pipl_preview"] = pipl_rows
        if pipl_rows:
            print_status(f"pipl: {len(pipl_rows)} preview item(s)", "success")

        # IntelX
        print_status("[3/5] IntelX phonebook...", "info")
        sources_tried.append("intelx")
        ix_rows, ix_err = self._intelx_phonebook(name, email, phone)
        if ix_err:
            warnings.append(f"intelx: {ix_err}")
            sources_failed.append("intelx")
        matches["intelx"] = ix_rows
        if ix_rows:
            print_status(f"intelx: {len(ix_rows)} selector(s)", "success")

        # DuckDuckGo
        print_status("[4/5] DuckDuckGo (name + social dorks)...", "info")
        sources_tried.append("duckduckgo")
        ddg_rows = self._duckduckgo(name, email, phone)
        matches["duckduckgo"] = ddg_rows
        if ddg_rows:
            print_status(f"duckduckgo: {len(ddg_rows)} link(s)", "success")
        else:
            sources_failed.append("duckduckgo")
            warnings.append("duckduckgo: 0 results or blocked")

        # Gravatar + optional BreachDirectory (email-only side quests)
        print_status("[5/5] Gravatar + BreachDirectory (if email given)...", "info")
        gravatar = None
        breach = None
        if email:
            sources_tried.append("gravatar")
            gravatar = self._gravatar(email)
            if gravatar:
                print_status(f"gravatar: profile found ({gravatar.get('display_name') or '?'})",
                             "success")
            sources_tried.append("breachdirectory")
            breach, b_err = self._breach_directory(email)
            if b_err:
                warnings.append(f"breachdirectory: {b_err}")
                sources_failed.append("breachdirectory")
            elif breach and breach.get("found"):
                print_status(f"breachdirectory: {breach['count']} hit(s)", "warning")

        dorks = self._dorks(name, email, phone)

        self.results = {
            "query": {"name": name, "email": email, "phone": phone, "state": state},
            "matches": matches,
            "gravatar": gravatar,
            "breach_directory": breach,
            "google_dorks": dorks,
            "sources_tried": sorted(set(sources_tried)),
            "sources_failed": sorted(set(sources_failed)),
            "warnings": warnings,
        }

        # ---------- summary ----------
        total_matches = sum(len(v) for v in matches.values())
        hit_sources = [s for s, v in matches.items() if v]

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  People Search Summary")
        print(f"{'─'*58}{Colors.RESET}")
        print(f"  Found {Colors.BOLD}{total_matches}{Colors.RESET} match(es) "
              f"across {Colors.BOLD}{len(hit_sources)}{Colors.RESET} source(s)")
        for src in ("thatsthem", "truepeople", "fastpeople", "pipl_preview",
                    "intelx", "duckduckgo"):
            rows = matches.get(src) or []
            if not rows:
                continue
            print(f"\n  {Colors.CYAN}{src}{Colors.RESET} ({len(rows)}):")
            for row in rows[:3]:
                label = (row.get("name") or row.get("title")
                         or row.get("selector") or row.get("snippet") or "?")
                extra = row.get("address") or row.get("url") or ""
                print(f"    {Colors.GREEN}+{Colors.RESET} {label[:60]}")
                if extra:
                    print(f"      {Colors.DIM}{extra[:80]}{Colors.RESET}")
        if gravatar:
            print(f"\n  {Colors.CYAN}gravatar{Colors.RESET}: "
                  f"{gravatar.get('display_name') or 'profile'} "
                  f"-> {gravatar.get('profile_url')}")
        if breach and breach.get("found"):
            print(f"  {Colors.YELLOW}breach:{Colors.RESET} "
                  f"{breach['count']} hit(s)")
        if dorks:
            print(f"\n  {Colors.DIM}dorks generated: {len(dorks)}{Colors.RESET}")
        if warnings:
            print(f"  {Colors.DIM}warnings: {len(warnings)}"
                  f" ({', '.join(w.split(':')[0] for w in warnings[:4])}"
                  f"{'...' if len(warnings) > 4 else ''}){Colors.RESET}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return True
