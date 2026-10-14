"""Pastes aggregator - multi-source hunt for a target across paste sites,
archives, and public code indices.

Searches: Bing/DDG dorks over pastebin+ghostbin+gist+controlc+rentry+paste.ee,
PsbDmp archive, IntelX (if api_keys.intelx), HIBP pasteaccount (if api_keys.hibp
and TARGET is email), PublicWWW source-code search, and grep.app code search.

Authorized OSINT only. Honor local laws and target sites' ToS. Rate limits apply.
"""
import re
import time
import json
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


PASTE_DORK_SITES = ["pastebin.com", "ghostbin.co", "gist.github.com",
                    "controlc.com", "rentry.co", "paste.ee"]
ALL_SOURCES = ["pastebin_dork", "psbdmp", "intelx", "hibp", "publicwww", "grepapp"]
HOST_LABELS = {"pastebin.com": "pastebin", "ghostbin.co": "ghostbin",
               "gist.github.com": "gist", "controlc.com": "controlc",
               "rentry.co": "rentry", "paste.ee": "pasteee"}


class PastesAggregator(BaseModule):
    """Aggregate pastes, leaks, and code hits for a keyword/email/domain."""

    name = "harvest/pastes_aggregator"
    description = "Multi-source paste hunter: Bing+DDG dorks, PsbDmp, IntelX, HIBP, PublicWWW, grep.app"
    category = "harvest"
    target_type = "keyword/email/domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Keyword, email, domain, or wallet")
        self.add_option("SOURCES", "auto", False,
                        f"'all'/'auto' or CSV subset: {','.join(ALL_SOURCES)}")
        self.add_option("MAX_PER_SOURCE", "20", False, "Cap on hits per source")
        self.add_option("FETCH_CONTENT", "false", False,
                        "If true, fetch actual paste bodies (slower)")

    # ---------- helpers ----------

    def _classify(self, t):
        t = t.strip()
        if "@" in t and "." in t.split("@")[-1]:
            return "email"
        if re.match(r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$", t):
            return "domain"
        return "keyword"

    def _get(self, url, timeout=12, **kw):
        headers = kw.pop("headers", {}) or {}
        headers.setdefault("User-Agent", Config().get("user_agent"))
        headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        try:
            return http.get(url, headers=headers, timeout=timeout, allow_redirects=True, **kw)
        except Exception:
            return None

    def _host(self, url):
        try:
            return urllib.parse.urlparse(url).netloc.lower().replace("www.", "", 1)
        except Exception:
            return ""

    def _source_of(self, url):
        host = self._host(url)
        for dom, lab in HOST_LABELS.items():
            if dom in host:
                return lab
        return host or "unknown"

    def _paste_id(self, url, src):
        try:
            path = urllib.parse.urlparse(url).path.strip("/")
        except Exception:
            return ""
        if not path:
            return ""
        return path.split("/")[-1][:40]

    def _snip(self, text, limit=300):
        if not text:
            return ""
        clean = re.sub(r"\s+", " ", text).strip()
        return clean[:limit] + ("..." if len(clean) > limit else "")

    # ---------- sources ----------

    def _pastebin_dork(self, target, max_hits):
        """Bing + DuckDuckGo HTML search for paste-hosts + target."""
        if BeautifulSoup is None:
            return [], "bs4 not installed"
        quoted = f'"{target}"'
        site_filter = " OR ".join(f"site:{s}" for s in PASTE_DORK_SITES)
        query = f"({site_filter}) {quoted}"
        results, seen = [], set()

        def _harvest(soup, selector, link_sel, snip_sel, engine):
            for item in soup.select(selector)[:max_hits * 2]:
                a = item.select_one(link_sel) if link_sel else item.find("a", href=True)
                if not a:
                    continue
                href = a.get("href", "")
                if engine == "ddg" and "uddg=" in href:
                    try:
                        href = urllib.parse.unquote(href.split("uddg=", 1)[1].split("&", 1)[0])
                    except Exception:
                        pass
                if not href or href in seen:
                    continue
                seen.add(href)
                src = self._source_of(href)
                if src == "unknown":
                    continue
                title = a.get_text(" ", strip=True)
                sn = item.select_one(snip_sel)
                snippet = sn.get_text(" ", strip=True) if sn else ""
                results.append({
                    "source": src, "url": href,
                    "id": self._paste_id(href, src),
                    "snippet": self._snip(snippet, 220),
                    "found_in": "title" if target.lower() in title.lower() else "body",
                    "timestamp": None, "engine": engine,
                })
                if len(results) >= max_hits:
                    return True
            return False

        # Bing
        try:
            r = self._get("https://www.bing.com/search",
                          params={"q": query, "count": max(10, max_hits)})
            if r is not None and r.status_code == 200:
                if _harvest(BeautifulSoup(r.text, "html.parser"),
                            "li.b_algo", "a", "p", "bing"):
                    return results[:max_hits], None
        except Exception:
            pass

        # DuckDuckGo HTML
        try:
            r = self._get("https://html.duckduckgo.com/html/", params={"q": query})
            if r is not None and r.status_code == 200:
                _harvest(BeautifulSoup(r.text, "html.parser"),
                         "div.result", "a.result__a", ".result__snippet", "ddg")
        except Exception as e:
            if not results:
                return [], f"both engines failed: {e.__class__.__name__}"

        return results[:max_hits], None

    def _psbdmp(self, target, max_hits, fetch_content):
        """psbdmp.ws JSON archive - pastebin IDs mentioning target."""
        try:
            resp = self._get(f"https://psbdmp.ws/api/search/{urllib.parse.quote(target)}",
                             timeout=15)
        except Exception as e:
            return [], f"request error: {e.__class__.__name__}"
        if resp is None:
            return [], "no response"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            return [], "bad JSON"

        items = data.get("data") if isinstance(data, dict) else data
        items = items or []
        results = []
        for item in items[:max_hits]:
            pid = (item.get("id") or item.get("key")) if isinstance(item, dict) else str(item)
            ts = item.get("time") or item.get("date") if isinstance(item, dict) else None
            if not pid:
                continue
            snippet = ""
            if fetch_content:
                try:
                    r = self._get(f"https://pastebin.com/raw/{pid}", timeout=10)
                    if r is not None and r.status_code == 200:
                        snippet = self._snip(r.text, 300)
                except Exception:
                    pass
            results.append({
                "source": "pastebin",
                "url": f"https://pastebin.com/{pid}",
                "id": pid, "snippet": snippet, "found_in": "body",
                "timestamp": ts, "engine": "psbdmp",
            })
        return results, None

    def _intelx(self, target, max_hits, fetch_content):
        """IntelX intelligent search; requires api_keys.intelx."""
        key = Config().get("api_keys.intelx")
        if not key:
            return [], "no api key"
        hdrs = {"x-key": key, "Content-Type": "application/json",
                "User-Agent": Config().get("user_agent")}
        try:
            s = http.post("https://2.intelx.io/intelligent/search", headers=hdrs,
                          json={"term": target, "maxresults": max_hits, "media": 0,
                                "sort": 4, "terminate": [], "timeout": 5}, timeout=20)
        except Exception as e:
            return [], f"search error: {e.__class__.__name__}"
        if s is None or s.status_code != 200:
            return [], f"search HTTP {s.status_code if s else 'none'}"
        try:
            sid = s.json().get("id")
        except Exception:
            return [], "bad search response"
        if not sid:
            return [], "no search id"
        time.sleep(1.0)  # IntelX needs a moment
        try:
            r = http.get(f"https://2.intelx.io/intelligent/search/result?id={sid}&limit={max_hits}",
                         headers=hdrs, timeout=20)
            if r is None or r.status_code != 200:
                return [], f"result HTTP {r.status_code if r else 'none'}"
            data = r.json()
        except Exception as e:
            return [], f"parse error: {e.__class__.__name__}"

        results = []
        for rec in (data.get("records") or [])[:max_hits]:
            sid_val = rec.get("systemid") or rec.get("storageid") or ""
            bucket = rec.get("bucket") or ""
            snippet = ""
            if fetch_content and sid_val:
                try:
                    v = http.get(f"https://2.intelx.io/file/view?f=0&storageid={sid_val}&bucket={bucket}",
                                 headers=hdrs, timeout=15)
                    if v is not None and v.status_code == 200:
                        snippet = self._snip(v.text, 300)
                except Exception:
                    pass
            results.append({
                "source": f"intelx/{bucket}" if bucket else "intelx",
                "url": f"https://intelx.io/?did={sid_val}" if sid_val else "",
                "id": sid_val,
                "snippet": snippet or self._snip(rec.get("name") or "", 220),
                "found_in": "body",
                "timestamp": rec.get("date") or rec.get("added"),
                "engine": "intelx",
            })
        return results, None

    def _hibp_pastes(self, email, max_hits):
        """HIBP pasteaccount endpoint - requires api_keys.hibp."""
        key = Config().get("api_keys.hibp")
        if not key:
            return [], "no api key"
        hdrs = {"hibp-api-key": key, "Accept": "application/json",
                "User-Agent": Config().get("user_agent")}
        try:
            r = http.get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(email)}",
                         headers=hdrs, timeout=15)
        except Exception as e:
            return [], f"error: {e.__class__.__name__}"
        if r is None:
            return [], "no response"
        if r.status_code == 404:
            return [], None
        if r.status_code == 401:
            return [], "unauthorized"
        if r.status_code == 429:
            return [], "rate limited"
        if r.status_code != 200:
            return [], f"HTTP {r.status_code}"
        try:
            items = r.json() or []
        except Exception:
            return [], "bad JSON"
        return [{
            "source": p.get("Source") or "paste",
            "id": p.get("Id") or "",
            "title": p.get("Title") or "",
            "date": p.get("Date"),
            "email_count": p.get("EmailCount") or 0,
            "url": f"https://pastebin.com/{p.get('Id')}" if p.get("Source") == "Pastebin" and p.get("Id") else "",
        } for p in items[:max_hits]], None

    def _publicwww(self, target, max_hits):
        """PublicWWW source-code search - scrape HTML results."""
        if BeautifulSoup is None:
            return [], "bs4 not installed"
        resp = self._get(f"https://publicwww.com/websites/{urllib.parse.quote(target)}/",
                         timeout=15)
        if resp is None:
            return [], "no response"
        if resp.status_code in (403, 429):
            return [], f"blocked (HTTP {resp.status_code})"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"
        results = []
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            rows = (soup.select("ul.websites li") or soup.select("div.website")
                    or soup.select("tr.website"))
            for row in rows[:max_hits]:
                a = row.find("a", href=True)
                if not a:
                    continue
                href = a["href"]
                if href.startswith("/"):
                    href = "https://publicwww.com" + href
                title = a.get_text(" ", strip=True)
                sn = row.find("p") or row.find("div", class_="snippet")
                snippet = sn.get_text(" ", strip=True) if sn else ""
                results.append({
                    "source": "publicwww", "url": href,
                    "id": self._host(href),
                    "snippet": self._snip(snippet or title, 220),
                    "found_in": "body", "timestamp": None, "engine": "publicwww",
                })
        except Exception as e:
            return results, f"parse error: {e.__class__.__name__}"
        return results, None

    def _grepapp(self, target, max_hits):
        """grep.app code search API across public repos."""
        try:
            resp = http.get("https://grep.app/api/search",
                            params={"q": target},
                            headers={"User-Agent": Config().get("user_agent"),
                                     "Accept": "application/json"},
                            timeout=15)
        except Exception as e:
            return [], f"error: {e.__class__.__name__}"
        if resp is None or resp.status_code != 200:
            return [], f"HTTP {resp.status_code if resp else 'none'}"
        try:
            data = resp.json()
        except Exception:
            return [], "bad JSON"
        results = []
        for h in ((data.get("hits") or {}).get("hits") or [])[:max_hits]:
            repo = h.get("repo", {}).get("raw") or ""
            path = h.get("path", {}).get("raw") or ""
            branch = h.get("branch", {}).get("raw") or "master"
            content = h.get("content", {}).get("snippet") or ""
            clean = re.sub(r"<[^>]+>", "", content)
            results.append({
                "repo": repo, "path": path,
                "snippet": self._snip(clean, 300),
                "url": f"https://github.com/{repo}/blob/{branch}/{path}" if repo and path else "",
            })
        return results, None

    # ---------- main ----------

    def _resolve_sources(self, raw, target_type):
        raw = (raw or "auto").strip().lower()
        if raw in ("auto", "all", ""):
            picked = list(ALL_SOURCES)
        else:
            picked = [s.strip() for s in raw.split(",") if s.strip() in ALL_SOURCES]
        if not picked:
            picked = list(ALL_SOURCES)
        if target_type != "email" and "hibp" in picked:
            picked = [s for s in picked if s != "hibp"]
        return picked

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        try:
            max_per = max(1, int(self.get_option("MAX_PER_SOURCE") or 20))
        except (TypeError, ValueError):
            max_per = 20
        fetch_content = (self.get_option("FETCH_CONTENT") or "false").lower() == "true"
        ttype = self._classify(target)
        sources = self._resolve_sources(self.get_option("SOURCES"), ttype)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Pastes Aggregator")
        print(f"  Target: {target}  ({ttype})")
        print(f"  Sources: {', '.join(sources)}  | fetch_content={fetch_content}")
        print(f"{'='*58}{Colors.RESET}\n")

        if BeautifulSoup is None:
            print_status("bs4 not installed - dork + publicwww sources will skip", "warning")

        jobs = {}
        if "pastebin_dork" in sources:
            jobs["pastebin_dork"] = lambda: self._pastebin_dork(target, max_per)
        if "psbdmp" in sources:
            jobs["psbdmp"] = lambda: self._psbdmp(target, max_per, fetch_content)
        if "intelx" in sources:
            jobs["intelx"] = lambda: self._intelx(target, max_per, fetch_content)
        if "hibp" in sources:
            jobs["hibp"] = lambda: self._hibp_pastes(target, max_per)
        if "publicwww" in sources:
            jobs["publicwww"] = lambda: self._publicwww(target, max_per)
        if "grepapp" in sources:
            jobs["grepapp"] = lambda: self._grepapp(target, max_per)

        pastes, hibp_pastes, code_hits = [], [], []
        sources_skipped, warnings = {}, []
        started = time.time()
        total, counter = len(jobs), {"n": 0}

        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(fn): name for name, fn in jobs.items()}
            for fut in as_completed(futs):
                name = futs[fut]
                counter["n"] += 1
                try:
                    rows, err = fut.result()
                except Exception as e:
                    rows, err = [], f"exception: {e.__class__.__name__}"
                if err:
                    sources_skipped[name] = err
                    warnings.append(f"{name}: {err}")

                tag = f"[{counter['n']}/{total}] {name}"
                if name == "hibp":
                    hibp_pastes.extend(rows)
                    if rows:
                        print_status(f"{tag}: {Colors.RED}found {len(rows)} paste(s) "
                                     f"containing email!{Colors.RESET}", "warning")
                    else:
                        print_status(f"{tag}: 0 hits ({err or 'clean'})",
                                     "warning" if err else "info")
                elif name == "grepapp":
                    code_hits.extend(rows)
                    print_status(f"{tag}: found {len(rows)} code hit(s)"
                                 if rows else f"{tag}: 0 hits ({err or 'empty'})",
                                 "success" if rows else "info")
                else:
                    pastes.extend(rows)
                    print_status(f"{tag}: found {len(rows)} hit(s)"
                                 if rows else f"{tag}: 0 hits ({err or 'empty'})",
                                 "success" if rows else "info")

        # Dedupe pastes by (source, id or url)
        seen, uniq = set(), []
        for p in pastes:
            key = (p.get("source"), p.get("id") or p.get("url"))
            if key not in seen:
                seen.add(key)
                uniq.append(p)
        pastes = uniq

        duration = round(time.time() - started, 2)
        total_hits = len(pastes) + len(hibp_pastes) + len(code_hits)

        self.results = {
            "target": target, "target_type": ttype,
            "sources_queried": sorted(jobs.keys()),
            "sources_skipped": sources_skipped,
            "pastes": pastes, "hibp_pastes": hibp_pastes, "code_hits": code_hits,
            "stats": {"total_hits": total_hits, "duration_sec": duration},
            "warnings": warnings,
        }

        # ---------- summary ----------
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Pastes Aggregator Summary")
        print(f"{'-'*58}{Colors.RESET}")
        print(f"  {Colors.BOLD}{total_hits}{Colors.RESET} total hit(s) in "
              f"{Colors.BOLD}{duration}s{Colors.RESET}")

        by_source = {}
        for p in pastes:
            by_source[p["source"]] = by_source.get(p["source"], 0) + 1
        if by_source:
            print(f"\n  {Colors.CYAN}pastes by source:{Colors.RESET}")
            for src, n in sorted(by_source.items(), key=lambda kv: -kv[1]):
                print(f"    {Colors.GREEN}+{Colors.RESET} {src:<15} {n}")

        if pastes:
            print(f"\n  {Colors.CYAN}top paste IDs:{Colors.RESET}")
            for p in pastes[:8]:
                print(f"    {Colors.GREEN}+{Colors.RESET} [{p.get('source') or '?'}] "
                      f"{p.get('id') or '?'}")
                if p.get("url"):
                    print(f"      {Colors.DIM}{p['url'][:80]}{Colors.RESET}")
                if p.get("snippet"):
                    print(f"      {Colors.DIM}{p['snippet'][:100]}{Colors.RESET}")

        if hibp_pastes:
            print(f"\n  {Colors.RED}{Colors.BOLD}HIBP PASTES ({len(hibp_pastes)}){Colors.RESET}")
            for p in hibp_pastes[:10]:
                print(f"    {Colors.RED}!{Colors.RESET} {p.get('source')} "
                      f"id={p.get('id')} date={p.get('date') or '?'} "
                      f"emails={p.get('email_count')}")
                if p.get("title"):
                    print(f"      {Colors.DIM}{p['title'][:80]}{Colors.RESET}")

        if code_hits:
            print(f"\n  {Colors.CYAN}code hits (grep.app):{Colors.RESET}")
            for h in code_hits[:5]:
                print(f"    {Colors.GREEN}+{Colors.RESET} {h.get('repo')} :: {h.get('path')}")
                if h.get("snippet"):
                    print(f"      {Colors.DIM}{h['snippet'][:100]}{Colors.RESET}")

        if sources_skipped:
            print(f"\n  {Colors.DIM}skipped: "
                  f"{', '.join(f'{k}({v})' for k, v in sources_skipped.items())}"
                  f"{Colors.RESET}")

        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")
        return True
