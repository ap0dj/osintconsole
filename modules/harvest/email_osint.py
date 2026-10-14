import re
import hashlib
import socket
import json
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from core import http
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.config import Config


# Keyless email-registration probes. Each entry was probed LIVE on 2026-10-13
# through core.http. The former "Twitter/X" probe
# (api.twitter.com/i/users/email_available.json) was REMOVED: it is an
# unofficial/undocumented endpoint the owner wants gone, and HTTP errors from it
# were previously bucketed silently. Spotify and Duolingo were confirmed alive
# and discriminating; Pinterest (403), WordPress (403 auth-required) and Imgur
# (412 security-check) are dead keyless and now surface as ERRORS, never as a
# false "not found" (see _check_service).
SERVICE_CHECKS = {
    "Spotify": {
        "url": "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}",
        "method": "GET",
        "exists_when": "status_20",
        "check_field": "status",
        "exists_value": 20,
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/?source_url=/&data={{\"options\":{{\"email\":\"{email}\"}}}}",
        "method": "GET",
        "exists_when": "resource_response",
    },
    "WordPress": {
        "url": "https://public-api.wordpress.com/rest/v1.1/users/{email}",
        "method": "GET",
        "exists_when": "status_200",
    },
    "Duolingo": {
        "url": "https://www.duolingo.com/2017-06-30/users?email={email}",
        "method": "GET",
        "exists_when": "has_users",
    },
    "Imgur": {
        "url": "https://imgur.com/signin/ajax_email_available?email={email}",
        "method": "GET",
        "exists_when": "data_false",
    },
}


class EmailOsint(BaseModule):
    """Comprehensive email OSINT: validate, enrich, find accounts, search the web."""

    name = "harvest/email_osint"
    description = "Full email OSINT - validation, Gravatar, service lookup, web search, username/dork derivation"
    category = "harvest"
    target_type = "email"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Email address to investigate")
        self.add_option("CHECK_SERVICES", "true", False, "Check registration on popular services")
        self.add_option("WEB_SEARCH", "true", False, "Search the web for the email")
        self.add_option("THREADS", "5", False, "Threads for service checks")

    def _validate_email(self, email):
        """Validate email format, domain, and MX records."""
        result = {
            "valid_format": False,
            "domain": "",
            "mx_records": [],
            "domain_exists": False,
            "is_disposable": False,
            "is_free_provider": False,
            "provider": "",
        }

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return result
        result["valid_format"] = True

        local_part, domain = email.rsplit("@", 1)
        result["domain"] = domain
        result["local_part"] = local_part

        free_providers = {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
            "aol.com", "icloud.com", "mail.com", "protonmail.com", "proton.me",
            "zoho.com", "yandex.com", "gmx.com", "tutanota.com", "fastmail.com",
            "hey.com", "pm.me", "ymail.com", "rocketmail.com",
        }

        disposable_domains = {
            "tempmail.com", "guerrillamail.com", "mailinator.com", "10minutemail.com",
            "throwaway.email", "temp-mail.org", "fakeinbox.com", "sharklasers.com",
            "guerrillamailblock.com", "grr.la", "dispostable.com", "yopmail.com",
            "trashmail.com", "maildrop.cc",
        }

        result["is_free_provider"] = domain.lower() in free_providers
        result["is_disposable"] = domain.lower() in disposable_domains
        result["provider"] = domain

        try:
            mx = dns.resolver.resolve(domain, "MX")
            result["mx_records"] = [str(r.exchange).rstrip(".") for r in mx]
            result["domain_exists"] = True
        except Exception:
            try:
                dns.resolver.resolve(domain, "A")
                result["domain_exists"] = True
            except Exception:
                pass

        return result

    def _gravatar_lookup(self, email):
        """Check Gravatar for profile and avatar."""
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        result = {"hash": email_hash, "exists": False}

        try:
            resp = http.get(
                f"https://www.gravatar.com/avatar/{email_hash}?d=404",
                timeout=5
            )
            if resp.status_code == 200:
                result["exists"] = True
                result["avatar_url"] = f"https://www.gravatar.com/avatar/{email_hash}?s=400"
                result["profile_url"] = f"https://gravatar.com/{email_hash}"

            profile_resp = http.get(
                f"https://en.gravatar.com/{email_hash}.json",
                timeout=5
            )
            if profile_resp.status_code == 200:
                data = profile_resp.json()
                entry = data.get("entry", [{}])[0]
                result["display_name"] = entry.get("displayName")
                result["about_me"] = entry.get("aboutMe")
                result["current_location"] = entry.get("currentLocation")
                result["profile_url_json"] = entry.get("profileUrl")

                photos = entry.get("photos", [])
                if photos:
                    result["photo_url"] = photos[0].get("value")

                accounts = entry.get("accounts", [])
                result["linked_accounts"] = [
                    {"domain": a.get("domain"), "display": a.get("display"),
                     "url": a.get("url"), "username": a.get("username")}
                    for a in accounts
                ]

                urls = entry.get("urls", [])
                result["urls"] = [{"title": u.get("title"), "value": u.get("value")}
                                  for u in urls]
        except Exception:
            pass

        return result

    def _check_service(self, service_name, config_data, email, timeout=8):
        """Check if email is registered on a specific service."""
        # Defensive: refuse POST probes against registration/auth endpoints.
        if config_data["method"] == "POST" and any(
            p in config_data["url"] for p in ("/auth/", "/signup", "/register")
        ):
            return service_name, None  # refuse abuse-flavored probes
        try:
            url = config_data["url"].format(email=email)
            headers = {
                "User-Agent": Config().get("user_agent"),
                "Accept": "application/json",
            }

            if config_data["method"] == "POST":
                post_data = {}
                for k, v in config_data.get("post_data", {}).items():
                    post_data[k] = v.format(email=email) if isinstance(v, str) else v
                resp = requests.post(url, json=post_data, headers=headers, timeout=timeout)
            else:
                resp = http.get(url, headers=headers, timeout=timeout)

            if resp is None:
                return service_name, None  # no response -> ERROR, not "not found"

            check = config_data["exists_when"]
            status = getattr(resp, "status_code", None)

            # status_200 reads the HTTP status itself: 2xx => registered,
            # 404 => genuinely absent, anything else (401/403/5xx ...) => ERROR.
            if check == "status_200":
                if status is not None and 200 <= status < 300:
                    return service_name, True
                if status == 404:
                    return service_name, False
                return service_name, None

            # Every body-interpreting check needs a clean HTTP 200. A non-200
            # (403 auth-wall, 412 bot-check, 429 throttle, 5xx ...) means we got
            # NO verdict -> surface it as an ERROR, never as a silent "not found".
            if status != 200:
                return service_name, None

            if check == "taken":
                data = resp.json()
                field = config_data.get("check_field", "taken")
                return service_name, data.get(field, False) is True

            elif check == "status_20":
                data = resp.json()
                return service_name, data.get("status") == 20

            elif check == "has_users":
                data = resp.json()
                users = data.get("users", [])
                return service_name, len(users) > 0

            elif check == "data_false":
                data = resp.json()
                return service_name, data.get("data", {}).get("available") is False

            elif check == "resource_response":
                return service_name, "resource_response" in resp.text

            return service_name, False

        except Exception:
            return service_name, None

    def _check_all_services(self, email, threads=5):
        """Check email registration on multiple services concurrently."""
        results = {"registered": [], "not_found": [], "errors": []}

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_service, name, conf, email): name
                for name, conf in SERVICE_CHECKS.items()
            }
            for future in as_completed(futures):
                name, exists = future.result()
                if exists is True:
                    results["registered"].append(name)
                    print_status(f"[REGISTERED] {name}", "success")
                elif exists is False:
                    results["not_found"].append(name)
                else:
                    # exists is None => the probe gave NO verdict (HTTP error,
                    # timeout, bad JSON). Surfaced distinctly from "not found"
                    # so a dead source is never mistaken for "email not here".
                    results["errors"].append(name)
                    print_status(f"[ERROR] {name} - check failed, no verdict", "warning")

        return results

    def _web_search(self, email):
        """Search the web for mentions of the email."""
        config = Config()
        headers = {"User-Agent": config.get("user_agent")}
        results = {"mentions": [], "total": 0}

        queries = [
            f'"{email}"',
            f'"{email}" site:linkedin.com',
            f'"{email}" site:facebook.com',
            f'"{email}" site:pastebin.com',
        ]

        for query in queries:
            try:
                resp = http.get(
                    f"https://www.bing.com/search?q={query}",
                    headers=headers, timeout=10
                )
                if resp.status_code == 200:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for li in soup.find_all("li", class_="b_algo"):
                        link = li.find("a")
                        snippet = li.find("p")
                        if link:
                            results["mentions"].append({
                                "title": link.text[:100],
                                "url": link.get("href", ""),
                                "snippet": snippet.text[:200] if snippet else "",
                                "query": query,
                            })
            except Exception:
                pass

        results["total"] = len(results["mentions"])
        return results

    def _google_dork_email(self, email):
        """Generate Google dorks for the email."""
        local, domain = email.rsplit("@", 1)
        dorks = [
            f'"{email}"',
            f'"{email}" filetype:pdf',
            f'"{email}" filetype:xlsx OR filetype:csv',
            f'"{email}" site:pastebin.com OR site:ghostbin.com',
            f'"{email}" "password" OR "passwd"',
            f'"{local}" site:linkedin.com',
            f'intext:"{email}" -site:{domain}',
            f'"{email}" site:github.com',
            f'"{email}" site:stackoverflow.com',
            f'"{email}" resume OR cv filetype:pdf',
        ]
        return dorks

    def _derive_usernames(self, email):
        """Extract potential usernames from the email address."""
        local = email.split("@")[0].lower()
        usernames = {local}

        clean = re.sub(r'[._+-]+', ' ', local).strip()
        parts = clean.split()
        if len(parts) >= 2:
            usernames.add(parts[0])
            usernames.add(parts[-1])
            usernames.add(parts[0] + parts[-1])
            usernames.add(parts[-1] + parts[0])
            usernames.add(parts[0][0] + parts[-1])
            usernames.add(parts[0] + parts[-1][0])

        no_nums = re.sub(r'\d+', '', local)
        if no_nums and no_nums != local:
            usernames.add(no_nums)

        return sorted(u for u in usernames if len(u) >= 2)

    def _domain_osint(self, domain):
        """Quick OSINT on the email's domain."""
        result = {"domain": domain}

        try:
            import whois
            w = whois.whois(domain)
            result["registrar"] = w.registrar
            result["creation_date"] = str(w.creation_date)
            result["org"] = w.org
            result["country"] = w.country
        except Exception:
            pass

        try:
            ips = socket.gethostbyname_ex(domain)[2]
            result["ips"] = ips
        except Exception:
            pass

        try:
            txt = dns.resolver.resolve(domain, "TXT")
            spf = [str(r) for r in txt if "spf" in str(r).lower()]
            dmarc_records = []
            try:
                dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
                dmarc_records = [str(r) for r in dmarc]
            except Exception:
                pass
            result["spf"] = spf
            result["dmarc"] = dmarc_records
        except Exception:
            pass

        return result

    def run(self):
        if not self.validate():
            return False

        email = self.get_option("TARGET").strip().lower()
        check_services = self.get_option("CHECK_SERVICES").lower() == "true"
        web_search = self.get_option("WEB_SEARCH").lower() == "true"
        threads = int(self.get_option("THREADS") or 5)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Full Email OSINT")
        print(f"  Target: {email}")
        print(f"{'='*58}{Colors.RESET}\n")

        # 1. Validation
        print_status("[1/7] Validating email...", "info")
        validation = self._validate_email(email)
        if validation["valid_format"]:
            print_status(f"Format: valid", "success")
            print_status(f"Domain: {validation['domain']} "
                         f"({'exists' if validation['domain_exists'] else 'NOT FOUND'})",
                         "success" if validation["domain_exists"] else "error")
            if validation["mx_records"]:
                print_status(f"MX: {', '.join(validation['mx_records'][:3])}", "success")
            if validation["is_free_provider"]:
                print_status(f"Free email provider", "info")
            if validation["is_disposable"]:
                print_status(f"DISPOSABLE email detected!", "warning")
        else:
            print_status("Invalid email format", "error")
            return False

        # 2. Gravatar
        print_status("[2/7] Checking Gravatar...", "info")
        gravatar = self._gravatar_lookup(email)
        if gravatar.get("exists"):
            print_status(f"Gravatar found!", "success")
            print_status(f"  Avatar: {gravatar.get('avatar_url')}", "success")
            if gravatar.get("display_name"):
                print_status(f"  Name: {gravatar['display_name']}", "success")
            if gravatar.get("current_location"):
                print_status(f"  Location: {gravatar['current_location']}", "success")
            if gravatar.get("about_me"):
                print_status(f"  About: {gravatar['about_me'][:100]}", "info")
            for acc in gravatar.get("linked_accounts", []):
                print_status(f"  Linked: {acc['domain']} -> {acc.get('url')}", "success")
            for u in gravatar.get("urls", []):
                print_status(f"  URL: {u.get('title', '')} -> {u.get('value')}", "success")
        else:
            print_status("No Gravatar profile", "info")

        # 3. Username derivation
        print_status("[3/7] Deriving usernames...", "info")
        usernames = self._derive_usernames(email)
        print_status(f"Possible usernames: {', '.join(usernames)}", "info")

        # 4. Domain OSINT
        print_status("[4/7] Domain OSINT...", "info")
        domain_info = self._domain_osint(validation["domain"])
        if domain_info.get("org"):
            print_status(f"Domain org: {domain_info['org']}", "success")
        if domain_info.get("country"):
            print_status(f"Domain country: {domain_info['country']}", "success")
        if domain_info.get("registrar"):
            print_status(f"Registrar: {domain_info['registrar']}", "info")

        # 5. Service checks
        services = {"registered": [], "not_found": [], "errors": []}
        if check_services:
            print_status("[5/7] Checking service registrations...", "info")
            services = self._check_all_services(email, threads)
            if services["registered"]:
                print_status(f"Registered on {len(services['registered'])} service(s)", "success")
            if services["errors"]:
                print_status(f"No verdict (check errored) on: "
                             f"{', '.join(services['errors'])}", "warning")

        # 6. Web search
        web_results = {"mentions": [], "total": 0}
        if web_search:
            print_status("[6/7] Searching the web...", "info")
            web_results = self._web_search(email)
            if web_results["mentions"]:
                for m in web_results["mentions"][:10]:
                    print_status(f"  {m['title'][:60]}", "success")
                    print_status(f"    {m['url']}", "info")
            print_status(f"Found {web_results['total']} mention(s)", "info")

        # 7. Google dorks
        print_status("[7/7] Generating dorks...", "info")
        dorks = self._google_dork_email(email)

        self.results = {
            "target": email,
            "validation": validation,
            "gravatar": gravatar,
            "derived_usernames": usernames,
            "domain_info": domain_info,
            "services": services,
            "web_mentions": web_results,
            "google_dorks": dorks,
        }

        # --- Summary ---
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Email OSINT Summary: {email}")
        print(f"{'─'*58}{Colors.RESET}")

        if validation["domain_exists"]:
            print(f"  {Colors.GREEN}+ Domain valid{Colors.RESET}: {validation['domain']}")
        if validation["is_disposable"]:
            print(f"  {Colors.RED}! Disposable email{Colors.RESET}")
        if gravatar.get("exists"):
            print(f"  {Colors.GREEN}+ Gravatar{Colors.RESET}: {gravatar.get('display_name', 'found')}")
            for acc in gravatar.get("linked_accounts", []):
                print(f"    -> {acc['domain']}: {acc.get('url')}")
        if services.get("registered"):
            print(f"  {Colors.GREEN}+ Registered on{Colors.RESET}: {', '.join(services['registered'])}")
        if services.get("errors"):
            print(f"  {Colors.YELLOW}! No verdict (errored){Colors.RESET}: {', '.join(services['errors'])}")
        if domain_info.get("org"):
            print(f"  {Colors.BLUE}* Domain owner{Colors.RESET}: {domain_info['org']}")
        if web_results["total"] > 0:
            print(f"  {Colors.CYAN}* Web mentions{Colors.RESET}: {web_results['total']}")
        print(f"  {Colors.DIM}* Usernames{Colors.RESET}: {', '.join(usernames)}")
        print(f"  {Colors.DIM}* Dorks generated{Colors.RESET}: {len(dorks)}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return True
