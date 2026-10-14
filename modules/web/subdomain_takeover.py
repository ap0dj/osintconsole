from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# service -> (cname markers, fingerprint text in HTTP body)
FINGERPRINTS = [
    ("GitHub Pages", ["github.io"], ["there isn't a github pages site here",
                                     "for root urls (like http://example.com/) you must provide an index.html file"]),
    ("Heroku", ["herokuapp.com", "herokudns.com"], ["no such app", "heroku | no such app"]),
    ("AWS S3", ["s3.amazonaws.com", "s3-website"], ["nosuchbucket", "the specified bucket does not exist"]),
    ("Shopify", ["myshopify.com"], ["sorry, this shop is currently unavailable",
                                    "only one step left!"]),
    ("Fastly", ["fastly.net"], ["fastly error: unknown domain"]),
    ("Pantheon", ["pantheonsite.io"], ["the gods are wise, but do not know of the site which you seek"]),
    ("Tumblr", ["domains.tumblr.com"], ["whatever you were looking for doesn't currently exist at this address",
                                        "there's nothing here."]),
    ("WordPress", ["wordpress.com"], ["do you want to register"]),
    ("Ghost", ["ghost.io"], ["the thing you were looking for is no longer here",
                             "domain error"]),
    ("Surge.sh", ["surge.sh"], ["project not found"]),
    ("Bitbucket", ["bitbucket.io"], ["repository not found"]),
    ("Zendesk", ["zendesk.com"], ["help center closed", "this help center no longer exists"]),
    ("Readme.io", ["readme.io"], ["project doesnt exist... yet!"]),
    ("Unbounce", ["unbouncepages.com"], ["the requested url was not found on this server"]),
    ("Help Scout", ["helpscoutdocs.com"], ["no settings were found for this company"]),
    ("Cargo", ["cargocollective.com"], ["404 not found"]),
    ("Webflow", ["proxy-ssl.webflow.com", "webflow.io"], ["the page you are looking for doesn't exist or has been moved"]),
    ("Netlify", ["netlify.app", "netlify.com"], ["not found - request id"]),
    ("Azure", ["azurewebsites.net", "cloudapp.net", "trafficmanager.net",
               "blob.core.windows.net"], ["404 web site not found", "the specified blob does not exist"]),
    ("Desk.com", ["desk.com"], ["please try again or try desk.com free for 14 days"]),
    ("Teamwork", ["teamwork.com"], ["oops - we didn't find your site"]),
]


class SubdomainTakeover(FetchErrorsMixin, BaseModule):
    name = "web/subdomain_takeover"
    description = "Detect dangling CNAME / subdomain takeover against 20+ service fingerprints"
    category = "web"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Subdomain/domain to check (or comma-separated list)")

    def _get_cname(self, host):
        """Return (cname_chain, error_or_None).

        A DNS *error* (timeout/SERVFAIL/no-nameservers) must not look the same
        as a host that genuinely has no CNAME, or an unreachable resolver would
        read as "no takeover-prone CNAME -> safe".
        """
        chain = []
        if not HAS_DNS:
            return chain, "dnspython not installed (CNAME check unavailable)"
        try:
            answers = dns.resolver.resolve(host, "CNAME")
            for r in answers:
                chain.append(str(r.target).rstrip(".").lower())
            return chain, None
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Host exists with no CNAME, or doesn't exist at all - both are
            # definitive "no CNAME" answers, not lookup failures.
            return chain, None
        except Exception as exc:
            return chain, f"CNAME lookup failed: {exc}"

    def _nxdomain(self, host):
        """True = NXDOMAIN, False = resolves, None = couldn't determine."""
        if not HAS_DNS:
            return None
        try:
            dns.resolver.resolve(host, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except dns.resolver.NoAnswer:
            return False
        except Exception:
            return None

    def _check_host(self, host):
        result = {"host": host, "cname": [], "vulnerable": False,
                  "service": None, "reason": None, "error": None, "checked": True}
        cnames, cname_err = self._get_cname(host)
        result["cname"] = cnames
        if cname_err:
            # Could not resolve the CNAME - this is NOT evidence the host is safe.
            result["error"] = cname_err
            result["checked"] = False
            self._note_error(f"{host}: {cname_err}")
            return result

        matched_service = None
        for service, markers, _ in FINGERPRINTS:
            for cname in cnames:
                if any(marker in cname for marker in markers):
                    matched_service = service
                    break
            if matched_service:
                break

        # A takeover needs a CNAME pointing at a known service in the first
        # place. Without one, the body fingerprints below ("404 not found",
        # "repository not found", "domain error") match ordinary error pages
        # and would flag any plain 404 as a confirmed takeover.
        if not matched_service:
            return result

        # The host has a CNAME to a takeover-prone service, so it is at minimum
        # a candidate - never let it fall through to "no indicator / safe".
        result["service"] = matched_service

        # Fetch body and look for the takeover fingerprint
        body = ""
        body_fetched = False
        for scheme in ("https", "http"):
            try:
                # verify=False intentional: takeover-prone hosts often serve broken/mismatched TLS
                resp = http.get(f"{scheme}://{host}", verify=False,
                                allow_redirects=True, timeout=12)
                body = (resp.text or "").lower()
                body_fetched = True
                break
            except Exception:
                continue

        if body_fetched:
            for service, markers, texts in FINGERPRINTS:
                if service != matched_service:
                    continue
                for text in texts:
                    if text in body:
                        result["vulnerable"] = True
                        result["service"] = service
                        result["reason"] = f"Fingerprint matched: '{text[:40]}...'"
                        return result

        # CNAME points to a known service but target host is NXDOMAIN -> dangling
        for cname in cnames:
            if self._nxdomain(cname) is True:
                result["vulnerable"] = True
                result["reason"] = f"Dangling CNAME -> {cname} (NXDOMAIN)"
                return result

        if not body_fetched:
            # Body unreachable and dangling-check inconclusive: we could neither
            # confirm nor rule out takeover. Surface it, do NOT call it safe.
            result["error"] = "service body unreachable - takeover not confirmed/ruled out"
            self._note_error(f"{host}: {result['error']}")
            result["reason"] = (f"CNAME -> {matched_service}; could not fetch service "
                                f"body to confirm (verify manually)")
        else:
            result["reason"] = "CNAME points to a takeover-prone service (verify manually)"

        return result

    def run(self):
        if not self.validate():
            return False

        targets = [t.strip() for t in self.get_option("TARGET").split(",") if t.strip()]

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Subdomain Takeover Check ({len(targets)} host(s))")
        print(f"{'='*58}{Colors.RESET}\n")

        self._errors = []
        if not HAS_DNS:
            print_status("dnspython not installed - CNAME checks disabled; "
                         "results are INCONCLUSIVE, not 'safe'", "warning")

        checks = []
        vulnerable = []
        errored = []
        for host in targets:
            res = self._check_host(host)
            checks.append(res)
            if res["vulnerable"]:
                vulnerable.append(res)
                print_status(f"VULNERABLE: {host} -> {res['service']} "
                             f"({res['reason']})", "warning")
            elif res.get("error"):
                errored.append(res)
                print_status(f"{host}: could NOT check ({res['error']}) - "
                             f"not evidence of safety", "warning")
            elif res["service"]:
                print_status(f"{host}: CNAME -> {res['service']} (not confirmed)", "info")
            else:
                print_status(f"{host}: no takeover indicator", "success")

        self.results = {
            "hosts_checked": len(targets),
            "vulnerable_count": len(vulnerable),
            "vulnerable": vulnerable,
            "errored_count": len(errored),
            "all_checks": checks,
            "fetch_errors": list(self._errors),
        }

        # If nothing could actually be checked, this is a FAILURE, not a clean
        # "no takeovers" result - callers must not count it as safe.
        if targets and len(errored) == len(targets):
            self._fail()
            print(f"\n{Colors.BOLD}{Colors.RED}{'='*58}")
            print(f"  Check FAILED for all {len(targets)} host(s) - "
                  f"takeover status UNKNOWN")
            print(f"{'='*58}{Colors.RESET}\n")
            return False

        color = Colors.RED if vulnerable else Colors.GREEN
        print(f"\n{Colors.BOLD}{color}{'='*58}")
        suffix = f", {len(errored)} uncheckable" if errored else ""
        print(f"  {len(vulnerable)} potential takeover(s) found{suffix}")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
