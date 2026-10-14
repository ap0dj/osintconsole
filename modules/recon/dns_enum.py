import re
import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.query
import dns.zone
import dns.reversename
import dns.rdatatype
import dns.exception

from core.base_module import BaseModule
from core.utils import Colors, print_status, is_valid_domain, is_valid_ip


# -------- NS provider fingerprints (regex -> provider label) ---------------
NS_PROVIDER_PATTERNS = [
    (re.compile(r"\.awsdns-\d+\.(?:com|org|net|co\.uk)\.?$", re.I), "AWS Route 53"),
    (re.compile(r"\.cloudflare\.com\.?$", re.I),                    "Cloudflare"),
    (re.compile(r"\.ns\.cloudflare\.com\.?$", re.I),                "Cloudflare"),
    (re.compile(r"\.googledomains\.com\.?$", re.I),                 "Google Domains"),
    (re.compile(r"\.(?:ns\.)?google\.com\.?$", re.I),               "Google Cloud DNS"),
    (re.compile(r"\.registrar-servers\.com\.?$", re.I),             "Namecheap"),
    (re.compile(r"\.domaincontrol\.com\.?$", re.I),                 "GoDaddy"),
    (re.compile(r"\.dnsmadeeasy\.com\.?$", re.I),                   "DNS Made Easy"),
    (re.compile(r"\.dynect\.net\.?$", re.I),                        "Dyn / Oracle"),
    (re.compile(r"\.ovh\.(?:net|com)\.?$", re.I),                   "OVH"),
    (re.compile(r"\.hover\.com\.?$", re.I),                         "Hover"),
    (re.compile(r"\.he\.net\.?$", re.I),                            "Hurricane Electric"),
    (re.compile(r"\.name\.com\.?$", re.I),                          "Name.com"),
    (re.compile(r"\.gandi\.net\.?$", re.I),                         "Gandi"),
    (re.compile(r"\.wix(?:dns)?\.(?:com|net)\.?$", re.I),           "Wix"),
    (re.compile(r"\.hostinger\.(?:com|net)\.?$", re.I),             "Hostinger"),
    (re.compile(r"\.digitalocean\.com\.?$", re.I),                  "DigitalOcean"),
    (re.compile(r"\.linode\.com\.?$", re.I),                        "Linode / Akamai"),
    (re.compile(r"\.azure-dns\.(?:com|net|org|info)\.?$", re.I),    "Azure DNS"),
    (re.compile(r"\.bluehost\.com\.?$", re.I),                      "Bluehost"),
    (re.compile(r"\.hostgator\.com\.?$", re.I),                     "HostGator"),
]

# -------- SPF include fingerprints (domain fragment -> mail provider) ------
SPF_INCLUDE_PROVIDERS = [
    ("_spf.google.com",      "Google Workspace"),
    ("spf.protection.outlook", "Microsoft 365"),
    ("sendgrid.net",         "SendGrid"),
    ("mailgun.org",          "Mailgun"),
    ("amazonses.com",        "Amazon SES"),
    ("mandrillapp.com",      "Mailchimp Transactional"),
    ("mailchimp.com",        "Mailchimp"),
    ("salesforce.com",       "Salesforce"),
    ("zoho.com",             "Zoho Mail"),
    ("zendesk.com",          "Zendesk"),
    ("mcsv.net",             "Mailchimp"),
    ("sparkpostmail.com",    "SparkPost"),
    ("postmarkapp.com",      "Postmark"),
    ("stspg-customer.com",   "Statuspage"),
    ("constantcontact.com",  "Constant Contact"),
    ("hubspotemail.net",     "HubSpot"),
    ("pphosted.com",         "Proofpoint"),
    ("mimecast.com",         "Mimecast"),
    ("messagelabs.com",      "Symantec MessageLabs"),
    ("fastmail.com",         "Fastmail"),
    ("yandex.net",           "Yandex"),
]

# -------- DKIM selectors to probe ------------------------------------------
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "s1", "s2",
    "mail", "mandrill", "dkim", "mx", "sendgrid", "mailgun", "zoho",
    "amazonses", "sparkpost", "postmark", "hs1-20940454", "key1",
]

# -------- Common subdomains to probe (curated, not a brute force) ----------
COMMON_SUBS = [
    "www", "mail", "ftp", "webmail", "smtp", "imap", "pop", "ns1", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "test", "dev", "staging",
    "prod", "api", "admin", "portal", "secure", "vpn", "remote", "intranet",
    "stage", "beta", "alpha", "demo", "www2", "mobile", "m", "api2",
    "status", "support", "help", "docs", "blog", "forum", "shop", "store",
    "cdn", "static", "assets", "img", "images", "media", "download", "files",
    "mx", "mx1", "mx2", "exchange", "owa",
]


def _rand_label(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _fingerprint_ns(ns_name):
    for pat, label in NS_PROVIDER_PATTERNS:
        if pat.search(ns_name):
            return label
    return None


def _parse_spf(txt):
    """Parse an SPF TXT record into its mechanisms."""
    out = {
        "raw": txt,
        "includes": [],
        "ip4": [],
        "ip6": [],
        "a": [],
        "mx": [],
        "redirect": None,
        "exists": [],
        "all_policy": None,
        "mechanisms": [],
    }
    tokens = txt.split()
    for tok in tokens:
        out["mechanisms"].append(tok)
        low = tok.lower()
        if low.startswith("include:"):
            out["includes"].append(tok.split(":", 1)[1])
        elif low.startswith("ip4:"):
            out["ip4"].append(tok.split(":", 1)[1])
        elif low.startswith("ip6:"):
            out["ip6"].append(tok.split(":", 1)[1])
        elif low.startswith("a:"):
            out["a"].append(tok.split(":", 1)[1])
        elif low == "a":
            out["a"].append("@")
        elif low.startswith("mx:"):
            out["mx"].append(tok.split(":", 1)[1])
        elif low == "mx":
            out["mx"].append("@")
        elif low.startswith("exists:"):
            out["exists"].append(tok.split(":", 1)[1])
        elif low.startswith("redirect="):
            out["redirect"] = tok.split("=", 1)[1]
        elif low.endswith("all"):
            out["all_policy"] = tok
    return out


def _parse_dmarc(txt):
    """Parse a DMARC TXT record (semi-colon separated k=v pairs)."""
    out = {
        "raw": txt,
        "policy": None,
        "subdomain_policy": None,
        "pct": None,
        "reporting_emails": [],
        "forensic_emails": [],
        "aspf": None,
        "adkim": None,
    }
    for part in [p.strip() for p in txt.split(";") if p.strip()]:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "p":
            out["policy"] = v
        elif k == "sp":
            out["subdomain_policy"] = v
        elif k == "pct":
            out["pct"] = v
        elif k == "aspf":
            out["aspf"] = v
        elif k == "adkim":
            out["adkim"] = v
        elif k == "rua":
            out["reporting_emails"] = [a.replace("mailto:", "").strip()
                                       for a in v.split(",") if a.strip()]
        elif k == "ruf":
            out["forensic_emails"] = [a.replace("mailto:", "").strip()
                                      for a in v.split(",") if a.strip()]
    return out


def _detect_mail_providers(spf_includes, mx_records, dkim_hits):
    found = set()
    hay = " ".join(spf_includes + mx_records + list(dkim_hits.keys())).lower()
    for frag, label in SPF_INCLUDE_PROVIDERS:
        if frag.lower() in hay:
            found.add(label)
    if any("google" in s for s in dkim_hits.keys()):
        found.add("Google Workspace")
    return sorted(found)


def _email_security_grade(spf, dmarc, dkim_hits):
    """Score SPF+DMARC+DKIM presence -> grade A..F."""
    score = 0
    if spf:
        score += 1
        if spf.get("all_policy") in ("-all", "~all"):
            score += 1
    if dmarc:
        score += 1
        pol = (dmarc.get("policy") or "").lower()
        if pol == "reject":
            score += 2
        elif pol == "quarantine":
            score += 1
    if any(dkim_hits.values()):
        score += 1
    return {0: "F", 1: "F", 2: "D", 3: "C", 4: "B", 5: "A", 6: "A"}.get(score, "A")


def _mk_resolver(nameservers=None, timeout=5):
    r = dns.resolver.Resolver()
    if nameservers:
        r.nameservers = nameservers
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _resolve_a_direct(ns_ip, qname, timeout=5):
    """Query a specific NS directly (no recursion)."""
    try:
        q = dns.message.make_query(qname, dns.rdatatype.A)
        resp = dns.query.udp(q, ns_ip, timeout=timeout)
        return sorted({r.address for rr in resp.answer
                       for r in rr if rr.rdtype == dns.rdatatype.A})
    except Exception:
        return None


class DnsEnum(BaseModule):
    name = "recon/dns_enum"
    description = "Advanced DNS reconnaissance (records, wildcard, email security, NS intel, CAA, subdomain probe)"
    category = "recon"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain to enumerate")
        self.add_option("DNS_SERVER", "8.8.8.8", False, "Recursive DNS server to use")
        self.add_option("COMMON_PROBE", "true", False, "Probe curated common subdomains in parallel")
        self.add_option("DKIM_PROBE", "true", False, "Probe common DKIM selectors")
        self.add_option("AXFR_PER_NS", "true", False, "Attempt AXFR against each authoritative NS")

    # ------------------------- small helpers -----------------------------
    def _bool_opt(self, name):
        v = (self.get_option(name) or "").strip().lower()
        return v in ("1", "true", "yes", "y", "on")

    def _query(self, resolver, qname, rtype, raise_nx=False):
        try:
            ans = resolver.resolve(qname, rtype)
            return [str(r) for r in ans]
        except dns.resolver.NXDOMAIN:
            if raise_nx:
                raise
            return []
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout):
            return []
        except Exception:
            return []

    # ---------------------------- phases ---------------------------------
    def _phase_records(self, resolver, target):
        print_status("Phase 1/8  -  Standard record enumeration", "info")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]
        records = {}
        for rtype in record_types:
            try:
                vals = self._query(resolver, target, rtype, raise_nx=True)
            except dns.resolver.NXDOMAIN:
                print_status(f"Domain {target} does not exist", "error")
                return None
            if vals:
                records[rtype] = vals
                for v in vals:
                    print_status(f"{rtype}: {v}", "success")
        self.results["records"] = records
        try:
            ip = socket.gethostbyname(target)
            self.results["resolved_ip"] = ip
            print_status(f"Resolved IP: {ip}", "success")
        except socket.gaierror:
            self.results["resolved_ip"] = None
        return records

    def _phase_wildcard(self, resolver, target):
        print_status("Phase 2/8  -  Wildcard DNS detection", "info")
        ips_seen = []
        for _ in range(3):
            label = _rand_label(12)
            probe = f"{label}.{target}"
            vals = self._query(resolver, probe, "A")
            if vals:
                ips_seen.append(set(vals))
        detected = bool(ips_seen) and all(ips_seen[0] == s for s in ips_seen[1:])
        wildcard_ip = sorted(ips_seen[0])[0] if detected and ips_seen[0] else None
        self.results["wildcard"] = {
            "detected": detected,
            "ip": wildcard_ip,
            "sample_resolutions": [sorted(s) for s in ips_seen],
        }
        if detected:
            msg = (f"{Colors.RED}{Colors.BOLD}[!] WILDCARD DNS DETECTED{Colors.RESET} "
                   f"- all subdomain brute-force results are suspect "
                   f"(wildcard IP: {wildcard_ip})")
            print(f"  {msg}")
        else:
            print_status("No wildcard DNS entry detected", "success")
        return detected, wildcard_ip

    def _phase_ns_intel(self, resolver, target):
        print_status("Phase 3/8  -  Nameserver intelligence", "info")
        ns_list = self._query(resolver, target, "NS")
        ns_info = []
        providers = set()
        ns_ip_map = {}
        for ns_raw in ns_list:
            ns = ns_raw.rstrip(".")
            provider = _fingerprint_ns(ns)
            if provider:
                providers.add(provider)
            ips = []
            for rt in ("A", "AAAA"):
                ips += self._query(resolver, ns, rt)
            ns_ip_map[ns] = ips
            ns_info.append({"ns": ns, "ips": ips, "provider": provider})
            tag = f" [{Colors.CYAN}{provider}{Colors.RESET}]" if provider else ""
            print_status(f"NS {ns} -> {', '.join(ips) if ips else 'no-ip'}{tag}", "success")
        self.results["nameservers_info"] = ns_info
        self.results["ns_providers"] = sorted(providers)
        if providers:
            print_status(f"DNS hosted by: {', '.join(sorted(providers))}", "success")
        return ns_info, ns_ip_map

    def _phase_email_security(self, resolver, target):
        print_status("Phase 4/8  -  Email security (SPF / DMARC / DKIM / MTA-STS)", "info")

        # SPF (lives in the apex TXT)
        spf_parsed = None
        for txt in self.results.get("records", {}).get("TXT", []):
            clean = txt.strip('"')
            if clean.lower().startswith("v=spf1"):
                spf_parsed = _parse_spf(clean)
                print_status(f"SPF: {clean}", "success")
                break

        # DMARC
        dmarc_parsed = None
        for raw in self._query(resolver, f"_dmarc.{target}", "TXT"):
            clean = raw.strip('"').replace('" "', "")
            if clean.lower().startswith("v=dmarc1"):
                dmarc_parsed = _parse_dmarc(clean)
                print_status(f"DMARC: {clean}", "success")
                break
        if not dmarc_parsed:
            print_status("No DMARC record found", "warning")

        # DKIM selectors
        dkim_hits = {}
        if self._bool_opt("DKIM_PROBE"):
            def probe(sel):
                vals = self._query(resolver, f"{sel}._domainkey.{target}", "TXT")
                return sel, bool(vals), vals
            with ThreadPoolExecutor(max_workers=10) as ex:
                for sel, ok, vals in ex.map(probe, DKIM_SELECTORS):
                    dkim_hits[sel] = ok
                    if ok:
                        print_status(f"DKIM selector found: {sel}", "success")

        # MTA-STS
        mta_sts_vals = self._query(resolver, f"_mta-sts.{target}", "TXT")
        mta_sts = any(v.lower().strip('"').startswith("v=stsv1") for v in mta_sts_vals)
        if mta_sts:
            print_status("MTA-STS policy TXT found", "success")

        mx_records = self.results.get("records", {}).get("MX", [])
        includes = spf_parsed["includes"] if spf_parsed else []
        providers = _detect_mail_providers(includes, mx_records, dkim_hits)
        grade = _email_security_grade(spf_parsed, dmarc_parsed, dkim_hits)
        grade_color = {"A": Colors.GREEN, "B": Colors.GREEN,
                       "C": Colors.YELLOW, "D": Colors.YELLOW,
                       "F": Colors.RED}.get(grade, Colors.YELLOW)

        self.results["email_security"] = {
            "spf": spf_parsed,
            "dmarc": dmarc_parsed,
            "dkim_selectors": dkim_hits,
            "mta_sts": mta_sts,
            "mail_providers_detected": providers,
            "grade": grade,
        }
        print(f"  {Colors.BOLD}Email security grade:{Colors.RESET} "
              f"{grade_color}{Colors.BOLD}{grade}{Colors.RESET}")
        if providers:
            print_status(f"Mail providers detected: {', '.join(providers)}", "success")

    def _phase_common_subs(self, resolver, target, wildcard_ip):
        if not self._bool_opt("COMMON_PROBE"):
            self.results["common_subdomains_found"] = []
            return
        print_status(f"Phase 5/8  -  Probing {len(COMMON_SUBS)} common subdomains", "info")

        def probe(sub):
            fqdn = f"{sub}.{target}"
            vals = self._query(resolver, fqdn, "A")
            return sub, fqdn, vals

        found = []
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(probe, s) for s in COMMON_SUBS]
            for fut in as_completed(futs):
                sub, fqdn, vals = fut.result()
                if not vals:
                    continue
                # Filter out wildcard-poisoned responses
                if wildcard_ip and vals == [wildcard_ip]:
                    continue
                entry = {"subdomain": fqdn, "ips": vals}
                found.append(entry)
                print_status(f"{fqdn} -> {', '.join(vals)}", "success")
        found.sort(key=lambda e: e["subdomain"])
        self.results["common_subdomains_found"] = found
        print_status(f"Common subdomain probe found {len(found)} live hosts", "info")

    def _phase_recursive_vs_auth(self, resolver, target, ns_ip_map):
        print_status("Phase 6/8  -  Resolver vs authoritative consistency", "info")
        resolver_vals = set(self._query(resolver, target, "A"))
        inconsistencies = []
        for ns, ips in ns_ip_map.items():
            for nsip in ips:
                try:
                    socket.inet_aton(nsip)  # IPv4 only for direct udp query
                except Exception:
                    continue
                direct = _resolve_a_direct(nsip, target)
                if direct is None:
                    continue
                if set(direct) != resolver_vals:
                    inconsistencies.append({
                        "ns": ns, "ns_ip": nsip,
                        "resolver": sorted(resolver_vals),
                        "authoritative": direct,
                    })
                    print_status(
                        f"Inconsistency: resolver={sorted(resolver_vals)} vs "
                        f"{ns}({nsip})={direct}", "warning")
                break  # one IPv4 per NS is enough
        self.results["dns_inconsistencies"] = inconsistencies
        if not inconsistencies:
            print_status("Resolver and authoritative answers match", "success")

    def _phase_caa(self):
        print_status("Phase 7/8  -  CAA records -> authorized CAs", "info")
        caa_raw = self.results.get("records", {}).get("CAA", [])
        self.results["caa_records"] = caa_raw
        cas = set()
        for raw in caa_raw:
            m = re.search(r'\b(?:issue|issuewild)\s+"?([^"\s]+)"?', raw, re.I)
            if m and m.group(1) != ";":
                cas.add(m.group(1))
        self.results["ca_authorized"] = sorted(cas)
        if cas:
            print_status(f"CAs authorized to issue certs: {', '.join(sorted(cas))}", "success")
        else:
            print_status("No CAA records (any CA may issue)", "warning")

    def _phase_axfr(self, dns_server, target, ns_ip_map):
        print_status("Phase 8/8  -  Zone transfer (AXFR) attempts", "info")
        results_per_ns = {}
        targets = []
        if self._bool_opt("AXFR_PER_NS") and ns_ip_map:
            for ns, ips in ns_ip_map.items():
                for ip in ips:
                    try:
                        socket.inet_aton(ip)
                    except Exception:
                        continue
                    targets.append((ns, ip))
                    break
        else:
            targets.append(("resolver", dns_server))

        for ns, ip in targets:
            try:
                xfr = dns.zone.from_xfr(dns.query.xfr(ip, target, timeout=10))
                nodes = [str(n) for n in xfr.nodes.keys()]
                results_per_ns[ns] = {"status": "allowed", "records": nodes}
                print_status(f"AXFR allowed on {ns} ({ip}) - {len(nodes)} records!",
                             "success")
            except dns.exception.Timeout:
                results_per_ns[ns] = {"status": "timeout"}
                print_status(f"AXFR timeout on {ns} ({ip})", "warning")
            except Exception as e:
                et = type(e).__name__.lower()
                status = "refused" if "refused" in et or "notzone" in et else "refused"
                results_per_ns[ns] = {"status": status, "error": str(e)}
        self.results["axfr_per_ns"] = results_per_ns
        if not any(v.get("status") == "allowed" for v in results_per_ns.values()):
            print_status("Zone transfer refused by all nameservers", "info")

    # ----------------------------- main ---------------------------------
    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip().rstrip(".")
        if not (is_valid_domain(target) or is_valid_ip(target)):
            print_status(f"TARGET must be a domain or IP: '{target}'", "error")
            return False

        dns_server = (self.get_option("DNS_SERVER") or "8.8.8.8").strip()
        print_status(f"Starting advanced DNS enumeration on {target}", "info")

        resolver = _mk_resolver([dns_server] if dns_server else None, timeout=5)

        self.results = {
            "target": target,
            "dns_server": dns_server,
            "records": {},
        }

        # Phase 1 - standard records
        try:
            records = self._phase_records(resolver, target)
        except Exception as e:
            print_status(f"Record enumeration failed: {e}", "error")
            return False
        if records is None:
            return False

        # Phase 2 - wildcard
        try:
            _, wildcard_ip = self._phase_wildcard(resolver, target)
        except Exception as e:
            print_status(f"Wildcard check failed: {e}", "warning")
            wildcard_ip = None

        # Phase 3 - NS intel
        try:
            _, ns_ip_map = self._phase_ns_intel(resolver, target)
        except Exception as e:
            print_status(f"NS intelligence failed: {e}", "warning")
            ns_ip_map = {}

        # Phase 4 - email security
        try:
            self._phase_email_security(resolver, target)
        except Exception as e:
            print_status(f"Email security analysis failed: {e}", "warning")

        # Phase 5 - common subdomain probe
        try:
            self._phase_common_subs(resolver, target, wildcard_ip)
        except Exception as e:
            print_status(f"Common subdomain probe failed: {e}", "warning")

        # Phase 6 - resolver vs authoritative
        try:
            self._phase_recursive_vs_auth(resolver, target, ns_ip_map)
        except Exception as e:
            print_status(f"Consistency check failed: {e}", "warning")

        # Phase 7 - CAA
        try:
            self._phase_caa()
        except Exception as e:
            print_status(f"CAA analysis failed: {e}", "warning")

        # Phase 8 - AXFR per NS
        try:
            self._phase_axfr(dns_server, target, ns_ip_map)
        except Exception as e:
            print_status(f"AXFR failed: {e}", "warning")

        total = sum(len(v) for v in self.results["records"].values())
        subs_found = len(self.results.get("common_subdomains_found", []))
        print_status(
            f"DNS enumeration complete. {total} base records, "
            f"{subs_found} common subdomains, "
            f"grade {self.results.get('email_security', {}).get('grade', '?')}",
            "info")
        return True
