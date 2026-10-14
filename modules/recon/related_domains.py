import socket

from core.base_module import BaseModule
from core.utils import print_status, is_valid_domain, format_table
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin

# HackerTarget returns these as plain text (HTTP 200) when the free-tier quota
# is spent -- they are failures, not "no related domains".
_HT_ERROR_MARKERS = ("api count exceeded", "api usage exceeded", "error check your")

# Soft-import dns.resolver — NS method is silently skipped when unavailable
try:
    import dns.resolver as _dns
    _DNS_OK = True
except ImportError:
    _dns = None
    _DNS_OK = False


class RelatedDomains(FetchErrorsMixin, BaseModule):
    name = "recon/related_domains"
    description = "Find domains related by registrant, nameservers, IP, or certificate SAN"
    category = "recon"
    target_type = "domain"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain name")
        self.add_option(
            "METHODS", "all", False,
            "Comma-separated: ns,cert,reverse_ip,whois or 'all'"
        )
        self.add_option(
            "SECURITYTRAILS_KEY", "", False,
            "SecurityTrails API key for WHOIS-based discovery"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _resolve_ip(self, domain):
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def _is_subdomain_of(self, candidate, parent):
        """Return True if candidate is the parent or a subdomain of it."""
        return candidate == parent or candidate.endswith(f".{parent}")

    # ------------------------------------------------------------------
    # Method 1 – Certificate SANs via crt.sh
    # ------------------------------------------------------------------
    def _cert_san(self, domain):
        found = []
        try:
            print_status("Querying crt.sh for certificate SANs...", "info")
            resp = http.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=25,
            )
            if not resp or resp.status_code != 200:
                self._note_error(
                    f"crt.sh HTTP {resp.status_code if resp else 'no response'}")
                return found

            self._any_ok = True
            data = resp.json()
            seen: set = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if (
                        not name
                        or name.startswith("*")
                        or name == domain
                        or name in seen
                        or not is_valid_domain(name)
                    ):
                        continue
                    seen.add(name)
                    found.append({
                        "domain": name,
                        "source": "crt.sh SAN",
                        "note": "certificate SAN",
                    })

            print_status(
                f"crt.sh SAN: {len(found)} related domain(s)",
                "success" if found else "warning",
            )
        except Exception as e:
            self._note_error(f"crt.sh query failed: {e}")
        return found

    # ------------------------------------------------------------------
    # Method 2 – Shared nameserver via HackerTarget
    # ------------------------------------------------------------------
    def _shared_ns(self, domain):
        found = []
        if not _DNS_OK:
            print_status("dns.resolver not installed — skipping NS method", "warning")
            return found
        try:
            print_status("Resolving NS records...", "info")
            ns_records = _dns.resolve(domain, "NS")
            ns_hosts = [str(ns.target).rstrip(".").lower() for ns in ns_records]
            print_status(f"Nameservers: {', '.join(ns_hosts)}", "info")

            seen: set = set()
            for ns_host in ns_hosts:
                try:
                    resp = http.get(
                        f"https://api.hackertarget.com/findshareddns/?q={ns_host}",
                        timeout=20,
                    )
                    if not resp or resp.status_code != 200:
                        self._note_error(
                            f"HackerTarget findshareddns HTTP "
                            f"{resp.status_code if resp else 'no response'} "
                            f"for {ns_host}")
                        continue
                    text = resp.text or ""
                    low = text.lower()
                    if low.startswith("error") or any(m in low for m in _HT_ERROR_MARKERS):
                        self._note_error(
                            f"HackerTarget findshareddns quota/rejection for "
                            f"{ns_host}: {text[:80]}")
                        continue
                    self._any_ok = True
                    for line in text.splitlines():
                        line = line.strip().lower()
                        if (
                            not line
                            or line == domain
                            or line in seen
                            or not is_valid_domain(line)
                        ):
                            continue
                        seen.add(line)
                        found.append({
                            "domain": line,
                            "source": "shared NS",
                            "note": f"NS: {ns_host}",
                        })
                except Exception as inner_e:
                    self._note_error(
                        f"HackerTarget NS lookup failed for {ns_host}: {inner_e}")

            print_status(
                f"Shared NS: {len(found)} related domain(s)",
                "success" if found else "warning",
            )
        except Exception as e:
            self._note_error(f"NS resolution failed: {e}")
        return found

    # ------------------------------------------------------------------
    # Method 3 – Reverse IP via HackerTarget
    # ------------------------------------------------------------------
    def _reverse_ip(self, domain):
        found = []
        ip = self._resolve_ip(domain)
        if not ip:
            print_status(f"Cannot resolve {domain} — skipping reverse IP", "warning")
            return found

        print_status(f"Reverse IP lookup for {ip}...", "info")
        try:
            resp = http.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                timeout=20,
            )
            if not resp or resp.status_code != 200:
                self._note_error(
                    f"HackerTarget reverseiplookup HTTP "
                    f"{resp.status_code if resp else 'no response'}")
                return found

            text = resp.text or ""
            low = text.lower()
            if low.startswith("error") or any(m in low for m in _HT_ERROR_MARKERS):
                self._note_error(
                    f"HackerTarget reverseiplookup quota/rejection: {text[:80]}")
                return found

            self._any_ok = True
            seen: set = set()
            for line in text.splitlines():
                line = line.strip().lower()
                if (
                    not line
                    or line == domain
                    or line in seen
                    or not is_valid_domain(line)
                ):
                    continue
                seen.add(line)
                found.append({
                    "domain": line,
                    "source": "reverse IP",
                    "note": f"IP: {ip}",
                })

            print_status(
                f"Reverse IP: {len(found)} co-hosted domain(s)",
                "success" if found else "warning",
            )
        except Exception as e:
            self._note_error(f"Reverse IP lookup failed: {e}")
        return found

    # ------------------------------------------------------------------
    # Method 4 – WHOIS registrant via SecurityTrails
    # ------------------------------------------------------------------
    def _whois_registrant(self, domain, api_key):
        found = []
        if not api_key:
            return found

        print_status("Querying SecurityTrails WHOIS registrant...", "info")
        try:
            st_headers = {"apikey": api_key, "Accept": "application/json"}

            # Step 1: get registrant email from WHOIS
            resp = http.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/whois",
                headers=st_headers,
                timeout=15,
            )
            if not resp or resp.status_code != 200:
                self._note_error(
                    f"SecurityTrails WHOIS HTTP "
                    f"{resp.status_code if resp else 'no response'}")
                return found

            self._any_ok = True
            whois_data = resp.json()

            # Try several possible paths to the registrant email
            registrant_email = None
            for contact in whois_data.get("contacts", []):
                if contact.get("email"):
                    registrant_email = contact["email"]
                    break
            if not registrant_email:
                registrant_email = (
                    whois_data.get("registrant_info", {}).get("email")
                    or whois_data.get("registrant_email")
                )

            if not registrant_email:
                print_status("No registrant email found in WHOIS response", "warning")
                return found

            print_status(f"Registrant email: {registrant_email}", "info")

            # Step 2: find all domains registered by that email
            resp2 = http.post(
                "https://api.securitytrails.com/v1/domains/list"
                "?include_ips=false&scroll_id=&page=1",
                headers={**st_headers, "Content-Type": "application/json"},
                json={"filter": {"whois_email": registrant_email}},
                timeout=15,
            )
            if not resp2 or resp2.status_code != 200:
                self._note_error(
                    f"SecurityTrails domain-list HTTP "
                    f"{resp2.status_code if resp2 else 'no response'}")
                return found

            data2 = resp2.json()
            seen: set = set()
            for record in data2.get("records", []):
                hostname = (record.get("hostname") or "").strip().lower()
                if (
                    not hostname
                    or hostname == domain
                    or hostname in seen
                    or not is_valid_domain(hostname)
                ):
                    continue
                seen.add(hostname)
                found.append({
                    "domain": hostname,
                    "source": "WHOIS registrant",
                    "note": f"registrant: {registrant_email}",
                })

            print_status(
                f"WHOIS registrant: {len(found)} related domain(s)",
                "success" if found else "warning",
            )
        except Exception as e:
            self._note_error(f"SecurityTrails WHOIS lookup failed: {e}")
        return found

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        target = (self.get_option("TARGET") or "").strip().lower()
        methods_raw = (self.get_option("METHODS") or "all").strip().lower()
        api_key = (self.get_option("SECURITYTRAILS_KEY") or "").strip()

        if methods_raw == "all":
            methods = {"ns", "cert", "reverse_ip", "whois"}
        else:
            methods = {m.strip() for m in methods_raw.split(",") if m.strip()}

        print_status(f"Discovering domains related to: {target}", "info")
        print_status(f"Methods active: {', '.join(sorted(methods))}", "info")

        self._errors = []
        self._any_ok = False
        all_found = []
        sources_breakdown = {}

        if "cert" in methods:
            results = self._cert_san(target)
            all_found.extend(results)
            sources_breakdown["cert"] = len(results)

        if "ns" in methods:
            results = self._shared_ns(target)
            all_found.extend(results)
            sources_breakdown["ns"] = len(results)

        if "reverse_ip" in methods:
            results = self._reverse_ip(target)
            all_found.extend(results)
            sources_breakdown["reverse_ip"] = len(results)

        if "whois" in methods:
            results = self._whois_registrant(target, api_key)
            all_found.extend(results)
            sources_breakdown["whois"] = len(results)

        # Deduplicate: first source wins; drop target itself and its subdomains
        seen_domains: set = set()
        unique = []
        for entry in all_found:
            d = entry["domain"]
            if d in seen_domains or self._is_subdomain_of(d, target):
                continue
            seen_domains.add(d)
            unique.append(entry)

        # Sort alphabetically by domain
        unique.sort(key=lambda x: x["domain"])

        self.results = {
            "target": target,
            "related_domains": unique,
            "total_found": len(unique),
            "methods_used": sorted(methods),
            "sources_breakdown": sources_breakdown,
            "fetch_errors": list(getattr(self, "_errors", [])),
        }

        # Every method that ran errored (and none returned a usable response)
        # with nothing found -> this is a fetch failure, NOT "no related domains".
        if not unique and self._errors and not self._any_ok:
            self.results["error"] = "fetch_failed"
            print_status(
                "Related-domain discovery FAILED - every source errored or was "
                "rate-limited; this is NOT evidence there are no related domains",
                "error")
            return False

        # Print results table
        if unique:
            rows = [[e["domain"], e["source"], e["note"]] for e in unique]
            print(f"\n{format_table(['Domain', 'Source', 'Notes'], rows)}\n")
        else:
            print_status("No related domains discovered", "warning")

        print_status(f"Total related domains found: {len(unique)}", "info")
        if self._errors:
            print_status(
                f"({len(self._errors)} source(s) errored - results may be partial)",
                "warning")
        return True
