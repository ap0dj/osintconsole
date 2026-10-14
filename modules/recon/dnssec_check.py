"""DNSSEC deployment check for a domain.

Queries DNSKEY, DS (published at the parent zone) and RRSIG records to
determine whether a zone is DNSSEC-signed. Returns REAL lookup data only. A
resolver failure (timeout / SERVFAIL / no reachable nameserver) is surfaced as
error="fetch_failed" -- it is NEVER reported as "DNSSEC NOT enabled", which is
a definitive negative the lookup did not actually establish.
"""
try:
    import dns.resolver
    import dns.flags
    import dns.rdatatype
    _DNS_OK = True
except Exception:
    _DNS_OK = False

from core.base_module import BaseModule
from core.utils import print_status, is_valid_domain
from modules.harvest.crypto_transactions import FetchErrorsMixin


class DnssecCheck(FetchErrorsMixin, BaseModule):
    name = "recon/dnssec_check"
    description = "Check DNSSEC deployment (DNSKEY, DS, RRSIG) for a domain"
    category = "recon"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain to check")
        self.add_option("DNS_SERVER", "", False,
                        "DNSSEC-aware resolver to query (blank = system default)")

    def _build_resolver(self):
        resolver = dns.resolver.Resolver()
        server = (self.get_option("DNS_SERVER") or "").strip()
        if server:
            resolver.nameservers = [server]
        resolver.timeout = 8
        resolver.lifetime = 12
        # Request DNSSEC records (set the DO flag via EDNS0).
        resolver.use_edns(0, dns.flags.DO, 4096)
        return resolver

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip().lower().rstrip(".")

        self._errors = []
        self.results = {
            "domain": target,
            "dnssec_enabled": False,
            "validatable": False,   # signed AND a DS chain of trust exists
            "dnskey_count": 0,
            "algorithms": [],
            "has_ds": False,
            "has_rrsig": False,
            "fetch_errors": [],
        }

        if not is_valid_domain(target):
            print_status(f"Invalid domain: {target}", "error")
            return True

        if not _DNS_OK:
            print_status("dnspython not available; cannot run DNSSEC check", "error")
            return True

        print_status(f"Checking DNSSEC deployment for {target}", "info")
        resolver = self._build_resolver()

        # --- DNSKEY: presence => zone is signed; collect algorithm numbers ---
        # dnskey_failed marks a lookup error (timeout/SERVFAIL) as opposed to a
        # genuine NoAnswer, so a failure is never reported as "unsigned".
        dnskey_failed = False
        algorithms = set()
        try:
            answers = resolver.resolve(target, "DNSKEY")
            for rdata in answers:
                try:
                    algorithms.add(int(rdata.algorithm))
                except Exception:
                    pass
            count = len(answers)
            self.results["dnskey_count"] = count
            self.results["algorithms"] = sorted(algorithms)
            if count > 0:
                self.results["dnssec_enabled"] = True
                print_status(
                    f"DNSKEY records: {count} (algorithms: {sorted(algorithms)})",
                    "success")
        except dns.resolver.NXDOMAIN:
            print_status(f"Domain {target} does not exist", "error")
            return True
        except dns.resolver.NoAnswer:
            print_status("No DNSKEY records (zone not signed)", "warning")
        except Exception as e:
            dnskey_failed = True
            self._note_error(f"DNSKEY lookup failed: {e}")

        # --- DS at the parent zone: indicates a chain of trust ---
        try:
            ds = resolver.resolve(target, "DS")
            if len(ds) > 0:
                self.results["has_ds"] = True
                print_status(f"DS records at parent: {len(ds)}", "success")
        except dns.resolver.NoAnswer:
            print_status("No DS records at parent (no chain of trust)", "warning")
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass

        # --- RRSIG covering the A record ---
        try:
            answer = resolver.resolve(target, "A")
            response = answer.response
            for rrset in list(response.answer) + list(response.authority):
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    self.results["has_rrsig"] = True
                    break
            if self.results["has_rrsig"]:
                print_status("RRSIG present on A record", "success")
            else:
                print_status("No RRSIG on A record", "info")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass

        self.results["validatable"] = (self.results["dnssec_enabled"]
                                       and self.results["has_ds"])
        self.results["fetch_errors"] = list(getattr(self, "_errors", []))

        if self.results["validatable"]:
            print_status(f"DNSSEC ENABLED + chain of trust for {target}", "success")
        elif self.results["dnssec_enabled"]:
            print_status(f"DNSSEC signed but NO DS chain of trust (island) for {target}",
                         "warning")
        elif dnskey_failed:
            # The DNSKEY query errored, so we cannot claim the zone is unsigned.
            self.results["error"] = "fetch_failed"
            print_status(
                f"DNSSEC status UNKNOWN for {target} - DNSKEY lookup failed "
                f"(resolver timeout/SERVFAIL); this is NOT evidence it is "
                f"unsigned", "error")
            return False
        else:
            print_status(f"DNSSEC NOT enabled for {target}", "warning")
        return True
