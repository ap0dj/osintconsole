import socket
import dns.resolver
import dns.reversename
import dns.exception
import ipaddress
from core.base_module import BaseModule
from core.utils import print_status, is_valid_ip
from modules.harvest.crypto_transactions import FetchErrorsMixin


class ReverseDns(FetchErrorsMixin, BaseModule):
    name = "recon/reverse_dns"
    description = "Reverse DNS lookup and neighbor IP discovery"
    category = "recon"
    target_type = "ip"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target IP address")
        self.add_option("RANGE", "0", False, "Scan neighboring IPs (e.g., 16 for /28 range)")

    def _reverse_lookup(self, ip):
        """Return (hostnames, failed).

        failed=True means the lookup itself errored (resolver timeout / SERVFAIL
        / no reachable nameserver) and the result is unknown -- this must NOT be
        reported as "no PTR record". failed=False with an empty list is a genuine
        absence of a PTR record.
        """
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            return [str(rdata) for rdata in answers], False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], False  # genuine: IP has no PTR record
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            pass  # transient failure -> try the system resolver before giving up
        except Exception:
            pass
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return [hostname], False
        except socket.herror:
            return [], False  # genuine: host not found / no PTR
        except Exception:
            return [], True   # gaierror / timeout -> lookup failed, unknown

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")

        if not is_valid_ip(target):
            try:
                target = socket.gethostbyname(target)
                print_status(f"Resolved to IP: {target}", "info")
            except socket.gaierror:
                print_status(f"Cannot resolve target", "error")
                return False

        scan_range = int(self.get_option("RANGE") or 0)
        print_status(f"Running reverse DNS on {target}", "info")

        self._errors = []
        results_map = {}
        hostnames, target_failed = self._reverse_lookup(target)
        if hostnames:
            results_map[target] = hostnames
            for h in hostnames:
                print_status(f"{target} -> {h}", "success")
        elif target_failed:
            self._note_error(
                f"Reverse DNS lookup for {target} failed "
                f"(resolver timeout/SERVFAIL/no nameserver)")
        else:
            print_status(f"{target} -> No PTR record", "warning")

        if scan_range > 0:
            print_status(f"Scanning {scan_range} neighboring IPs", "info")
            base_ip = ipaddress.IPv4Address(target)
            for offset in range(-scan_range // 2, scan_range // 2 + 1):
                if offset == 0:
                    continue
                try:
                    neighbor = str(base_ip + offset)
                    hostnames, _ = self._reverse_lookup(neighbor)
                    if hostnames:
                        results_map[neighbor] = hostnames
                        for h in hostnames:
                            print_status(f"{neighbor} -> {h}", "success")
                except Exception:
                    pass

        self.results = {
            "target": target,
            "range_scanned": scan_range,
            "records": results_map,
            "total_found": len(results_map),
            "fetch_errors": list(getattr(self, "_errors", [])),
        }

        # The primary target's lookup failed and nothing resolved at all: this is
        # a fetch failure, NOT evidence the IP has no PTR record.
        if target_failed and not results_map:
            self.results["error"] = "fetch_failed"
            print_status(
                "Reverse DNS FAILED - resolver unreachable/timeout; this is NOT "
                "evidence the IP has no PTR record", "error")
            return False

        print_status(f"Reverse DNS complete. {len(results_map)} records found", "info")
        return True
