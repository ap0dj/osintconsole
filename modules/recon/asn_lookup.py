import socket
from core.base_module import BaseModule
from core.utils import print_status, is_valid_ip
from core.config import Config
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


class AsnLookup(FetchErrorsMixin, BaseModule):
    name = "recon/asn_lookup"
    description = "ASN lookup - BGP info, IP ranges, network owner, peering"
    category = "recon"
    target_type = "domain/ip/asn"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain, IP, or ASN (e.g., AS13335)")

    def _lookup_by_ip(self, ip):
        data = {}
        try:
            resp = http.get(f"https://api.bgpview.io/ip/{ip}", timeout=10)
            if resp.status_code != 200:
                self._note_error(f"BGPView IP lookup HTTP {resp.status_code}")
                return data
            result = resp.json().get("data", {})
            prefixes = result.get("rir_allocation", {})
            ptr = result.get("ptr_record")
            asns = result.get("prefixes", [])
            data["ip"] = ip
            data["ptr_record"] = ptr
            data["rir"] = prefixes.get("rir_name")
            data["allocation_status"] = prefixes.get("allocation_status")
            data["prefix"] = prefixes.get("prefix")
            data["associated_asns"] = []
            for prefix_entry in asns:
                asn_info = prefix_entry.get("asn", {})
                data["associated_asns"].append({
                    "asn": asn_info.get("asn"),
                    "name": asn_info.get("name"),
                    "description": asn_info.get("description"),
                    "prefix": prefix_entry.get("prefix"),
                    "country": asn_info.get("country_code"),
                })
        except Exception as e:
            self._note_error(f"BGPView IP lookup failed: {e}")
        return data

    def _lookup_by_asn(self, asn):
        asn_num = asn.upper().replace("AS", "")
        data = {}
        try:
            resp = http.get(f"https://api.bgpview.io/asn/{asn_num}", timeout=10)
            if resp.status_code != 200:
                self._note_error(f"BGPView ASN lookup HTTP {resp.status_code}")
            else:
                result = resp.json().get("data", {})
                data["asn"] = result.get("asn")
                data["name"] = result.get("name")
                data["description_short"] = result.get("description_short")
                data["description_full"] = result.get("description_full")
                data["country_code"] = result.get("country_code")
                data["website"] = result.get("website")
                data["email_contacts"] = result.get("email_contacts", [])
                data["abuse_contacts"] = result.get("abuse_contacts", [])
                data["looking_glass"] = result.get("looking_glass")
                data["traffic_estimation"] = result.get("traffic_estimation")
                rir = result.get("rir_allocation", {})
                data["rir"] = rir.get("rir_name")
                data["date_allocated"] = rir.get("date_allocated")
        except Exception as e:
            self._note_error(f"BGPView ASN lookup failed: {e}")

        try:
            resp2 = http.get(f"https://api.bgpview.io/asn/{asn_num}/prefixes", timeout=10)
            if resp2.status_code == 200:
                result2 = resp2.json().get("data", {})
                ipv4 = result2.get("ipv4_prefixes", [])
                ipv6 = result2.get("ipv6_prefixes", [])
                data["ipv4_prefixes"] = [p.get("prefix") for p in ipv4]
                data["ipv6_prefixes"] = [p.get("prefix") for p in ipv6]
                data["total_ipv4_prefixes"] = len(ipv4)
                data["total_ipv6_prefixes"] = len(ipv6)
            else:
                self._note_error(f"BGPView ASN prefixes HTTP {resp2.status_code}")
        except Exception as e:
            self._note_error(f"BGPView ASN prefixes failed: {e}")

        try:
            resp3 = http.get(f"https://api.bgpview.io/asn/{asn_num}/peers", timeout=10)
            if resp3.status_code == 200:
                result3 = resp3.json().get("data", {})
                peers = result3.get("ipv4_peers", [])
                data["peers"] = [{"asn": p.get("asn"), "name": p.get("name"),
                                  "country": p.get("country_code")} for p in peers[:20]]
                data["total_peers"] = len(peers)
            else:
                self._note_error(f"BGPView ASN peers HTTP {resp3.status_code}")
        except Exception as e:
            self._note_error(f"BGPView ASN peers failed: {e}")

        return data

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        print_status(f"Running ASN/BGP lookup on {target}", "info")

        self._errors = []
        if target.upper().startswith("AS"):
            self.results = self._lookup_by_asn(target)
        elif is_valid_ip(target):
            self.results = self._lookup_by_ip(target)
        else:
            try:
                ip = socket.gethostbyname(target)
                print_status(f"Resolved {target} -> {ip}", "info")
                self.results = self._lookup_by_ip(ip)
                self.results["domain"] = target
            except socket.gaierror:
                print_status(f"Cannot resolve {target}", "error")
                return False

        # BGPView unreachable/erroring and nothing came back -> fetch failure,
        # not "this target has no ASN/BGP footprint".
        meaningful = {k: v for k, v in self.results.items() if k != "domain"}
        if not meaningful and getattr(self, "_errors", []):
            self.results = {"target": target}
            return self._fail()
        self.results["fetch_errors"] = list(getattr(self, "_errors", []))

        for key, value in self.results.items():
            if value and not isinstance(value, (list, dict)):
                print_status(f"{key}: {value}", "success")
            elif isinstance(value, list) and len(value) <= 10:
                for item in value:
                    if isinstance(item, dict):
                        line = " | ".join(f"{k}={v}" for k, v in item.items() if v)
                        print_status(f"  {line}", "success")
                    else:
                        print_status(f"  {item}", "success")

        print_status("ASN/BGP lookup complete", "info")
        return True
