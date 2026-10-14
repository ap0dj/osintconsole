import whois
from core.base_module import BaseModule
from core.utils import print_status, is_valid_domain, is_valid_ip


class WhoisLookup(BaseModule):
    name = "recon/whois_lookup"
    description = "WHOIS domain/IP registration information lookup"
    category = "recon"
    target_type = "domain/ip"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain or IP")

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        if not (is_valid_domain(target) or is_valid_ip(target)):
            print_status(f"TARGET must be a domain or IP: '{target}'", "error")
            return False

        print_status(f"Running WHOIS lookup on {target}", "info")

        try:
            w = whois.whois(target)
            self.results = {
                "target": target,
                "registrar": w.registrar,
                "whois_server": w.whois_server,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "emails": w.emails if w.emails else [],
                "dnssec": w.dnssec,
                "name": w.name,
                "org": w.org,
                "address": w.address,
                "city": w.city,
                "state": w.state,
                "country": w.country,
                "registrant_postal_code": w.registrant_postal_code,
            }

            for key, value in self.results.items():
                if value and key != "target":
                    print_status(f"{key}: {value}", "success")

            print_status("WHOIS lookup complete", "info")
            return True

        except Exception as e:
            print_status(f"WHOIS lookup failed: {e}", "error")
            return False
