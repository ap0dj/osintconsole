import socket
from core.base_module import BaseModule
from core.utils import print_status, is_valid_ip
from core import http


class WhoisIp(BaseModule):
    name = "recon/whois_ip"
    description = "IP WHOIS via RDAP (rdap.org) - network, range, org, abuse contact"
    category = "recon"
    target_type = "domain/ip"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target IP address or domain")

    # ---- jCard / vcardArray helpers -------------------------------------
    def _vcard_value(self, vcard_array, prop):
        """Return the first value of a jCard property (e.g. 'fn', 'email')."""
        try:
            if not vcard_array or len(vcard_array) < 2:
                return None
            for item in vcard_array[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == prop:
                    val = item[3]
                    if isinstance(val, str) and val.strip():
                        return val.strip()
        except Exception:
            pass
        return None

    def _find_abuse_email(self, entities):
        """Walk entities recursively; collect emails from abuse-role contacts."""
        emails = []
        if not isinstance(entities, list):
            return emails
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            roles = ent.get("roles") or []
            if "abuse" in roles:
                email = self._vcard_value(ent.get("vcardArray"), "email")
                if email and "@" in email:
                    emails.append(email)
            emails.extend(self._find_abuse_email(ent.get("entities")))
        return emails

    def _find_org(self, entities):
        """Find an organisation / registrant name from the entity tree."""
        if not isinstance(entities, list):
            return None
        # Prefer the most authoritative roles first.
        for want in ("registrant", "administrative", "technical"):
            for ent in entities:
                if isinstance(ent, dict) and want in (ent.get("roles") or []):
                    name = self._vcard_value(ent.get("vcardArray"), "fn") or ent.get("handle")
                    if name:
                        return name
        # Fall back to any named entity, then recurse into nested ones.
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            name = self._vcard_value(ent.get("vcardArray"), "fn")
            if name:
                return name
            nested = self._find_org(ent.get("entities"))
            if nested:
                return nested
        return None

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()

        if is_valid_ip(target):
            ip = target
        else:
            try:
                ip = socket.gethostbyname(target)
                print_status(f"Resolved {target} -> {ip}", "info")
            except socket.gaierror:
                print_status(f"Cannot resolve {target}", "error")
                return False

        print_status(f"RDAP WHOIS lookup for {ip} (rdap.org)...", "info")

        try:
            resp = http.get(f"https://rdap.org/ip/{ip}")
        except Exception as e:
            print_status(f"RDAP request failed: {e}", "error")
            return False

        if resp.status_code != 200:
            print_status(f"RDAP returned HTTP {resp.status_code} for {ip}", "warning")
            return False

        try:
            data = resp.json()
        except Exception as e:
            print_status(f"Could not parse RDAP JSON: {e}", "error")
            return False

        network_name = data.get("name") or data.get("handle")
        start = data.get("startAddress")
        end = data.get("endAddress")
        range_str = f"{start} - {end}" if start and end else None

        cidr = None
        cidrs = data.get("cidr0_cidrs")
        if isinstance(cidrs, list) and cidrs:
            parts = []
            for c in cidrs:
                if not isinstance(c, dict):
                    continue
                prefix = c.get("v4prefix") or c.get("v6prefix")
                length = c.get("length")
                if prefix and length is not None:
                    parts.append(f"{prefix}/{length}")
            cidr = ", ".join(parts) if parts else None

        entities = data.get("entities") or []
        abuse_emails = self._find_abuse_email(entities)

        self.results = {
            "target": target,
            "ip": ip,
            "network_name": network_name,
            "range": range_str,
            "country": data.get("country"),
            "org": self._find_org(entities),
            "abuse_email": abuse_emails[0] if abuse_emails else None,
            "cidr": cidr,
        }

        for key in ("network_name", "range", "cidr", "country", "org", "abuse_email"):
            if self.results.get(key):
                print_status(f"{key}: {self.results[key]}", "success")

        print_status("RDAP WHOIS lookup complete", "info")
        return True
