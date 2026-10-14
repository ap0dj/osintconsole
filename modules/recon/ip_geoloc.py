import socket
from core.base_module import BaseModule
from core.utils import print_status, is_valid_ip
from core import geoip


class IpGeoloc(BaseModule):
    name = "recon/ip_geoloc"
    description = "IP geolocation and network information lookup"
    category = "recon"
    target_type = "domain/ip"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target IP or domain")

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")

        if not is_valid_ip(target):
            try:
                ip = socket.gethostbyname(target)
                print_status(f"Resolved {target} to {ip}", "info")
            except socket.gaierror:
                print_status(f"Cannot resolve {target}", "error")
                return False
        else:
            ip = target

        print_status(f"Looking up geolocation for {ip}", "info")

        data = geoip.lookup(ip)
        if not data:
            print_status("Geolocation lookup failed (ip-api and ipwho.is both "
                         "unavailable)", "error")
            self.results = {"target": target, "ip": ip, "error": "fetch_failed"}
            return False

        self.results = {
            "target": target,
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "zip": data.get("zip"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "asname": data.get("asname"),
            "reverse": data.get("reverse"),
            "mobile": data.get("mobile"),
            "proxy": data.get("proxy"),
            "hosting": data.get("hosting"),
            "source": data.get("_source"),
        }
        for key, value in self.results.items():
            if value and key not in ("target",):
                print_status(f"{key}: {value}", "success")
        return True
