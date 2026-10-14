import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_ip
from core.config import Config
from core import http, geoip


# Zones verified live to list the standard 127.0.0.2 test entry. SORBS (both
# zones) and db.wpbl.info were removed: they no longer list even the test
# address, so they could only ever answer "clean" and padded the count.
DNSBL_ZONES = [
    "zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
    "cbl.abuseat.org", "pbl.spamhaus.org", "dnsbl-1.uceprotect.net",
    "psbl.surriel.com", "bl.mailspike.net", "all.s5h.net",
]

# Minimum independent evidence before "CLEAN" may be claimed. Below this the
# verdict is UNKNOWN — absence of data is not absence of risk.
_MIN_INTEL_SOURCES = 2


def _rev(ip):
    return ".".join(reversed(ip.split(".")))


def _interpret(answer):
    """Classify a DNSBL A-record answer.

    listed  : 127.0.0.2 – 127.0.0.255 (real listing codes)
    refused : 127.255.255.x — Spamhaus' 'query refused / public resolver /
              rate limited' codes; NOT a listing
    hijack  : any non-127 answer — the resolver rewrote NXDOMAIN (common ISP
              behaviour); trusting it would mark every IP as listed
    clean   : 127.0.0.1 is used by some lists as 'not listed'
    """
    if not answer.startswith("127."):
        return "hijack"
    if answer.startswith("127.255.255."):
        return "refused"
    if answer == "127.0.0.1":
        return "clean"
    return "listed"


class IpReputation(BaseModule):
    name = "recon/ip_reputation"
    description = (
        "IP reputation - live-verified DNSBLs + free intel (ip-api, InternetDB, "
        "GreyNoise RIOT/noise, OTX) + AbuseIPDB/IPQS APIs when keyed; "
        "UNKNOWN (never CLEAN) when evidence is insufficient"
    )
    category = "recon"
    target_type = "domain/ip"

    def _register_options(self):
        self.add_option("TARGET", "", True, "IP address or domain")
        self.add_option("THREADS", "12", False, "Concurrent DNSBL lookups")

    # ------------------------------------------------------------------ #
    # DNSBL                                                               #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _resolve(name):
        try:
            return socket.gethostbyname(name)
        except socket.gaierror:
            return None          # NXDOMAIN
        except Exception:
            return "error"

    def _check_zone(self, ip, zone):
        """(zone, status, code). Status: listed / clean / unavailable /
        refused / hijack / error. A zone must list the 127.0.0.2 test entry to
        count — otherwise it is dead or blocked and its 'clean' means nothing."""
        test = self._resolve(f"{_rev('127.0.0.2')}.{zone}")
        if test is None:
            return zone, "unavailable", None
        if test == "error":
            return zone, "error", None
        test_kind = _interpret(test)
        if test_kind in ("hijack", "refused"):
            return zone, test_kind, test

        ans = self._resolve(f"{_rev(ip)}.{zone}")
        if ans is None:
            return zone, "clean", None
        if ans == "error":
            return zone, "error", None
        return zone, _interpret(ans), ans

    # ------------------------------------------------------------------ #
    # Free intel sources                                                  #
    # ------------------------------------------------------------------ #
    def _ip_api(self, ip):
        d = geoip.lookup(ip)
        if not d:
            return {}
        return {
            "country": d.get("country"),
            "isp": d.get("isp"),
            "org": d.get("org"),
            "as": d.get("as"),
            "mobile": d.get("mobile"),
            "proxy": d.get("proxy"),
            "hosting": d.get("hosting"),
            "reverse": d.get("reverse"),
            "source": d.get("_source"),
        }

    def _internetdb(self, ip):
        try:
            resp = http.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 200:
                d = resp.json()
                return {"open_ports": d.get("ports", []),
                        "vulns": d.get("vulns", []),
                        "tags": d.get("tags", []),
                        "hostnames": d.get("hostnames", [])}
            if resp.status_code == 404:
                # Verified live: InternetDB 404s IPs it has no record of.
                return {"_seen": False}
        except Exception:
            pass
        return {}

    def _greynoise(self, ip):
        """GreyNoise Community. 404 = IP not observed (still a valid answer)."""
        try:
            resp = http.get(f"https://api.greynoise.io/v3/community/{ip}",
                            headers={"Accept": "application/json"})
            if resp.status_code in (200, 404):
                d = resp.json()
                d["_seen"] = resp.status_code == 200
                return d
        except Exception:
            pass
        return {}

    def _otx(self, ip):
        try:
            resp = http.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general")
            if resp.status_code == 200:
                d = resp.json()
                pulses = (d.get("pulse_info") or {}).get("pulses", [])
                return {
                    "pulses": (d.get("pulse_info") or {}).get("count", 0),
                    "pulse_names": [p.get("name") for p in pulses[:10]],
                    "reputation": d.get("reputation"),
                    "country": d.get("country_name"),
                    "asn": d.get("asn"),
                    "_answered": True,
                }
        except Exception:
            pass
        return {}

    # ------------------------------------------------------------------ #
    # Paid APIs (only when keyed)                                         #
    # ------------------------------------------------------------------ #
    def _abuseipdb(self, ip, key):
        try:
            resp = http.get("https://api.abuseipdb.com/api/v2/check",
                            headers={"Key": key, "Accept": "application/json"},
                            params={"ipAddress": ip, "maxAgeInDays": 90})
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "abuse_confidence_score": d.get("abuseConfidenceScore"),
                    "total_reports": d.get("totalReports"),
                    "last_reported": d.get("lastReportedAt"),
                    "usage_type": d.get("usageType"),
                    "domain": d.get("domain"),
                }
        except Exception:
            pass
        return {}

    def _ipqs(self, ip, key):
        try:
            resp = http.get(f"https://ipqualityscore.com/api/json/ip/{key}/{ip}")
            if resp.status_code == 200:
                d = resp.json()
                if d.get("success"):
                    return {
                        "fraud_score": d.get("fraud_score"),
                        "vpn": d.get("vpn"),
                        "tor": d.get("tor"),
                        "proxy": d.get("proxy"),
                        "bot_status": d.get("bot_status"),
                        "recent_abuse": d.get("recent_abuse"),
                    }
        except Exception:
            pass
        return {}

    # ------------------------------------------------------------------ #
    @staticmethod
    def _verdict(dnsbl, ipapi, gn, otx, abuse, ipqs, intel_hits):
        """Risk score + verdict from evidence only. Returns (risk, verdict, why)."""
        why = []
        live = [z for z, st, _ in dnsbl if st in ("listed", "clean")]
        listed = [z for z, st, _ in dnsbl if st == "listed"]

        # GreyNoise RIOT = known benign business service (Google DNS, CDNs...).
        if gn.get("riot") and not listed:
            return 0, "BENIGN SERVICE", [
                f"GreyNoise RIOT: {gn.get('name') or 'known business service'}"]

        risk = 0
        if listed:
            risk += len(listed) * 15
            why.append(f"listed on {len(listed)} DNSBL(s)")
        if gn.get("classification") == "malicious":
            risk += 40
            why.append("GreyNoise: malicious")
        elif gn.get("classification") == "suspicious":
            risk += 20
            why.append("GreyNoise: suspicious")
        if otx.get("pulses"):
            risk += min(30, otx["pulses"] * 5)
            why.append(f"{otx['pulses']} OTX pulse(s)")
        if ipapi.get("proxy"):
            # ip-api's proxy flag is a heuristic (verified live: it flags
            # 8.8.8.8, Google DNS), so alone it must never reach SUSPICIOUS.
            risk += 10
            why.append("ip-api heuristic marks it proxy/VPN (weak, uncorroborated)")
        if abuse.get("abuse_confidence_score"):
            risk += abuse["abuse_confidence_score"] // 2
            why.append(f"AbuseIPDB {abuse['abuse_confidence_score']}%")
        if ipqs.get("fraud_score"):
            risk += ipqs["fraud_score"] // 2
            why.append(f"IPQS fraud {ipqs['fraud_score']}")
        risk = min(risk, 100)

        if risk >= 70:
            return risk, "MALICIOUS", why
        if risk >= 35:
            return risk, "SUSPICIOUS", why
        if not live and intel_hits < _MIN_INTEL_SOURCES and not (abuse or ipqs):
            return risk, "UNKNOWN", why + [
                "insufficient evidence - too few sources answered"]
        return risk, "CLEAN", why or ["no negative signal from the sources that answered"]

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        threads = max(1, int(self.get_option("THREADS") or 12))
        config = Config()

        if is_valid_ip(target):
            ip = target
        else:
            try:
                ip = socket.gethostbyname(target)
                print_status(f"Resolved {target} -> {ip}", "info")
            except socket.gaierror:
                print_status(f"Cannot resolve {target}", "error")
                return False

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  IP Reputation: {ip}")
        print(f"{'='*58}{Colors.RESET}\n")

        # --- DNSBL (each zone liveness-checked) ---
        print_status(f"Checking {len(DNSBL_ZONES)} DNS blacklists "
                     f"(each verified live first)...", "info")
        dnsbl = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self._check_zone, ip, z) for z in DNSBL_ZONES]
            for future in as_completed(futures):
                zone, status, code = future.result()
                dnsbl.append((zone, status, code))
                if status == "listed":
                    print_status(f"LISTED on {zone} ({code})", "warning")

        listed = [z for z, st, _ in dnsbl if st == "listed"]
        live = [z for z, st, _ in dnsbl if st in ("listed", "clean")]
        unusable = {st: [z for z, s, _ in dnsbl if s == st]
                    for st in ("unavailable", "refused", "hijack", "error")}
        if unusable["hijack"]:
            print_status("Your DNS resolver rewrites NXDOMAIN (hijack) - DNSBL "
                         "answers ignored rather than trusted", "warning")

        # --- Free intel sources, in parallel ---
        probes = [
            ("ip-api", self._ip_api),
            ("InternetDB", self._internetdb),
            ("GreyNoise", self._greynoise),
            ("AlienVault OTX", self._otx),
        ]
        print_status(f"Querying {len(probes)} free intel sources...", "info")
        collected, failures = {}, []
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_map = {executor.submit(fn, ip): label for label, fn in probes}
            for future in as_completed(future_map):
                label = future_map[future]
                try:
                    data = future.result()
                except Exception:
                    data = {}
                collected[label] = data
                if not data:
                    failures.append(label)
                    print_status(f"{label}: unavailable", "warning")

        ipapi = collected.get("ip-api") or {}
        idb = collected.get("InternetDB") or {}
        gn = collected.get("GreyNoise") or {}
        otx = collected.get("AlienVault OTX") or {}
        intel_hits = len(probes) - len(failures)

        # --- Paid APIs ---
        abuse, ipqs = {}, {}
        ab_key = config.get("api_keys.abuseipdb")
        if ab_key:
            abuse = self._abuseipdb(ip, ab_key)
        qs_key = config.get("api_keys.ipqualityscore")
        if qs_key:
            ipqs = self._ipqs(ip, qs_key)

        risk, verdict, why = self._verdict(dnsbl, ipapi, gn, otx, abuse, ipqs,
                                           intel_hits)

        # Known CVEs on exposed services = EXPOSURE, not maliciousness.
        exposure = idb.get("vulns") or []

        self.results = {
            "target": target,
            "ip": ip,
            "risk_score": risk,
            "verdict": verdict,
            "verdict_reasons": why,
            "dnsbl_listed": listed,
            "dnsbl_listed_count": len(listed),
            "dnsbl_checked_live": len(live),
            "dnsbl_unusable": {k: v for k, v in unusable.items() if v},
            "network": ipapi,
            "internetdb": idb,
            "greynoise": gn,
            "otx": otx,
            "abuseipdb": abuse,
            "ipqualityscore": ipqs,
            "exposure_cves": exposure,
            "free_sources_hit": intel_hits,
            "free_sources_failed": failures,
        }

        color = (Colors.RED if verdict == "MALICIOUS" else
                 Colors.YELLOW if verdict in ("SUSPICIOUS", "UNKNOWN") else
                 Colors.GREEN)
        print(f"\n{Colors.BOLD}{color}{'='*58}")
        print(f"  Verdict: {verdict}  (risk score {risk}/100)")
        for reason in why:
            print(f"    - {reason}")
        print(f"  Blacklists: {len(listed)} listed / {len(live)} live zones checked"
              + (f"  ({sum(map(len, unusable.values()))} zone(s) unusable)"
                 if any(unusable.values()) else ""))
        print(f"  Intel sources: {intel_hits}/{len(probes)} answered"
              + (f", unavailable: {', '.join(failures)}" if failures else ""))
        if exposure:
            print(f"  Exposure: {len(exposure)} known CVE(s) on exposed services "
                  f"(vulnerable is not the same as malicious)")
        print(f"{'='*58}{Colors.RESET}\n")
        return True
