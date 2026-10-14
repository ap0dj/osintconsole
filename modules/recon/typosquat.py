"""Typosquatting / lookalike domain discovery.

Generates plausible lookalike permutations of a domain and reports which ones
are actually REGISTERED (i.e. resolve to an A record). Only domains that really
resolve are reported -- no fabricated positives.
"""
import socket
import random
import string
import concurrent.futures

from core.base_module import BaseModule
from core.utils import print_status, is_valid_domain

# Adjacent keys on a QWERTY keyboard (used for fat-finger replacements).
QWERTY = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg", "y": "tugh",
    "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}

# Simple visual look-alike substitutions.
HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}

TLD_SWAPS = ["com", "net", "org", "co", "io", "info"]

MAX_CANDIDATES = 400


class Typosquat(BaseModule):
    name = "recon/typosquat"
    description = "Generate lookalike domains and detect which are registered"
    category = "recon"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain (e.g. example.com)")
        self.add_option("THREADS", "30", False, "Resolver threads")

    def _permutations(self, name, tld):
        """Build a deduplicated set of lookalike full domains."""
        variants = set()
        n = len(name)

        # Character omission.
        for i in range(n):
            variants.add(name[:i] + name[i + 1:])

        # Adjacent character swap.
        for i in range(n - 1):
            chars = list(name)
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            variants.add("".join(chars))

        # Replacement with an adjacent QWERTY key.
        for i, ch in enumerate(name):
            for repl in QWERTY.get(ch.lower(), ""):
                variants.add(name[:i] + repl + name[i + 1:])

        # Character duplication.
        for i in range(n):
            variants.add(name[:i + 1] + name[i] + name[i + 1:])

        # Homoglyph substitution.
        for i, ch in enumerate(name):
            sub = HOMOGLYPHS.get(ch.lower())
            if sub:
                variants.add(name[:i] + sub + name[i + 1:])

        # Build full domains from the name variants (keeping original TLD).
        domains = set()
        for v in variants:
            v = v.strip(".")
            if v and v != name:
                domains.add(f"{v}.{tld}")

        # Common TLD swaps on the original name.
        for t in TLD_SWAPS + [tld]:
            domains.add(f"{name}.{t}")

        # Never report the original domain itself.
        domains.discard(f"{name}.{tld}")
        return domains

    @staticmethod
    def _resolve(domain):
        try:
            ip = socket.gethostbyname(domain)
            return (domain, ip)
        except Exception:
            return None

    def _wildcard_ips(self):
        """Resolve guaranteed-nonexistent domains. If they resolve, the resolver
        is hijacking NXDOMAIN (ISP catch-all) -> those IPs are false positives."""
        ips = set()
        for tld in ("com", "net", "org"):
            rnd = "zzqx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
            res = self._resolve(f"{rnd}.{tld}")
            if res:
                ips.add(res[1])
        return ips

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip().lower().rstrip(".")

        self.results = {
            "domain": target,
            "candidates_generated": 0,
            "registered": [],
            "registered_count": 0,
        }

        if not is_valid_domain(target):
            print_status(f"Invalid domain: {target}", "error")
            return True

        if "." not in target:
            print_status("Target must include a TLD", "error")
            return True

        name, tld = target.split(".", 1)
        if not name:
            print_status("Could not split domain into name + TLD", "error")
            return True

        candidates = sorted(self._permutations(name, tld))
        if len(candidates) > MAX_CANDIDATES:
            candidates = candidates[:MAX_CANDIDATES]
        self.results["candidates_generated"] = len(candidates)

        if not candidates:
            print_status("No candidates generated", "warning")
            return True

        try:
            threads = max(1, int(self.get_option("THREADS")))
        except (TypeError, ValueError):
            threads = 30

        # Detect ISP NXDOMAIN hijacking so we don't report every candidate as registered.
        wildcard_ips = self._wildcard_ips()
        self.results["resolver_hijacking"] = bool(wildcard_ips)
        if wildcard_ips:
            print_status(
                f"Resolver returns IPs for nonexistent domains (NXDOMAIN hijacking): "
                f"{', '.join(sorted(wildcard_ips))}. Filtering those to avoid false positives.",
                "warning")

        print_status(
            f"Generated {len(candidates)} lookalike candidates; "
            f"checking registration with {threads} threads", "info")

        registered = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for result in executor.map(self._resolve, candidates):
                if result:
                    domain, ip = result
                    if ip in wildcard_ips:
                        continue  # hijack artifact, not a real registration
                    registered.append({"domain": domain, "ip": ip})
                    print_status(f"Registered: {domain} -> {ip}", "success")

        registered.sort(key=lambda r: r["domain"])
        self.results["registered"] = registered
        self.results["registered_count"] = len(registered)

        print_status(
            f"Done. {len(registered)}/{len(candidates)} lookalikes are registered",
            "info")
        return True
