import re
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.config import Config
from core import http

# Optional: Google's libphonenumber gives region, carrier, line type, timezone
# and validity fully offline with no key. Used when installed; the module still
# works (country + dorks) without it.
try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pn_timezone
    _HAS_PHONENUMBERS = True
except ImportError:
    _HAS_PHONENUMBERS = False


COUNTRY_CODES = {
    "1": "US/Canada", "7": "Russia/Kazakhstan", "20": "Egypt", "27": "South Africa",
    "30": "Greece", "31": "Netherlands", "32": "Belgium", "33": "France",
    "34": "Spain", "39": "Italy", "40": "Romania", "41": "Switzerland",
    "44": "United Kingdom", "45": "Denmark", "46": "Sweden", "47": "Norway",
    "48": "Poland", "49": "Germany", "52": "Mexico", "55": "Brazil",
    "60": "Malaysia", "61": "Australia", "62": "Indonesia", "63": "Philippines",
    "64": "New Zealand", "65": "Singapore", "66": "Thailand", "81": "Japan",
    "82": "South Korea", "84": "Vietnam", "86": "China", "90": "Turkey",
    "91": "India", "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka",
    "95": "Myanmar", "98": "Iran", "212": "Morocco", "213": "Algeria",
    "216": "Tunisia", "218": "Libya", "220": "Gambia", "233": "Ghana",
    "234": "Nigeria", "249": "Sudan", "251": "Ethiopia", "254": "Kenya",
    "256": "Uganda", "260": "Zambia", "263": "Zimbabwe", "352": "Luxembourg",
    "353": "Ireland", "354": "Iceland", "358": "Finland", "359": "Bulgaria",
    "370": "Lithuania", "371": "Latvia", "372": "Estonia", "380": "Ukraine",
    "420": "Czech Republic", "421": "Slovakia", "961": "Lebanon", "962": "Jordan",
    "963": "Syria", "964": "Iraq", "965": "Kuwait", "966": "Saudi Arabia",
    "967": "Yemen", "968": "Oman", "970": "Palestine", "971": "UAE",
    "972": "Israel", "973": "Bahrain", "974": "Qatar", "975": "Bhutan",
    "976": "Mongolia", "977": "Nepal",
}


class PhoneOsint(BaseModule):
    name = "harvest/phone_osint"
    description = "Phone number OSINT - country, carrier, line type, dorks (numverify/abstract optional)"
    category = "harvest"
    target_type = "phone"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Phone number with country code (e.g. +9647701234567)")

    def _normalize(self, number):
        digits = re.sub(r"[^\d+]", "", number)
        if not digits.startswith("+"):
            digits = "+" + digits
        return digits

    def _detect_country(self, number):
        bare = number.lstrip("+")
        for length in (3, 2, 1):
            prefix = bare[:length]
            if prefix in COUNTRY_CODES:
                return prefix, COUNTRY_CODES[prefix]
        return None, "Unknown"

    def _numverify(self, number, key):
        try:
            resp = http.get("https://apilayer.net/api/validate", params={
                "access_key": key, "number": number.lstrip("+"),
            })
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    return {
                        "valid": True,
                        "country": data.get("country_name"),
                        "location": data.get("location"),
                        "carrier": data.get("carrier"),
                        "line_type": data.get("line_type"),
                        "international_format": data.get("international_format"),
                    }
        except Exception:
            pass
        return {}

    def _abstract(self, number, key):
        try:
            resp = http.get("https://phonevalidation.abstractapi.com/v1/", params={
                "api_key": key, "phone": number.lstrip("+"),
            })
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "valid": data.get("valid"),
                    "carrier": data.get("carrier"),
                    "line_type": (data.get("type") or {}),
                    "country": (data.get("country") or {}).get("name"),
                }
        except Exception:
            pass
        return {}

    def _dorks(self, number):
        bare = number.lstrip("+")
        variants = [number, bare]
        if len(bare) > 4:
            variants.append(f"{bare[:-4]}-{bare[-4:]}")
        dorks = []
        for v in variants:
            dorks.append(f'"{v}"')
        dorks += [
            f'"{bare}" site:facebook.com',
            f'"{bare}" site:linkedin.com',
            f'"{number}" site:truecaller.com',
            f'"{bare}" "whatsapp"',
            f'"{bare}" filetype:pdf OR filetype:xlsx',
        ]
        return dorks

    def _links(self, number):
        bare = number.lstrip("+")
        return {
            "truecaller": f"https://www.truecaller.com/search/intl/{bare}",
            "whatsapp": f"https://wa.me/{bare}",
            "telegram_hint": "Add the number as a contact to reveal a Telegram account",
            "google": f"https://www.google.com/search?q=%22{bare}%22",
        }

    def _libphonenumber(self, number):
        """Offline region/carrier/line-type/timezone/validity via libphonenumber."""
        try:
            parsed = phonenumbers.parse(number, None)
        except Exception:
            return None
        if not phonenumbers.is_possible_number(parsed):
            return None
        ntype = phonenumbers.number_type(parsed)
        type_names = {
            getattr(phonenumbers.PhoneNumberType, n): n.lower().replace("_", " ")
            for n in ("MOBILE", "FIXED_LINE", "FIXED_LINE_OR_MOBILE", "VOIP",
                      "TOLL_FREE", "PREMIUM_RATE", "SHARED_COST", "PAGER",
                      "PERSONAL_NUMBER", "UAN", "VOICEMAIL")
        }
        return {
            "valid": phonenumbers.is_valid_number(parsed),
            "region": geocoder.description_for_number(parsed, "en") or None,
            "carrier": carrier.name_for_number(parsed, "en") or None,
            "line_type": type_names.get(ntype, "unknown"),
            "timezones": list(pn_timezone.time_zones_for_number(parsed)),
            "e164": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164),
        }

    def run(self):
        if not self.validate():
            return False

        raw = self.get_option("TARGET").strip()
        number = self._normalize(raw)
        config = Config()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Phone OSINT: {number}")
        print(f"{'='*58}{Colors.RESET}\n")

        code, country = self._detect_country(number)
        print_status(f"Country code: +{code} ({country})" if code
                     else "Could not detect country code", "info" if code else "warning")

        self.results = {
            "input": raw,
            "normalized": number,
            "country_code": code,
            "country": country,
        }

        # Free, offline enrichment when libphonenumber is installed.
        if _HAS_PHONENUMBERS:
            lpn = self._libphonenumber(number)
            if lpn:
                self.results["libphonenumber"] = lpn
                print_status(f"  valid: {lpn['valid']}  region: {lpn['region']}  "
                             f"carrier: {lpn['carrier']}  type: {lpn['line_type']}",
                             "success")
        else:
            print_status("Install 'phonenumbers' for offline carrier/line-type/"
                         "region (no key needed)", "info")

        nv_key = config.get("api_keys.numverify")
        if nv_key:
            print_status("Querying numverify...", "info")
            nv = self._numverify(number, nv_key)
            if nv:
                self.results["numverify"] = nv
                for k, v in nv.items():
                    if v:
                        print_status(f"  {k}: {v}", "success")

        ab_key = config.get("api_keys.abstractapi_phone")
        if ab_key:
            print_status("Querying AbstractAPI...", "info")
            ab = self._abstract(number, ab_key)
            if ab:
                self.results["abstractapi"] = ab
                for k, v in ab.items():
                    if v:
                        print_status(f"  {k}: {v}", "success")

        if not nv_key and not ab_key:
            print_status("No phone API key set (numverify/abstractapi) - "
                         "offline analysis only", "warning")

        self.results["dorks"] = self._dorks(number)
        self.results["lookup_links"] = self._links(number)

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary")
        print(f"{'─'*58}{Colors.RESET}")
        print(f"  Number:  {number}")
        print(f"  Country: {country}")
        print(f"\n  {Colors.CYAN}Lookup links:{Colors.RESET}")
        for name, link in self.results["lookup_links"].items():
            print(f"    {name}: {link}")
        print(f"\n  {Colors.CYAN}Dorks:{Colors.RESET} {len(self.results['dorks'])} generated")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return True
