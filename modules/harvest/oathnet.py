"""OathNet OSINT / breach-intelligence lookups (docs.oathnet.org).

A keyed provider like IntelX: one API, many point lookups. Endpoints, params,
auth and the response envelope are taken verbatim from the official OpenAPI
spec (https://docs.oathnet.org/openapi.yaml):

  base  : https://oathnet.org/api/service
  auth  : x-api-key header
  method: GET, parameters as query string
  shape : {success, message, data, lookups_left, search_session:{id}}

Every lookup returns the FULL `data` payload untouched (nothing is dropped or
cherry-picked), plus a flattened human view, so a rich result such as an Xbox
profile is shown in full. Read-only; results handle personal/breach data, so
use only for authorised investigations (the owner's standing rule).
"""
import re

from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_ip, is_valid_domain
from core.config import Config
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DISCORD_ID_RE = re.compile(r"^\d{17,20}$")


class OathNet(FetchErrorsMixin, BaseModule):
    name = "harvest/oathnet"
    description = ("OathNet OSINT/breach intel - IP, Steam, Xbox, Roblox, "
                   "Minecraft, Discord, Holehe, GHunt, subdomains, breach "
                   "search (needs api_keys.oathnet)")
    category = "harvest"
    target_type = "ip/email/domain/username"
    intrusive = False

    BASE = "https://oathnet.org/api/service"

    # name -> (path, query-parameter). Verbatim from the OpenAPI spec.
    LOOKUPS = {
        "ip":              ("/ip-info", "ip"),
        "steam":           ("/steam", "steam_id"),
        "xbox":            ("/xbox", "xbl_id"),
        "roblox":          ("/roblox-userinfo", "username"),
        "minecraft":       ("/mc-history", "username"),
        "discord":         ("/discord-userinfo", "discord_id"),
        "discord_history": ("/discord-username-history", "discord_id"),
        "holehe":          ("/holehe", "email"),
        "ghunt":           ("/ghunt", "email"),
        "subdomain":       ("/extract-subdomain", "domain"),
        "breach":          ("/search-breach", "q"),
    }

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Target: IP / email / domain / Steam64 / XUID or "
                        "Gamertag / Discord ID / Roblox / Minecraft name")
        self.add_option("LOOKUP", "auto", False,
                        "auto | " + " | ".join(self.LOOKUPS))
        self.add_option("API_KEY", "", False,
                        "OathNet API key (else api_keys.oathnet from config)")
        self.add_option("IS_ALIVE", "false", False,
                        "subdomain lookup: only return reachable hosts")
        self.add_option("SEARCH_ID", "", False,
                        "Group this call into an existing OathNet search session")

    # ------------------------------------------------------------------
    def _resolve_key(self):
        key = (self.get_option("API_KEY") or "").strip()
        if key:
            return key
        return (Config().get("api_keys.oathnet") or "").strip()

    def _auto_lookups(self, target):
        """Pick lookup(s) for an unambiguous target; else return None.

        Numeric 17-20 digit IDs are deliberately NOT auto-routed: a 17-digit
        value is a valid Steam64, Discord ID and XUID at once, so guessing would
        be a false result. The user sets LOOKUP for those.
        """
        t = target.strip()
        if is_valid_ip(t):
            return ["ip"]
        if _EMAIL_RE.match(t):
            return ["holehe", "ghunt", "breach"]   # email is rich - run all
        if is_valid_domain(t) and "." in t:
            return ["subdomain"]
        return None

    def _lookup(self, name, value, key):
        """One OathNet lookup -> its envelope dict, or {} on failure (recorded)."""
        path, param = self.LOOKUPS[name]
        params = {param: value}
        if name == "roblox" and value.isdigit():
            params = {"user_id": value}        # spec: user_id OR username
        if name == "subdomain" and (self.get_option("IS_ALIVE") or
                                     "false").strip().lower() == "true":
            params["is_alive"] = "true"
        sid = (self.get_option("SEARCH_ID") or "").strip()
        if sid:
            params["search_id"] = sid
        try:
            resp = http.get(f"{self.BASE}{path}", params=params,
                            headers={"x-api-key": key,
                                     "Accept": "application/json"}, timeout=30)
        except Exception as exc:
            self._note_error(f"{name}: request error: {exc}")
            return {}
        if resp.status_code in (401, 403):
            self._note_error(f"{name}: invalid or unauthorised API key "
                             f"(HTTP {resp.status_code})")
            return {}
        if resp.status_code == 429:
            self._note_error(f"{name}: rate-limited / daily quota exhausted (429)")
            return {}
        if resp.status_code != 200:
            self._note_error(f"{name}: HTTP {resp.status_code}")
            return {}
        try:
            env = resp.json()
        except ValueError:
            self._note_error(f"{name}: non-JSON response")
            return {}
        if isinstance(env, dict) and env.get("success") is False:
            # A clean "not found" is a valid answer, not a fetch failure.
            print_status(f"{name}: {env.get('message') or 'no result'}", "info")
        return env if isinstance(env, dict) else {"data": env}

    # ------------------------------------------------------------------
    @staticmethod
    def _flatten(data, prefix=""):
        """Every scalar leaf as (dotted-key, value) — so nothing is hidden."""
        out = []
        if isinstance(data, dict):
            for k, v in data.items():
                out.extend(OathNet._flatten(v, f"{prefix}{k}."))
        elif isinstance(data, (list, tuple)):
            for i, v in enumerate(data):
                out.extend(OathNet._flatten(v, f"{prefix}{i}."))
        else:
            out.append((prefix.rstrip("."), data))
        return out

    def _print_full(self, data):
        leaves = self._flatten(data)
        if not leaves:
            print_status("  (empty)", "info")
            return
        for key, val in leaves:
            sval = str(val)
            if len(sval) > 200:
                sval = sval[:200] + "..."
            print(f"    {Colors.CYAN}{key}{Colors.RESET}: {sval}")

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        key = self._resolve_key()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  OathNet Lookup: {target}")
        print(f"{'='*60}{Colors.RESET}\n")

        if not key:
            print_status("No OathNet API key. Set it with "
                         "'apikeys set oathnet <key>' or the API_KEY option.",
                         "error")
            self.results = {"target": target, "valid": False,
                            "error": "no_api_key"}
            return False

        chosen = (self.get_option("LOOKUP") or "auto").strip().lower()
        if chosen == "auto":
            lookups = self._auto_lookups(target)
            if not lookups:
                print_status("Could not auto-detect the lookup for this target. "
                             "Set LOOKUP explicitly (e.g. steam/xbox/discord/"
                             "roblox/minecraft).", "error")
                self.results = {"target": target, "valid": False,
                                "error": "ambiguous_target"}
                return False
        elif chosen in self.LOOKUPS:
            lookups = [chosen]
        else:
            print_status(f"Unknown LOOKUP '{chosen}'. Valid: auto, "
                         f"{', '.join(self.LOOKUPS)}", "error")
            self.results = {"target": target, "valid": False,
                            "error": "bad_lookup"}
            return False

        self._errors = []
        per_lookup = {}
        lookups_left = None
        session_id = None
        print_status(f"Running: {', '.join(lookups)}", "info")

        for name in lookups:
            print(f"\n  {Colors.BOLD}{Colors.YELLOW}[{name}]{Colors.RESET}")
            env = self._lookup(name, target, key)
            if not env:
                continue
            data = env.get("data")
            per_lookup[name] = {
                "success": env.get("success"),
                "message": env.get("message"),
                "data": data,                         # FULL payload, untouched
                "lookups_left": env.get("lookups_left"),
            }
            if env.get("lookups_left") is not None:
                lookups_left = env.get("lookups_left")
            sess = env.get("search_session")
            if isinstance(sess, dict) and sess.get("id"):
                session_id = sess["id"]
            if data not in (None, {}, []):
                self._print_full(data)
            else:
                print_status("  no data", "info")

        self.results = {
            "target": target,
            "valid": True,
            "lookups_run": list(per_lookup.keys()),
            "results": per_lookup,
            "lookups_left": lookups_left,
            "search_session_id": session_id,
            "fetch_errors": list(self._errors),
        }

        got_data = any(v.get("data") not in (None, {}, []) for v in per_lookup.values())
        if not per_lookup and self._errors:
            return self._fail()

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}")
        print(f"  OathNet done - {len(per_lookup)}/{len(lookups)} lookup(s)"
              + (f", {lookups_left} lookups left today" if lookups_left is not None
                 else ""))
        print(f"{'='*60}{Colors.RESET}\n")
        return True
