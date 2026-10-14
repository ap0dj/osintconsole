"""ENS resolution — map an .eth name to an address and back, free, no key.

Lets an investigator pivot between a human-readable ENS name (vitalik.eth) and
the 0x address behind it, in either direction:

  name  -> address   (forward)
  0x..  -> name       (reverse)

Primary source: api.ensideas.com (one endpoint, both directions). Falls back to
the Blockscout search API. The resolved address can be fed straight into
crypto_full / crypto_transactions for the full wallet picture.
"""
import re

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin

_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
# A dotted, non-address token is treated as a potential ENS name.
_NAME_RE = re.compile(r"^[A-Za-z0-9\-_.]+\.[A-Za-z]{2,}$")


class CryptoEns(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_ens"
    description = ("Resolve an ENS name to an address and back (free, no key) - "
                   "pivot between vitalik.eth and 0x...")
    category = "harvest"
    target_type = "wallet/domain/username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "ENS name (vitalik.eth) or 0x address")

    # ------------------------------------------------------------------
    @staticmethod
    def _classify(target):
        t = (target or "").strip()
        if _ADDR_RE.match(t):
            return "address"
        if _NAME_RE.match(t):
            return "name"
        return None

    def _resolve_ensideas(self, query):
        """Return (mapping_or_None, ok). ok is False only when the resolver
        itself could not be reached/parsed, so a fetch failure is never confused
        with a name that genuinely has no mapping."""
        try:
            resp = http.get(f"https://api.ensideas.com/ens/resolve/{query}",
                            timeout=20)
        except Exception as exc:
            self._note_error(f"ensideas error: {exc}")
            return None, False
        if resp.status_code != 200:
            self._note_error(f"ensideas HTTP {resp.status_code}")
            return None, False
        try:
            d = resp.json()
        except Exception:
            self._note_error("ensideas non-JSON response")
            return None, False
        if not isinstance(d, dict):
            return None, True  # clean response, just nothing usable
        return {
            "address": d.get("address"),
            "name": d.get("name"),
            "display_name": d.get("displayName"),
            "avatar": d.get("avatar"),
            "source": "ensideas",
        }, True

    def _resolve_blockscout(self, name):
        """Fallback: Blockscout search returns ENS matches with address_hash.
        Returns (mapping_or_None, ok) with the same failure-vs-empty contract."""
        try:
            resp = http.get("https://eth.blockscout.com/api/v2/search",
                            params={"q": name}, timeout=20)
        except Exception as exc:
            self._note_error(f"Blockscout search error: {exc}")
            return None, False
        if resp.status_code != 200:
            self._note_error(f"Blockscout search HTTP {resp.status_code}")
            return None, False
        try:
            items = resp.json().get("items") or []
        except Exception:
            self._note_error("Blockscout search non-JSON response")
            return None, False
        for item in items:
            ens = item.get("ens_info") or {}
            if item.get("address_hash") and ens.get("name", "").lower() == name.lower():
                return {
                    "address": item.get("address_hash"),
                    "name": ens.get("name"),
                    "display_name": ens.get("name"),
                    "avatar": None,
                    "source": "blockscout",
                }, True
        return None, True

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        kind = self._classify(target)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  ENS Resolution: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        if not kind:
            print_status("Enter an ENS name (name.eth) or a 0x address", "error")
            self.results = {"target": target, "valid": False}
            return False

        self._errors = []
        resolved, any_ok = self._resolve_ensideas(target)
        # Forward lookups get a Blockscout fallback; reverse only ensideas.
        if (not resolved or not resolved.get("address")) and kind == "name":
            bs_resolved, bs_ok = self._resolve_blockscout(target)
            any_ok = any_ok or bs_ok
            resolved = bs_resolved or resolved

        if not resolved or not resolved.get("address"):
            if not any_ok:
                # Every resolver failed to respond -> FETCH FAILURE, not a name
                # that genuinely has no mapping.
                print_status("ENS resolution FAILED - resolver unreachable; this "
                             "is NOT evidence the name has no mapping", "error")
                self.results = {"target": target, "input_type": kind,
                                "valid": True, "resolved": False}
                return self._fail()
            print_status("No ENS mapping found", "warning")
            self.results = {"target": target, "input_type": kind, "valid": True,
                            "resolved": False}
            return True

        addr = resolved.get("address")
        name = resolved.get("name")
        # ensideas echoes the address as `name` when there is no reverse record;
        # treat that as "no name".
        has_name = bool(name) and name != addr

        self.results = {
            "target": target,
            "input_type": kind,
            "valid": True,
            "resolved": True,
            "address": addr,
            "ens_name": name if has_name else None,
            "display_name": resolved.get("display_name") if has_name else None,
            "avatar": resolved.get("avatar"),
            "source": resolved.get("source"),
        }

        print_status(f"Address:  {addr}", "success")
        if has_name:
            print_status(f"ENS name: {name}", "success")
        else:
            print_status("No reverse ENS name set for this address", "info")
        if resolved.get("avatar"):
            print_status(f"Avatar:   {resolved['avatar']}", "info")
        print_status(f"Source:   {resolved.get('source')}", "info")
        print(f"\n  {Colors.DIM}Pivot: use crypto_full / crypto_transactions "
              f"with TARGET {addr}{Colors.RESET}\n")
        return True
