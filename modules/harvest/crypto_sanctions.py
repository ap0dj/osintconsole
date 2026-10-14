"""OFAC sanctions screening for crypto addresses — the free attribution layer.

Commercial tools (Chainalysis) charge for address labelling; the single most
valuable label for OSINT is "is this address under US sanctions". OFAC publishes
that list for free, so this module screens an address against it:

  * downloads the OFAC sanctioned-address lists (per chain) once and CACHES them
    locally, so every later check works offline
  * matches the target (case-insensitively for ETH) and reports a definite
    sanctioned / clear result with the list size and source

This is a factual lookup against an authoritative government list — not a
heuristic "risk score". Source: the 0xB10C mirror of the OFAC SDN digital-
currency addresses (derived directly from the US Treasury SDN list).
"""
import os
import re
import json
import time

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import detect_chain

_SRC = ("https://raw.githubusercontent.com/0xB10C/"
        "ofac-sanctioned-digital-currency-addresses/lists")

# detected chain -> OFAC list code. There is no published DOGE list (the
# mirror returns 404), so DOGE is recognised but reported as "no list".
_CHAIN_LIST = {
    "bitcoin": "XBT",
    "ethereum": "ETH",
    "litecoin": "LTC",
    "tron": "TRX",
}

_CACHE_TTL = 7 * 86400   # refresh weekly


class CryptoSanctions(BaseModule):
    name = "harvest/crypto_sanctions"
    description = ("Screen a crypto address against the OFAC sanctions list "
                   "(free, cached locally, works offline after first fetch)")
    category = "harvest"
    target_type = "wallet"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Crypto address (BTC/ETH/LTC/TRON)")
        self.add_option("REFRESH", "false", False,
                        "Force re-download of the OFAC list even if cached")

    # ------------------------------------------------------------------
    @staticmethod
    def _detect_chain(addr):
        # Shared suite classifier (ethereum/tron/bitcoin/litecoin/dogecoin).
        return detect_chain(addr)

    def _cache_dir(self):
        root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        path = os.path.join(root, "data", "ofac")
        os.makedirs(path, exist_ok=True)
        return path

    def _load_list(self, list_code, refresh):
        """Return (addresses set, source) using a local cache when possible."""
        cache_file = os.path.join(self._cache_dir(), f"{list_code}.json")
        fresh = (os.path.exists(cache_file)
                 and (time.time() - os.path.getmtime(cache_file)) < _CACHE_TTL)

        if fresh and not refresh:
            try:
                with open(cache_file, encoding="utf-8") as f:
                    return set(json.load(f)), "cache"
            except (OSError, ValueError):
                pass

        # Fetch fresh from the OFAC mirror.
        url = f"{_SRC}/sanctioned_addresses_{list_code}.json"
        try:
            resp = http.get(url, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    try:
                        with open(cache_file, "w", encoding="utf-8") as f:
                            json.dump(data, f)
                    except OSError:
                        pass
                    return set(data), "live"
            else:
                print_status(f"OFAC source HTTP {resp.status_code}", "warning")
        except Exception as exc:
            print_status(f"OFAC fetch error: {exc}", "warning")

        # Fetch failed — fall back to any cache we have, even if stale.
        if os.path.exists(cache_file):
            try:
                with open(cache_file, encoding="utf-8") as f:
                    return set(json.load(f)), "stale-cache"
            except (OSError, ValueError):
                pass
        return set(), "unavailable"

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        addr = self.get_option("TARGET").strip()
        refresh = (self.get_option("REFRESH") or "false").strip().lower() == "true"
        chain = self._detect_chain(addr)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  OFAC Sanctions Screening: {addr}")
        print(f"{'='*60}{Colors.RESET}\n")

        if not chain:
            print_status("Unrecognised address (BTC/ETH/LTC/TRON/DOGE)", "error")
            self.results = {"address": addr, "chain": None, "valid": False}
            return False

        list_code = _CHAIN_LIST.get(chain)
        if not list_code:
            # Recognised chain with no published OFAC list (e.g. DOGE). Say so
            # explicitly — "not screened" must never read as "clean".
            print_status(f"No OFAC sanctions list is published for {chain.upper()} "
                         f"- screening NOT possible (not a clean result)", "warning")
            self.results = {"address": addr, "chain": chain, "valid": True,
                            "list_available": False, "sanctioned": None,
                            "reason": "no_list_for_chain"}
            return True
        print_status(f"Chain: {chain.upper()}  (OFAC list: {list_code})", "info")

        sanctioned_set, source = self._load_list(list_code, refresh)
        if source == "unavailable":
            print_status("OFAC list unavailable (no network, no cache) - "
                         "screening INCONCLUSIVE", "warning")
            self.results = {"address": addr, "chain": chain, "valid": True,
                            "list_available": False, "sanctioned": None,
                            "reason": "list_unavailable"}
            return True

        # ETH is compared case-insensitively; Base58 chains are case-sensitive.
        if chain == "ethereum":
            hit = addr.lower() in {a.lower() for a in sanctioned_set}
        else:
            hit = addr in sanctioned_set

        self.results = {
            "address": addr,
            "chain": chain,
            "valid": True,
            "list_available": True,
            "list_code": list_code,
            "list_size": len(sanctioned_set),
            "list_source": source,
            "sanctioned": hit,
        }

        print_status(f"List loaded: {len(sanctioned_set)} sanctioned "
                     f"{list_code} addresses ({source})", "info")
        if hit:
            print(f"\n  {Colors.BOLD}{Colors.RED}*** SANCTIONED ***{Colors.RESET}")
            print(f"  {Colors.RED}This address is on the OFAC SDN sanctions "
                  f"list.{Colors.RESET}\n")
        else:
            print(f"\n  {Colors.GREEN}Not on the OFAC sanctions list "
                  f"({list_code}).{Colors.RESET}\n")
        return True
