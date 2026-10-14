"""NFT holdings — the ERC-721/1155 collections an EVM address holds.

NFT holdings are an identity signal (ENS names, PFP collections, POAPs, project
memberships) that a plain token balance misses. This lists the collections an
address holds, with the item count per collection, across any supported EVM
chain via the free Blockscout v2 API.
"""
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import EVM_CHAINS, evm_base, FetchErrorsMixin

import re
_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


class CryptoNft(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_nft"
    description = ("List the NFT collections (ERC-721/1155) an EVM address holds "
                   "via Blockscout - item counts per collection")
    category = "harvest"
    target_type = "wallet"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "EVM 0x address")
        self.add_option("CHAIN", "ethereum", False,
                        "EVM chain: ethereum/optimism/gnosis/zksync/scroll")
        self.add_option("MAX_COLLECTIONS", "50", False,
                        "Maximum collections to report")

    @staticmethod
    def _is_evm(addr):
        return bool(_ADDR_RE.match((addr or "").strip()))

    def _max(self):
        try:
            return max(1, min(200, int(self.get_option("MAX_COLLECTIONS") or "50")))
        except (TypeError, ValueError):
            return 50

    @staticmethod
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    def run(self):
        if not self.validate():
            return False

        addr = self.get_option("TARGET").strip()
        base, _ = evm_base(self.get_option("CHAIN"))
        chain = (self.get_option("CHAIN") or "ethereum").strip().lower()
        if chain not in EVM_CHAINS:
            chain = "ethereum"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  NFT Holdings ({chain}): {addr}")
        print(f"{'='*58}{Colors.RESET}\n")

        if not self._is_evm(addr):
            print_status("Not an EVM 0x address", "error")
            self.results = {"address": addr, "chain": None, "valid": False}
            return False

        self._errors = []
        try:
            resp = http.get(f"{base}/addresses/{addr}/nft/collections",
                            params={"type": "ERC-721,ERC-1155"}, timeout=25)
        except Exception as exc:
            # A fetch failure must NOT read as "this address holds no NFTs".
            self._note_error(f"Blockscout NFT error: {exc}")
            self.results = {"address": addr, "chain": chain, "valid": True,
                            "collection_count": 0, "collections": []}
            return self._fail()
        if resp.status_code != 200:
            self._note_error(f"Blockscout NFT HTTP {resp.status_code}")
            self.results = {"address": addr, "chain": chain, "valid": True,
                            "collection_count": 0, "collections": []}
            return self._fail()

        collections = []
        total_items = 0
        for entry in (resp.json().get("items") or [])[:self._max()]:
            token = entry.get("token") or {}
            amount = self._int(entry.get("amount"))
            total_items += amount
            collections.append({
                "name": token.get("name"),
                "symbol": token.get("symbol"),
                "type": token.get("type"),
                "contract": (token.get("address_hash") or "").lower() or None,
                "amount": amount,
                "holders_count": token.get("holders_count"),
            })
        collections.sort(key=lambda c: c["amount"], reverse=True)

        self.results = {
            "address": addr,
            "chain": chain,
            "valid": True,
            "collection_count": len(collections),
            "item_total": total_items,
            "collections": collections,
        }

        if not collections:
            print_status("No NFT holdings found", "info")
            return True

        print_status(f"{len(collections)} collections, {total_items} items total",
                     "success")
        print(f"\n  {Colors.BOLD}Collections:{Colors.RESET}")
        for c in collections[:20]:
            print(f"    {Colors.GREEN}{(c['name'] or c['symbol'] or '?')[:30]:32}"
                  f"{Colors.RESET} x{c['amount']:<5} "
                  f"{Colors.DIM}{c['type']}{Colors.RESET}")
        print()
        return True
