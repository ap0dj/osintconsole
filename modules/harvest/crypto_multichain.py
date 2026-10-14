"""Cross-chain presence — where is a 0x address active across EVM chains.

A 0x address can exist on every EVM chain, and an investigator rarely knows
which ones a target actually uses. This checks the address against every
Blockscout instance the project supports and reports balance, tx count and
first/last activity per chain — so "this address only matters on Optimism" or
"it is active on five chains" becomes visible at a glance.

Free Blockscout v2 API, no key. Read-only.
"""
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import EVM_CHAINS, FetchErrorsMixin


class CryptoMultichain(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_multichain"
    description = ("Check where a 0x address is active across EVM chains "
                   "(ethereum/optimism/gnosis/zksync/scroll) - balance + tx count")
    category = "harvest"
    target_type = "wallet"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "EVM 0x address")

    @staticmethod
    def _is_evm(addr):
        import re
        return bool(re.match(r"^0x[a-fA-F0-9]{40}$", (addr or "").strip()))

    @staticmethod
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    def _check_chain(self, base, symbol, addr):
        """One chain's address summary.

        Returns {"error": ...} when the chain's explorer could not be reached
        (exception / non-200) so a blocked or 429'd chain is NOT silently
        reported as "address not active here"; None when the explorer answered
        cleanly but the address is genuinely unseen there; the data dict when
        the address is active.
        """
        try:
            resp = http.get(f"{base}/addresses/{addr}", timeout=20)
        except Exception as exc:
            self._note_error(f"{symbol}/{base}: unreachable ({exc})")
            return {"error": "unreachable"}
        if resp.status_code != 200:
            self._note_error(f"{base}: HTTP {resp.status_code}")
            return {"error": f"http {resp.status_code}"}
        d = resp.json()
        balance = self._int(d.get("coin_balance")) / 1e18
        # has_tokens / has_token_transfers / a non-zero nonce or balance all
        # indicate the address has actually been used on this chain.
        counters = None
        try:
            c = http.get(f"{base}/addresses/{addr}/counters", timeout=20)
            if c.status_code == 200:
                counters = c.json()
        except Exception:
            counters = None

        tx_count = self._int((counters or {}).get("transactions_count"))
        active = bool(balance > 0 or tx_count > 0
                      or d.get("has_tokens") or d.get("has_token_transfers"))
        if not active:
            return None
        rate = d.get("exchange_rate")
        usd = None
        if rate:
            try:
                usd = round(balance * float(rate), 2)
            except (TypeError, ValueError):
                usd = None
        return {
            "native_balance": balance,
            "native_balance_usd": usd,
            "symbol": symbol,
            "tx_count": tx_count,
            "has_tokens": bool(d.get("has_tokens")),
            "ens_name": d.get("ens_domain_name"),
            "is_contract": bool(d.get("is_contract")),
        }

    def run(self):
        if not self.validate():
            return False

        addr = self.get_option("TARGET").strip()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Cross-chain Presence: {addr}")
        print(f"{'='*58}{Colors.RESET}\n")

        if not self._is_evm(addr):
            print_status("Not an EVM 0x address", "error")
            self.results = {"address": addr, "valid": False}
            return False

        self._errors = []
        active, checked, unreachable = {}, [], []
        reachable = 0
        for chain, (base_root, symbol) in EVM_CHAINS.items():
            base = f"{base_root}/api/v2"
            print_status(f"Checking {chain}...", "info")
            info = self._check_chain(base, symbol, addr)
            checked.append(chain)
            if info and info.get("error"):
                unreachable.append(chain)
                print_status(f"  {chain}: unreachable ({info['error']}) - "
                             f"NOT evidence the address is inactive here", "warning")
                continue
            # Explorer answered cleanly (active data, or None = genuinely unseen).
            reachable += 1
            if info:
                active[chain] = info
                print_status(f"  active on {chain}: {info['native_balance']} "
                             f"{symbol} / {info['tx_count']} txs", "success")

        self.results = {
            "address": addr,
            "valid": True,
            "chains_checked": checked,
            "active_chains": sorted(active.keys()),
            "active_count": len(active),
            "unreachable_chains": sorted(unreachable),
            "per_chain": active,
            "fetch_errors": list(self._errors),
        }

        # Every chain's explorer failed -> this is a FETCH FAILURE, not a wallet
        # that is inactive everywhere.
        if reachable == 0:
            return self._fail()

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Active on {len(active)} of {reachable} reachable chains: "
              f"{', '.join(sorted(active)) or 'none'}")
        if unreachable:
            print(f"  Unreachable (inconclusive): {', '.join(sorted(unreachable))}")
        print(f"{'='*58}{Colors.RESET}\n")
        return True
