"""Crypto wallet profiler — activity window, type, and risk signals.

A trace of transactions tells you where money moved; this tells you what kind
of address you are looking at before you read too much into a balance. It
derives, from free public-explorer data only:

  * activity window  - first/last seen, age, dormancy
  * address type     - ETH contract vs externally-owned account; BTC script type
  * behaviour signals - reuse, consolidation/fan-out, round-trip ratio

Every signal is a neutral, evidence-backed observation with the data behind it,
never a verdict. An address being a contract or being reused is a fact; calling
it "suspicious" would be a false alarm, so the module does not.
"""
import re
from datetime import datetime, timezone

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import (
    EVM_CHAINS, FetchErrorsMixin, detect_chain, evm_base)


ESPLORA = {
    "bitcoin": ("https://blockstream.info", "BTC"),
    "litecoin": ("https://litecoinspace.org", "LTC"),
}


class CryptoProfile(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_profile"
    description = ("Profile a wallet: activity window, address type, and neutral "
                   "behaviour signals (BTC/LTC via Esplora, ETH via Blockscout)")
    category = "harvest"
    target_type = "wallet"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Wallet address (BTC / LTC / ETH)")
        self.add_option("CHAIN", "ethereum", False,
                        "EVM chain for 0x addresses: "
                        "ethereum/optimism/gnosis/zksync/scroll")

    # ------------------------------------------------------------------
    # Chains this profiler has a data source for.
    SUPPORTED = ("ethereum", "bitcoin", "litecoin")

    @staticmethod
    def _detect_chain(addr):
        # Shared suite classifier; DOGE/Tron are recognised there but have no
        # profile source here, so they map to unsupported.
        chain = detect_chain(addr)
        return chain if chain in CryptoProfile.SUPPORTED else None

    @staticmethod
    def _btc_script_type(addr):
        if addr.startswith("bc1q") or addr.startswith("ltc1q"):
            return "P2WPKH (native segwit)"
        if addr.startswith("bc1p"):
            return "P2TR (taproot)"
        if addr.startswith("3") or addr.startswith("M"):
            return "P2SH (script / multisig / wrapped segwit)"
        if addr.startswith("1") or addr.startswith("L"):
            return "P2PKH (legacy)"
        return "unknown"

    @staticmethod
    def _age(first_ts, last_ts):
        if not first_ts:
            return {}
        now = datetime.now(timezone.utc).timestamp()
        out = {
            "first_seen": datetime.fromtimestamp(first_ts, timezone.utc).isoformat(),
            "age_days": round((now - first_ts) / 86400, 1),
        }
        if last_ts:
            out["last_seen"] = datetime.fromtimestamp(
                last_ts, timezone.utc).isoformat()
            out["dormant_days"] = round((now - last_ts) / 86400, 1)
        return out

    # ---- Esplora (BTC / LTC) -----------------------------------------
    def _esplora_profile(self, base, addr):
        try:
            info = http.get(f"{base}/api/address/{addr}", timeout=20)
            txs = http.get(f"{base}/api/address/{addr}/txs", timeout=20)
        except Exception as exc:
            self._note_error(f"Explorer error: {exc}")
            return {}
        if info.status_code != 200:
            self._note_error(f"Explorer HTTP {info.status_code}")
            return {}

        d = info.json()
        chain = d.get("chain_stats", {})
        funded = chain.get("funded_txo_sum", 0)
        spent = chain.get("spent_txo_sum", 0)
        tx_count = chain.get("tx_count", 0)
        funded_n = chain.get("funded_txo_count", 0)
        spent_n = chain.get("spent_txo_count", 0)

        recent = txs.json() if txs.status_code == 200 else []
        times = [t.get("status", {}).get("block_time")
                 for t in recent if t.get("status", {}).get("block_time")]
        # Esplora returns newest-first; the oldest of this page is our best
        # cheap lower bound for first-seen without paging the whole history.
        first_ts = min(times) if times else None
        last_ts = max(times) if times else None

        signals = []
        if funded_n > 1:
            signals.append({
                "signal": "address_reuse",
                "detail": f"received into {funded_n} separate outputs "
                          f"(reuse weakens BTC privacy)",
            })
        if tx_count and spent_n >= tx_count * 0.9 and spent_n > 5:
            signals.append({
                "signal": "high_spend_ratio",
                "detail": f"{spent_n}/{tx_count} outputs already spent "
                          f"(pass-through / forwarding pattern)",
            })

        return {
            "address_type": self._btc_script_type(addr),
            "balance": (funded - spent) / 1e8,
            "total_received": funded / 1e8,
            "total_sent": spent / 1e8,
            "transaction_count": tx_count,
            "funded_outputs": funded_n,
            "spent_outputs": spent_n,
            "activity": self._age(first_ts, last_ts),
            "signals": signals,
            "note": "first_seen is a lower bound from the most recent tx page, "
                    "not the full history",
        }

    # ---- Blockscout (EVM) --------------------------------------------
    def _eth_profile(self, addr, base=None):
        if base is None:
            base, _ = evm_base(self.get_option("CHAIN"))
        try:
            resp = http.get(f"{base}/addresses/{addr}", timeout=20)
        except Exception as exc:
            self._note_error(f"Blockscout error: {exc}")
            return {}
        if resp.status_code != 200:
            self._note_error(f"Blockscout HTTP {resp.status_code}")
            return {}
        d = resp.json()

        is_contract = bool(d.get("is_contract"))
        is_scam = bool(d.get("is_scam"))
        proxy_type = d.get("proxy_type")

        # implementations: list of {address_hash, name} -> readable labels,
        # falling back to the address when the explorer has no name for it.
        impl_names = []
        for impl in (d.get("implementations") or []):
            if isinstance(impl, dict):
                label = impl.get("name") or impl.get("address_hash")
                if label:
                    impl_names.append(label)

        # Native balance in whole ETH, and its USD value when a rate is present.
        try:
            balance = int(d.get("coin_balance", 0)) / 1e18
        except (TypeError, ValueError):
            balance = None
        balance_usd = None
        rate = d.get("exchange_rate")
        if balance is not None and rate not in (None, ""):
            try:
                balance_usd = balance * float(rate)
            except (TypeError, ValueError):
                balance_usd = None

        signals = []
        if is_contract:
            signals.append({
                "signal": "contract_account",
                "detail": "this is a smart contract, not a personal wallet"
                          + (" (verified source)" if d.get("is_verified") else ""),
            })
        if is_scam:
            signals.append({
                "signal": "explorer_scam_flag",
                "detail": "explorer (Blockscout) has flagged this address as scam",
            })
        if proxy_type and proxy_type != "none":
            impl_str = ", ".join(impl_names) if impl_names else "unnamed"
            signals.append({
                "signal": "proxy_contract",
                "detail": f"{proxy_type} proxy / smart-account; "
                          f"implementation(s): {impl_str}",
            })
        if d.get("has_token_transfers"):
            signals.append({
                "signal": "token_activity",
                "detail": "has ERC-20/721 token transfers beyond plain ETH",
            })

        return {
            "address_type": "contract" if is_contract else "EOA (wallet)",
            "balance": balance,
            "balance_usd": balance_usd,
            "is_contract": is_contract,
            "is_verified_contract": bool(d.get("is_verified")),
            "contract_name": (d.get("name") if is_contract else None),
            "ens_name": d.get("ens_domain_name"),
            "reputation": d.get("reputation"),
            "is_scam": is_scam,
            "proxy_type": proxy_type,
            "implementations": impl_names,
            "has_token_transfers": bool(d.get("has_token_transfers")),
            "has_tokens": bool(d.get("has_tokens")),
            "public_tags": [t.get("label") for t in (d.get("public_tags") or [])],
            "signals": signals,
        }

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        addr = self.get_option("TARGET").strip()
        chain = self._detect_chain(addr)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Crypto Wallet Profile: {addr}")
        print(f"{'='*60}{Colors.RESET}\n")

        if not chain:
            print_status("Unrecognised or unsupported address "
                         "(crypto_profile supports BTC / LTC / EVM)", "error")
            self.results = {"address": addr, "chain": None, "valid": False}
            return False

        self._errors = []
        if chain in ESPLORA:
            base, symbol = ESPLORA[chain]
            print_status(f"Chain: {chain.upper()}", "info")
            profile = self._esplora_profile(base, addr)
        else:
            # 0x address: EVM chain chosen by the CHAIN option.
            evm_url, symbol = evm_base(self.get_option("CHAIN"))
            evm_name = (self.get_option("CHAIN") or "ethereum").strip().lower()
            if evm_name not in EVM_CHAINS:
                evm_name = "ethereum"
            chain = evm_name
            print_status(f"Chain: {evm_name.upper()} (EVM)", "info")
            profile = self._eth_profile(addr, evm_url)

        self.results = {
            "address": addr,
            "chain": chain,
            "symbol": symbol,
            "valid": True,
            **profile,
            "fetch_errors": list(self._errors),
        }

        # Explorers answer an unused address with HTTP 200 and zero stats, so an
        # empty profile can only mean the lookup failed — not an unused wallet.
        if not profile:
            return self._fail()

        print_status(f"Type: {profile.get('address_type')}", "success")
        if profile.get("ens_name"):
            print_status(f"ENS name: {profile['ens_name']}", "success")
        if profile.get("balance") is not None:
            print_status(f"Balance: {profile['balance']} {symbol}", "info")
        if profile.get("balance_usd") is not None:
            print_status(f"Balance (USD): ${profile['balance_usd']:,.2f}", "info")
        if profile.get("reputation"):
            print_status(f"Explorer reputation: {profile['reputation']}", "info")
        if profile.get("is_scam"):
            print_status("Explorer (Blockscout) scam flag: yes", "warning")
        if profile.get("contract_name"):
            print_status(f"Contract: {profile['contract_name']}", "info")
        for tag in profile.get("public_tags") or []:
            print_status(f"Public tag: {tag}", "success")

        activity = profile.get("activity") or {}
        if activity.get("age_days") is not None:
            print_status(f"Active window: ~{activity['age_days']} days "
                         f"(dormant {activity.get('dormant_days', '?')}d)", "info")

        signals = profile.get("signals") or []
        if signals:
            print(f"\n  {Colors.BOLD}Behaviour signals "
                  f"(neutral observations):{Colors.RESET}")
            for s in signals:
                print(f"    {Colors.YELLOW}~{Colors.RESET} {s['signal']}: "
                      f"{Colors.DIM}{s['detail']}{Colors.RESET}")
        else:
            print_status("No notable behaviour signals", "info")

        print()
        return True
