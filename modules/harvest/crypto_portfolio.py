"""Crypto portfolio snapshot — a wallet's CURRENT holdings.

Where harvest/crypto_transactions answers "where did the money move", this
answers "what does this wallet hold right now": the native-coin balance plus,
for Ethereum, every ERC-20/721 token position, each valued in USD where the
explorer publishes a price, ranked so the heaviest positions surface first.

Sources (all free, no API key):
  ETH       : Blockscout v2 public instance (eth.blockscout.com). The address
              endpoint carries coin_balance (wei) and a live USD exchange_rate;
              /token-balances lists every token position the address holds.
  BTC / LTC : Esplora (blockstream.info / litecoinspace.org). These chains have
              no token layer, so holdings is just the native coin.

Everything is read-only public blockchain data.
"""
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import (
    CryptoTransactions, EVM_CHAINS, FetchErrorsMixin, evm_base)


ESPLORA = {
    "bitcoin": ("https://blockstream.info", "BTC"),
    "litecoin": ("https://litecoinspace.org", "LTC"),
}


class CryptoPortfolio(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_portfolio"
    description = ("Snapshot a wallet's current holdings: native balance plus "
                   "ERC-20/721 token positions valued in USD (ETH via "
                   "Blockscout, BTC/LTC via Esplora)")
    category = "harvest"
    target_type = "wallet"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Wallet address (BTC / LTC / ETH)")
        self.add_option("INCLUDE_TOKENS", "true", False,
                        "For ETH, also list ERC-20/721 token holdings")
        self.add_option("MAX_TOKENS", "25", False,
                        "Maximum token holdings to report (ranked by USD value)")
        self.add_option("CHAIN", "ethereum", False,
                        "EVM chain for 0x addresses: "
                        "ethereum/optimism/gnosis/zksync/scroll")

    # ------------------------------------------------------------------
    @staticmethod
    def _detect_chain(addr):
        # Reuse the transaction tracer's detector so the two stay in lockstep.
        return CryptoTransactions._detect_chain(addr)

    def _max_tokens(self):
        try:
            return max(1, min(200, int(self.get_option("MAX_TOKENS") or "25")))
        except (TypeError, ValueError):
            return 25

    # ---- numeric helpers ---------------------------------------------
    @staticmethod
    def _int(value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _scale(raw, decimals):
        """Scale a raw integer amount (string or int) by 10**decimals -> float.

        Blockscout sends amounts as strings and decimals as strings ("18").
        NFTs (ERC-721) carry no decimals, which arrives as 0 here, so the raw
        token count is returned unscaled. Bad input -> None.
        """
        try:
            raw = int(raw)
        except (TypeError, ValueError):
            return None
        return raw / (10 ** decimals) if decimals else float(raw)

    @staticmethod
    def _price(raw):
        """A USD exchange rate string -> float, or None when absent/null."""
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _empty_snapshot():
        return {
            "native_balance": None,
            "native_balance_usd": None,
            "token_count": 0,
            "tokens": [],
            "total_usd": None,
        }

    # ---- Blockscout (EVM) --------------------------------------------
    def _eth_portfolio(self, addr, include_tokens, max_tokens, base=None):
        if base is None:
            base, _ = evm_base(self.get_option("CHAIN"))
        out = self._empty_snapshot()

        # Native ETH balance + the explorer's live USD price.
        try:
            resp = http.get(f"{base}/addresses/{addr}", timeout=20)
        except Exception as exc:
            self._note_error(f"Blockscout error: {exc}")
            return out
        if resp.status_code != 200:
            self._note_error(f"Blockscout HTTP {resp.status_code}")
            return out

        d = resp.json()
        native = self._scale(d.get("coin_balance"), 18)
        rate = self._price(d.get("exchange_rate"))
        out["native_balance"] = native
        native_usd = (round(native * rate, 2)
                      if native is not None and rate is not None else None)
        out["native_balance_usd"] = native_usd

        tokens = self._eth_token_balances(base, addr) if include_tokens else []
        out["token_count"] = len(tokens)
        out["tokens"] = tokens[:max_tokens]

        # Total over the holdings actually reported, so the figure is
        # reproducible from this dict rather than an invisible 8k-token sum.
        token_usd = sum(t["balance_usd"] for t in out["tokens"]
                        if t.get("balance_usd") is not None)
        if native_usd is not None:
            out["total_usd"] = round(native_usd + token_usd, 2)
        return out

    def _eth_token_balances(self, base, addr):
        """Every token position the explorer lists for this address.

        /token-balances returns a flat LIST (not paginated items); each entry is
        {token, value, token_id, token_instance}. The raw integer `value` is
        scaled by the token's own decimals, and USD is computed when the token
        carries an exchange_rate.
        """
        try:
            resp = http.get(f"{base}/addresses/{addr}/token-balances", timeout=20)
        except Exception as exc:
            self._note_error(f"Blockscout token error: {exc}")
            return []
        if resp.status_code != 200:
            self._note_error(f"Blockscout token HTTP {resp.status_code}")
            return []

        data = resp.json()
        if not isinstance(data, list):
            return []

        holdings = []
        for entry in data:
            token = entry.get("token") or {}
            decimals = self._int(token.get("decimals"), 0)
            balance = self._scale(entry.get("value"), decimals)
            if balance is None:
                continue
            rate = self._price(token.get("exchange_rate"))
            balance_usd = round(balance * rate, 2) if rate is not None else None
            addr_hash = token.get("address_hash") or token.get("address") or ""
            holdings.append({
                "symbol": token.get("symbol"),
                "name": token.get("name"),
                "token_address": addr_hash.lower() or None,
                "token_type": token.get("type"),
                "balance": balance,
                "balance_usd": balance_usd,
            })

        # Heaviest USD first; unpriced tokens fall back to raw amount so a large
        # unpriced position still ranks above dust.
        holdings.sort(key=lambda h: (h["balance_usd"] or 0.0, h["balance"]),
                      reverse=True)
        return holdings

    # ---- Esplora (BTC / LTC) -----------------------------------------
    def _esplora_portfolio(self, base, addr):
        out = self._empty_snapshot()
        try:
            resp = http.get(f"{base}/api/address/{addr}", timeout=20)
        except Exception as exc:
            self._note_error(f"Explorer error: {exc}")
            return out
        if resp.status_code != 200:
            self._note_error(f"Explorer HTTP {resp.status_code}")
            return out

        chain = resp.json().get("chain_stats") or {}
        funded = chain.get("funded_txo_sum", 0)
        spent = chain.get("spent_txo_sum", 0)
        # No token layer on BTC/LTC; holdings is the native coin only.
        out["native_balance"] = (funded - spent) / 1e8
        return out

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        addr = self.get_option("TARGET").strip()
        chain = self._detect_chain(addr)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Crypto Portfolio Snapshot: {addr}")
        print(f"{'='*60}{Colors.RESET}\n")

        # dogecoin is detected by the shared regex but has no portfolio source
        # here, so only BTC / LTC / ETH are accepted.
        if chain != "ethereum" and chain not in ESPLORA:
            print_status("Unrecognised or unsupported address "
                         "(crypto_portfolio supports BTC / LTC / EVM)", "error")
            self.results = {"address": addr, "chain": None, "symbol": None,
                            "valid": False, **self._empty_snapshot()}
            return False

        self._errors = []
        if chain in ESPLORA:
            base, symbol = ESPLORA[chain]
            print_status(f"Chain: {chain.upper()}", "info")
            snapshot = self._esplora_portfolio(base, addr)
        else:
            # 0x address: EVM chain chosen by the CHAIN option.
            evm_url, symbol = evm_base(self.get_option("CHAIN"))
            evm_name = (self.get_option("CHAIN") or "ethereum").strip().lower()
            if evm_name not in EVM_CHAINS:
                evm_name = "ethereum"
            chain = evm_name
            print_status(f"Chain: {evm_name.upper()} (EVM)", "info")
            include = (self.get_option("INCLUDE_TOKENS") or "true"
                       ).strip().lower() == "true"
            snapshot = self._eth_portfolio(addr, include, self._max_tokens(),
                                           evm_url)

        self.results = {
            "address": addr,
            "chain": chain,
            "symbol": symbol,
            "valid": True,
            **snapshot,
            "fetch_errors": list(self._errors),
        }

        # The explorer answers an unused address with HTTP 200 and a zero
        # balance, so a None balance can only mean the lookup itself failed.
        native = snapshot.get("native_balance")
        if native is None:
            return self._fail()
        if self._errors:
            print_status(f"Partial data: {len(self._errors)} fetch error(s) - "
                         f"token holdings may be incomplete", "warning")

        nat_usd = snapshot.get("native_balance_usd")
        usd_str = f"  (${nat_usd:,.2f})" if nat_usd is not None else ""
        print_status(f"Native balance: {native} {symbol}{usd_str}", "success")

        tokens = snapshot.get("tokens") or []
        if snapshot.get("token_count"):
            print_status(f"Token positions: {snapshot['token_count']} "
                         f"(showing top {len(tokens)})", "info")
        if snapshot.get("total_usd") is not None:
            print_status(f"Reported portfolio value: "
                         f"${snapshot['total_usd']:,.2f}", "info")

        if tokens:
            print(f"\n  {Colors.BOLD}Top token holdings:{Colors.RESET}")
            for t in tokens:
                usd = (f"${t['balance_usd']:,.2f}"
                       if t.get("balance_usd") is not None else "n/a")
                print(f"    {Colors.GREEN}{(t['symbol'] or '?')[:10]:10}"
                      f"{Colors.RESET} {t['balance']:>24,.6f}  "
                      f"{Colors.DIM}{usd}{Colors.RESET}")

        print()
        return True
