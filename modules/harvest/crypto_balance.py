from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin, detect_chain


class CryptoBalance(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_balance"
    description = "Trace a crypto wallet (BTC/ETH/LTC/DOGE) - balance, tx count, tokens via free explorers"
    category = "harvest"
    target_type = "wallet"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Wallet address (BTC/ETH/LTC/DOGE)")

    # Symbols for the chains this module can actually query.
    _SYMBOLS = {"ethereum": "ETH", "bitcoin": "BTC",
                "litecoin": "LTC", "dogecoin": "DOGE"}

    def _detect_chain(self, addr):
        # The ONE shared suite classifier (strict Base58/bech32) instead of a
        # loose local regex that admitted 0/l/I/O and matched malformed
        # addresses. Tron is recognised there but not queried here.
        chain = detect_chain(addr)
        if chain in self._SYMBOLS:
            return chain, self._SYMBOLS[chain]
        return None, None

    def _esplora(self, base, addr):
        """Blockstream/Esplora-compatible API (BTC, LTC)."""
        try:
            resp = http.get(f"{base}/api/address/{addr}", timeout=20)
            if resp.status_code != 200:
                self._note_error(f"Explorer HTTP {resp.status_code}")
                return {}, resp.status_code
            d = resp.json()
            chain = d.get("chain_stats", {})
            mem = d.get("mempool_stats", {})
            funded = chain.get("funded_txo_sum", 0)
            spent = chain.get("spent_txo_sum", 0)
            return {
                "balance": (funded - spent) / 1e8,
                "received": funded / 1e8,
                "spent": spent / 1e8,
                "transaction_count": chain.get("tx_count", 0) + mem.get("tx_count", 0),
            }, 200
        except Exception as e:
            self._note_error(f"Explorer error: {e}")
            return {}, 0

    def _ethplorer(self, addr):
        """Ethplorer free API - ETH balance + token holdings."""
        try:
            resp = http.get(f"https://api.ethplorer.io/getAddressInfo/{addr}",
                            params={"apiKey": "freekey"}, timeout=20)
            if resp.status_code != 200:
                self._note_error(f"Ethplorer HTTP {resp.status_code}")
                return {}, resp.status_code
            d = resp.json()
            eth = d.get("ETH", {})
            tokens = []
            for t in d.get("tokens", [])[:20]:
                info = t.get("tokenInfo", {})
                try:
                    decimals = int(info.get("decimals", 18) or 18)
                    bal = float(t.get("balance", 0)) / (10 ** decimals)
                except Exception:
                    bal = t.get("balance")
                tokens.append({
                    "symbol": info.get("symbol"),
                    "name": info.get("name"),
                    "balance": bal,
                })
            return {
                "balance": eth.get("balance"),
                "transaction_count": d.get("countTxs"),
                "tokens": tokens,
                "token_count": len(d.get("tokens", [])),
            }, 200
        except Exception as e:
            self._note_error(f"Ethplorer error: {e}")
            return {}, 0

    def _dogechain(self, addr):
        try:
            resp = http.get(f"https://dogechain.info/api/v1/address/balance/{addr}", timeout=20)
            bal = None
            if resp.status_code == 200 and resp.json().get("success") == 1:
                bal = float(resp.json().get("balance", 0))
            else:
                self._note_error(f"Dogechain balance HTTP {resp.status_code}")
            tx_resp = http.get(
                f"https://dogechain.info/api/v1/address/transaction_count/{addr}", timeout=20)
            txc = None
            if tx_resp.status_code == 200 and tx_resp.json().get("success") == 1:
                txc = tx_resp.json().get("transaction_count")
                # Verified live: this is {"received", "sent", "total"}, not an int.
                if isinstance(txc, dict):
                    txc = txc.get("total")
            if bal is not None:
                return {"balance": bal, "transaction_count": txc}, 200
        except Exception as e:
            self._note_error(f"Dogechain error: {e}")
        return {}, 0

    def _fetch(self, chain, addr):
        if chain == "bitcoin":
            return self._esplora("https://blockstream.info", addr)
        if chain == "litecoin":
            return self._esplora("https://litecoinspace.org", addr)
        if chain == "ethereum":
            return self._ethplorer(addr)
        if chain == "dogecoin":
            return self._dogechain(addr)
        return {}, 0

    def _explorer_link(self, chain, addr):
        return {
            "bitcoin": f"https://www.blockchain.com/btc/address/{addr}",
            "ethereum": f"https://etherscan.io/address/{addr}",
            "litecoin": f"https://litecoinspace.org/address/{addr}",
            "dogecoin": f"https://dogechain.info/address/{addr}",
        }.get(chain, f"https://blockchair.com/{chain}/address/{addr}")

    def run(self):
        if not self.validate():
            return False

        addr = self.get_option("TARGET").strip()
        chain, symbol = self._detect_chain(addr)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Crypto Wallet Trace: {addr}")
        print(f"{'='*58}{Colors.RESET}\n")

        if not chain:
            print_status("Could not identify chain (supports BTC/ETH/LTC/DOGE)", "error")
            self.results = {"address": addr, "chain": None, "valid": False}
            return False

        print_status(f"Detected chain: {chain.upper()} ({symbol})", "success")
        print_status("Querying blockchain explorer...", "info")

        self._errors = []
        info, status = self._fetch(chain, addr)
        link = self._explorer_link(chain, addr)

        # Every source answers an unused address with HTTP 200 + a zero balance,
        # so no data at all means the lookup failed — never "address unused".
        if not info:
            self.results = {"address": addr, "chain": chain, "symbol": symbol,
                            "valid": True, "data": {}, "explorer": link,
                            "http_status": status}
            return self._fail()

        bal = info.get("balance")
        print_status(f"Balance: {bal} {symbol}", "success")
        if info.get("received") is not None:
            print_status(f"Total received: {info['received']} {symbol}", "info")
        if info.get("spent") is not None:
            print_status(f"Total spent: {info['spent']} {symbol}", "info")
        print_status(f"Transactions: {info.get('transaction_count')}", "info")
        if info.get("tokens"):
            print_status(f"Token holdings: {info.get('token_count')}", "success")
            for t in info["tokens"][:10]:
                print_status(f"  {t['symbol']}: {t['balance']}", "info")

        self.results = {
            "address": addr,
            "chain": chain,
            "symbol": symbol,
            "valid": True,
            "data": info,
            "explorer": link,
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  {symbol} Wallet Summary")
        print(f"{'─'*58}{Colors.RESET}")
        print(f"  Balance:      {bal} {symbol}")
        print(f"  Transactions: {info.get('transaction_count')}")
        print(f"  Explorer:     {link}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return True
