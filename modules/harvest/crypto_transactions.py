"""Crypto transaction tracer — real on-chain history + counterparty flow.

Where harvest/crypto_balance answers "how much is in this wallet", this answers
"where did the money come from and where did it go". It pulls the actual
transaction list from free, no-auth block explorers, labels each transaction as
received or sent relative to the target, and aggregates the counterparties so
the heaviest inflows and outflows are visible.

Sources (all free, no API key):
  BTC / LTC : Esplora (blockstream.info / litecoinspace.org) - the same API
              harvest/crypto_balance already relies on.
  ETH       : Blockscout v2 public instance (eth.blockscout.com).

Everything is read-only public blockchain data.
"""
import re
from collections import defaultdict

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
# The ONE address classifier lives in core so correlate/identity_pivot share it;
# re-exported here because the crypto modules import it from this module.
from core.chains import detect_chain  # noqa: F401


ESPLORA = {
    "bitcoin": ("https://blockstream.info", "BTC"),
    "litecoin": ("https://litecoinspace.org", "LTC"),
}

# EVM chains reachable on the free Blockscout v2 API (identical shape across
# instances). Verified live to answer /api/v2 without a key; base/arbitrum/
# polygon are WAF-blocked (403) so they are deliberately NOT listed. A 0x
# address cannot reveal its chain, so the module takes CHAIN explicitly and
# defaults to ethereum.
EVM_CHAINS = {
    "ethereum": ("https://eth.blockscout.com", "ETH"),
    "optimism": ("https://optimism.blockscout.com", "ETH"),
    "gnosis": ("https://gnosis.blockscout.com", "xDAI"),
    "zksync": ("https://zksync.blockscout.com", "ETH"),
    "scroll": ("https://scroll.blockscout.com", "ETH"),
}


def evm_base(chain_opt):
    """(base_url, native_symbol) for a CHAIN option, defaulting to ethereum."""
    key = (chain_opt or "ethereum").strip().lower()
    base, symbol = EVM_CHAINS.get(key, EVM_CHAINS["ethereum"])
    return f"{base}/api/v2", symbol


class FetchErrorsMixin:
    """Shared failure-vs-empty contract for the crypto modules.

    Every explorer failure (non-200, exception) goes through _note_error, so
    run() can tell 'the explorer failed' apart from 'the address genuinely has
    no activity'. Only the latter may be reported as empty/unused.
    """

    def _note_error(self, msg):
        if not hasattr(self, "_errors"):
            self._errors = []
        self._errors.append(msg)
        print_status(msg, "warning")

    def _fail(self, extra=None):
        """Mark results as a fetch failure and return False for run()."""
        errors = list(getattr(self, "_errors", []) or [])
        self.results = dict(self.results or {})
        self.results.update(extra or {})
        self.results["error"] = "fetch_failed"
        self.results["fetch_errors"] = errors
        print_status("Lookup FAILED - explorer unreachable or erroring; this is "
                     "NOT evidence the address is unused", "error")
        return False


class CryptoTransactions(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_transactions"
    description = ("Trace a wallet's real transaction history and rank its "
                   "counterparties (BTC/LTC via Esplora, ETH via Blockscout)")
    category = "harvest"
    target_type = "wallet"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Wallet address (BTC / LTC / ETH)")
        self.add_option("MAX_TX", "50", False,
                        "Maximum transactions to pull and analyse")
        self.add_option("INCLUDE_TOKENS", "true", False,
                        "For ETH, also trace ERC-20/721 token transfers")
        self.add_option("CHAIN", "ethereum", False,
                        "EVM chain for 0x addresses: "
                        "ethereum/optimism/gnosis/zksync/scroll")

    # ------------------------------------------------------------------
    @staticmethod
    def _detect_chain(addr):
        # Tron has its own module (crypto_tron); this tracer covers the rest.
        chain = detect_chain(addr)
        return None if chain == "tron" else chain

    def _max_tx(self):
        try:
            return max(1, min(200, int(self.get_option("MAX_TX") or "50")))
        except (TypeError, ValueError):
            return 50

    # ---- Esplora (BTC / LTC) -----------------------------------------
    def _esplora_txs(self, base, addr, limit):
        """Return parsed transactions from an Esplora-compatible explorer.

        Esplora returns at most 25 confirmed txs per page; /chain/{last_txid}
        walks backwards from there. Values are in satoshis.
        """
        txs = []
        last_seen = None
        while len(txs) < limit:
            url = f"{base}/api/address/{addr}/txs"
            if last_seen:
                url = f"{base}/api/address/{addr}/txs/chain/{last_seen}"
            try:
                resp = http.get(url, timeout=20)
            except Exception as exc:
                self._note_error(f"Explorer error: {exc}")
                break
            if resp.status_code != 200:
                self._note_error(f"Explorer HTTP {resp.status_code}")
                break
            page = resp.json()
            if not page:
                break
            for tx in page:
                txs.append(self._parse_esplora_tx(tx, addr))
            last_seen = page[-1].get("txid")
            if len(page) < 25:
                break
        return txs[:limit]

    @staticmethod
    def _parse_esplora_tx(tx, addr):
        """One Esplora tx -> direction, value, and counterparties vs `addr`.

        Sum of target inputs is money leaving the address; sum of target
        outputs is money arriving. Net > 0 means received, net < 0 sent.
        """
        sent = sum(
            vin.get("prevout", {}).get("value", 0)
            for vin in tx.get("vin", [])
            if (vin.get("prevout") or {}).get("scriptpubkey_address") == addr
        )
        received = sum(
            vout.get("value", 0)
            for vout in tx.get("vout", [])
            if vout.get("scriptpubkey_address") == addr
        )
        net = received - sent
        if net >= 0:
            # Inbound: counterparties are the input addresses (who paid us).
            parties = [
                (vin.get("prevout") or {}).get("scriptpubkey_address")
                for vin in tx.get("vin", [])
            ]
        else:
            # Outbound: counterparties are the output addresses (who we paid),
            # excluding change back to ourselves.
            parties = [
                vout.get("scriptpubkey_address")
                for vout in tx.get("vout", [])
                if vout.get("scriptpubkey_address") != addr
            ]
        status = tx.get("status", {})
        return {
            "txid": tx.get("txid"),
            "direction": "received" if net >= 0 else "sent",
            "value": abs(net) / 1e8,
            "fee": tx.get("fee", 0) / 1e8,
            "confirmed": bool(status.get("confirmed")),
            "block_time": status.get("block_time"),
            "counterparties": [p for p in parties if p],
        }

    # ---- Blockscout (EVM) --------------------------------------------
    def _blockscout_txs(self, addr, limit, base):
        txs = []
        try:
            resp = http.get(f"{base}/addresses/{addr}/transactions", timeout=20)
        except Exception as exc:
            self._note_error(f"Blockscout error: {exc}")
            return txs
        if resp.status_code != 200:
            self._note_error(f"Blockscout HTTP {resp.status_code}")
            return txs
        low = addr.lower()
        for tx in (resp.json().get("items") or [])[:limit]:
            frm = ((tx.get("from") or {}).get("hash") or "").lower()
            to = ((tx.get("to") or {}).get("hash") or "").lower()
            outbound = frm == low
            try:
                value = int(tx.get("value", 0)) / 1e18
            except (TypeError, ValueError):
                value = 0
            txs.append({
                "txid": tx.get("hash"),
                "direction": "sent" if outbound else "received",
                "value": value,
                "fee": self._eth_fee(tx),
                "confirmed": tx.get("status") == "ok",
                "block_time": tx.get("timestamp"),
                "counterparties": [to if outbound else frm],
            })
        return txs

    @staticmethod
    def _eth_fee(tx):
        try:
            return int(tx.get("fee", {}).get("value", 0)) / 1e18
        except (TypeError, ValueError, AttributeError):
            return 0

    def _blockscout_token_transfers(self, addr, limit, base):
        """ERC-20/721 token movements for an EVM address.

        On most EVM wallets the token flow (USDT, USDC, ...) matters more
        than the native coin, so tracing only `value` would miss where the money
        actually went. Amounts are scaled by each token's own decimals.
        """
        transfers = []
        try:
            resp = http.get(f"{base}/addresses/{addr}/token-transfers",
                            params={"type": "ERC-20"}, timeout=20)
        except Exception as exc:
            self._note_error(f"Blockscout token error: {exc}")
            return transfers
        if resp.status_code != 200:
            self._note_error(f"Blockscout token HTTP {resp.status_code}")
            return transfers
        low = addr.lower()
        for t in (resp.json().get("items") or [])[:limit]:
            frm = ((t.get("from") or {}).get("hash") or "").lower()
            to = ((t.get("to") or {}).get("hash") or "").lower()
            outbound = frm == low
            token = t.get("token") or {}
            total = t.get("total") or {}
            # Blockscout v2 names the contract address_hash, not address, and
            # the token's decimals live on the token object as a string.
            addr_hash = (token.get("address_hash") or token.get("address") or "")
            transfers.append({
                "txid": t.get("transaction_hash") or t.get("tx_hash"),
                "direction": "sent" if outbound else "received",
                "token_symbol": token.get("symbol"),
                "token_name": token.get("name"),
                "token_type": token.get("type"),
                "token_address": addr_hash.lower() or None,
                "token_reputation": token.get("reputation"),
                "value": self._scaled_amount(total, token),
                "block_time": t.get("timestamp"),
                "counterparties": [to if outbound else frm],
            })
        return transfers

    @staticmethod
    def _scaled_amount(total, token=None):
        """Scale a Blockscout token amount to a float.

        decimals arrives as a string ("18") and may sit on `total` or, when that
        is absent, on the token object. Both are handled.
        """
        try:
            raw = int(total.get("value", 0))
        except (TypeError, ValueError, AttributeError):
            return 0.0
        decimals = (total or {}).get("decimals")
        if decimals in (None, "") and token:
            decimals = token.get("decimals")
        try:
            decimals = int(decimals or 0)
        except (TypeError, ValueError):
            decimals = 0
        return raw / (10 ** decimals) if decimals else float(raw)

    # ---- Dogecoin (Blockchair) ---------------------------------------
    # dogechain.info's /transaction/{hash} endpoint returns 404 for every real
    # txid (verified live), so its history path yields nothing. Blockchair's
    # Dogecoin dashboards are reliable and expose inputs/outputs per tx.
    _DOGE_BASE = "https://api.blockchair.com/dogecoin"

    def _dogechain_txs(self, addr, limit):
        """Dogecoin history via Blockchair: one address call for the tx hashes,
        then a transaction call each to resolve inputs/outputs. Capped tighter
        than the others because it is 1 + N requests on a rate-limited free API."""
        txs = []
        doge_limit = min(limit, 15)
        try:
            resp = http.get(f"{self._DOGE_BASE}/dashboards/address/{addr}",
                            params={"limit": doge_limit}, timeout=30)
        except Exception as exc:
            self._note_error(f"Blockchair DOGE error: {exc}")
            return txs
        if resp.status_code != 200:
            self._note_error(f"Blockchair DOGE HTTP {resp.status_code}")
            return txs

        block = (resp.json().get("data") or {}).get(addr) or {}
        hashes = (block.get("transactions") or [])[:doge_limit]
        missed = 0
        for txid in hashes:
            detail = self._doge_tx_detail(txid)
            if not detail:
                missed += 1
                continue
            ins = detail.get("inputs") or []
            outs = detail.get("outputs") or []
            # Blockchair labels the address on each input/output as `recipient`;
            # values are in koinu (1 DOGE = 1e8).
            sent = sum(int(i.get("value", 0)) for i in ins
                       if i.get("recipient") == addr)
            received = sum(int(o.get("value", 0)) for o in outs
                           if o.get("recipient") == addr)
            net = received - sent
            if net >= 0:
                parties = [i.get("recipient") for i in ins]
            else:
                parties = [o.get("recipient") for o in outs
                           if o.get("recipient") != addr]
            tx_info = detail.get("transaction") or {}
            txs.append({
                "txid": txid,
                "direction": "received" if net >= 0 else "sent",
                "value": abs(net) / 1e8,
                "fee": (tx_info.get("fee") or 0) / 1e8,
                "confirmed": True,
                "block_time": tx_info.get("time"),
                "counterparties": [p for p in parties if p],
            })
        if missed:
            self._note_error(
                f"Blockchair DOGE: {missed}/{len(hashes)} tx details unavailable")
        return txs

    def _doge_tx_detail(self, txid):
        try:
            resp = http.get(f"{self._DOGE_BASE}/dashboards/transaction/{txid}",
                            timeout=30)
            if resp.status_code != 200:
                return {}
            return (resp.json().get("data") or {}).get(txid) or {}
        except Exception:
            return {}

    # ---- Counterparty flow -------------------------------------------
    @staticmethod
    def _flow(txs):
        """Aggregate per-counterparty inbound/outbound volume and tx counts."""
        agg = defaultdict(lambda: {"received_from": 0.0, "sent_to": 0.0,
                                   "tx_count": 0})
        for tx in txs:
            bucket = "received_from" if tx["direction"] == "received" else "sent_to"
            parties = tx["counterparties"] or []
            if not parties:
                continue
            # Split the value evenly when a tx has several counterparties, so a
            # batch payment does not over-credit any single address.
            share = tx["value"] / len(parties)
            for party in parties:
                agg[party][bucket] += share
                agg[party]["tx_count"] += 1
        flow = [{"address": addr, **vals} for addr, vals in agg.items()]
        flow.sort(key=lambda e: e["received_from"] + e["sent_to"], reverse=True)
        return flow

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        addr = self.get_option("TARGET").strip()
        limit = self._max_tx()
        chain = self._detect_chain(addr)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Crypto Transaction Trace: {addr}")
        print(f"{'='*60}{Colors.RESET}\n")

        if not chain:
            if detect_chain(addr) == "tron":
                print_status("Tron address - use harvest/crypto_tron", "error")
            else:
                print_status("Unrecognised address (BTC / LTC / ETH / DOGE)", "error")
            self.results = {"address": addr, "chain": None, "valid": False}
            return False

        self._errors = []
        token_transfers = []
        if chain in ESPLORA:
            base, symbol = ESPLORA[chain]
            print_status(f"Chain: {chain.upper()}  |  up to {limit} txs", "info")
            txs = self._esplora_txs(base, addr, limit)
        elif chain == "dogecoin":
            symbol = "DOGE"
            print_status(f"Chain: DOGECOIN  |  up to {limit} txs", "info")
            txs = self._dogechain_txs(addr, limit)
        else:
            # 0x address: the EVM chain is chosen by the CHAIN option.
            base, symbol = evm_base(self.get_option("CHAIN"))
            evm_name = (self.get_option("CHAIN") or "ethereum").strip().lower()
            if evm_name not in EVM_CHAINS:
                evm_name = "ethereum"
            chain = evm_name
            print_status(f"Chain: {evm_name.upper()} (EVM)  |  up to {limit} txs",
                         "info")
            txs = self._blockscout_txs(addr, limit, base)
            if (self.get_option("INCLUDE_TOKENS") or "true").strip().lower() == "true":
                token_transfers = self._blockscout_token_transfers(addr, limit, base)

        received = sum(t["value"] for t in txs if t["direction"] == "received")
        sent = sum(t["value"] for t in txs if t["direction"] == "sent")
        flow = self._flow(txs)

        self.results = {
            "address": addr,
            "chain": chain,
            "symbol": symbol,
            "valid": True,
            "transaction_count": len(txs),
            "total_received": round(received, 8),
            "total_sent": round(sent, 8),
            "transactions": txs,
            "counterparties": flow,
            "unique_counterparties": len(flow),
            "token_transfers": token_transfers,
            "token_summary": self._token_summary(token_transfers),
            "fetch_errors": list(self._errors),
        }

        if not txs and not token_transfers:
            if self._errors:
                # Explorer failed: this is NOT an empty wallet. Report it as a
                # failure so callers (full_recon / crypto_full) count it as one.
                self.results["error"] = "fetch_failed"
                print_status("Lookup FAILED - explorer unreachable or erroring; "
                             "this is NOT evidence the address is unused", "error")
                return False
            print_status("No transactions - the address has no on-chain activity",
                         "info")
            return True

        if self._errors:
            print_status(f"Partial data: {len(self._errors)} fetch error(s) - "
                         f"results may be incomplete", "warning")

        in_n = sum(1 for t in txs if t["direction"] == "received")
        out_n = len(txs) - in_n
        print_status(f"{len(txs)} native txs  ({in_n} in, {out_n} out)", "success")
        print_status(f"Received {round(received, 8)} {symbol}  |  "
                     f"Sent {round(sent, 8)} {symbol}", "info")
        print_status(f"Unique counterparties: {len(flow)}", "info")

        if flow:
            print(f"\n  {Colors.BOLD}Top counterparties:{Colors.RESET}")
            for party in flow[:10]:
                total = party["received_from"] + party["sent_to"]
                print(f"    {party['address'][:42]:44} "
                      f"{Colors.DIM}{round(total, 6)} {symbol} "
                      f"({party['tx_count']} tx){Colors.RESET}")

        if token_transfers:
            print(f"\n  {Colors.BOLD}ERC-20 token flow "
                  f"({len(token_transfers)} transfers):{Colors.RESET}")
            for tok in self.results["token_summary"][:10]:
                print(f"    {Colors.GREEN}{tok['symbol'] or '?':8}{Colors.RESET} "
                      f"in {round(tok['received'], 4)} / "
                      f"out {round(tok['sent'], 4)}  "
                      f"{Colors.DIM}({tok['transfer_count']} transfers){Colors.RESET}")

        print()
        return True

    @staticmethod
    def _token_summary(transfers):
        """Per-token in/out totals, so the ETH token flow is legible at a glance."""
        agg = {}
        for t in transfers:
            key = t.get("token_address") or t.get("token_symbol") or "?"
            row = agg.setdefault(key, {
                "symbol": t.get("token_symbol"),
                "name": t.get("token_name"),
                "token_address": t.get("token_address"),
                "received": 0.0, "sent": 0.0, "transfer_count": 0,
            })
            if t["direction"] == "received":
                row["received"] += t["value"]
            else:
                row["sent"] += t["value"]
            row["transfer_count"] += 1
        return sorted(agg.values(),
                      key=lambda r: r["received"] + r["sent"], reverse=True)
