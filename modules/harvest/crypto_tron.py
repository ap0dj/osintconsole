"""Tron (TRX / TRC-20) wallet intelligence via the free TronScan API.

Tron carries most of the region's USDT (TRC-20), and the BTC/ETH modules do not
touch it, so this is a dedicated module for the whole Tron picture in one pass:

  balance   - native TRX
  holdings  - every TRC-20 token position the account holds
  flow      - TRC-20 transfers, labelled sent/received, with counterparties
              and per-token / per-counterparty aggregation
  labels    - the explorer's OWN tags (e.g. "Binance") and risk bool — surfaced
              as evidence, never an invented verdict

Source: apilist.tronscanapi.com (free, no API key). Read-only public data.
"""
import re
from collections import defaultdict

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
BASE = "https://apilist.tronscanapi.com/api"


class CryptoTron(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_tron"
    description = ("Trace a Tron wallet: TRX balance, TRC-20 holdings, transfer "
                   "flow and explorer labels (free TronScan API, no key)")
    category = "harvest"
    target_type = "wallet"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "Tron address (starts with T)")
        self.add_option("MAX_TX", "40", False,
                        "TRC-20 transfers to pull for the flow analysis")

    @staticmethod
    def is_tron(addr):
        return bool(TRON_RE.match((addr or "").strip()))

    def _max_tx(self):
        try:
            return max(1, min(200, int(self.get_option("MAX_TX") or "40")))
        except (TypeError, ValueError):
            return 40

    # ---- numeric helpers ---------------------------------------------
    @staticmethod
    def _scale(raw, decimals):
        try:
            raw = int(raw)
        except (TypeError, ValueError):
            return None
        try:
            decimals = int(decimals or 0)
        except (TypeError, ValueError):
            decimals = 0
        return raw / (10 ** decimals) if decimals else float(raw)

    # ---- account: balance + holdings + labels ------------------------
    def _account(self, addr):
        """Return (data, ok). ok is False only when the fetch itself failed, so
        a genuinely empty-but-reachable account is never mistaken for a failure."""
        out = {"native_balance": None, "tx_count": None, "transfers_in": None,
               "transfers_out": None, "holdings": [], "token_count": 0,
               "account_name": None, "labels": []}
        try:
            resp = http.get(f"{BASE}/account", params={"address": addr}, timeout=25)
        except Exception as exc:
            self._note_error(f"TronScan account error: {exc}")
            return out, False
        if resp.status_code != 200:
            self._note_error(f"TronScan account HTTP {resp.status_code}")
            return out, False
        d = resp.json()

        # Native TRX is stored in SUN (1 TRX = 1e6 SUN).
        out["native_balance"] = self._scale(d.get("balance", 0), 6)
        out["tx_count"] = d.get("totalTransactionCount") or d.get("transactions")
        out["transfers_in"] = d.get("transactions_in")
        out["transfers_out"] = d.get("transactions_out")
        out["account_name"] = d.get("name") or None

        holdings = []
        for tok in (d.get("trc20token_balances") or []):
            decimals = tok.get("tokenDecimal", tok.get("decimals"))
            bal = self._scale(tok.get("balance"), decimals)
            if bal is None:
                continue
            holdings.append({
                "symbol": tok.get("tokenAbbr") or tok.get("tokenName"),
                "name": tok.get("tokenName"),
                "token_id": tok.get("tokenId"),
                "balance": bal,
            })
        holdings.sort(key=lambda h: h["balance"], reverse=True)
        out["holdings"] = holdings
        out["token_count"] = len(holdings)
        return out, True

    # ---- TRC-20 transfers: flow --------------------------------------
    def _transfers(self, addr, limit):
        """Return (data, ok). ok is False only when the fetch itself failed."""
        out = {"transfers": [], "risk_flag": None, "labels": []}
        try:
            resp = http.get(f"{BASE}/token_trc20/transfers",
                            params={"limit": limit, "start": 0,
                                    "relatedAddress": addr}, timeout=25)
        except Exception as exc:
            self._note_error(f"TronScan transfers error: {exc}")
            return out, False
        if resp.status_code != 200:
            self._note_error(f"TronScan transfers HTTP {resp.status_code}")
            return out, False
        d = resp.json()

        # The explorer's own risk bool and address tags — evidence, not verdict.
        norm = d.get("normalAddressInfo") or {}
        if addr in norm and isinstance(norm[addr], dict):
            out["risk_flag"] = norm[addr].get("risk")
        contract_info = d.get("contractInfo") or {}
        labels = []
        for info in contract_info.values():
            if isinstance(info, dict) and info.get("tag1"):
                labels.append(info["tag1"])
        out["labels"] = sorted(set(labels))

        low = addr
        for t in (d.get("token_transfers") or [])[:limit]:
            info = t.get("tokenInfo") or {}
            decimals = info.get("tokenDecimal", 0)
            value = self._scale(t.get("quant"), decimals)
            outbound = t.get("from_address") == low
            counterparty = t.get("to_address") if outbound else t.get("from_address")
            out["transfers"].append({
                "txid": t.get("transaction_id"),
                "direction": "sent" if outbound else "received",
                "token_symbol": info.get("tokenAbbr"),
                "token_name": info.get("tokenName"),
                "token_id": info.get("tokenId"),
                "value": value if value is not None else 0.0,
                "block_time": t.get("block_ts"),
                "success": t.get("finalResult") == "SUCCESS",
                "counterparties": [counterparty] if counterparty else [],
            })
        return out, True

    # ---- aggregation --------------------------------------------------
    @staticmethod
    def _flow(transfers):
        agg = defaultdict(lambda: {"received_from": 0.0, "sent_to": 0.0,
                                   "tx_count": 0})
        for t in transfers:
            bucket = "received_from" if t["direction"] == "received" else "sent_to"
            for party in t["counterparties"]:
                agg[party][bucket] += t["value"]
                agg[party]["tx_count"] += 1
        flow = [{"address": a, **v} for a, v in agg.items()]
        flow.sort(key=lambda e: e["received_from"] + e["sent_to"], reverse=True)
        return flow

    @staticmethod
    def _token_summary(transfers):
        agg = {}
        for t in transfers:
            key = t.get("token_id") or t.get("token_symbol") or "?"
            row = agg.setdefault(key, {"symbol": t.get("token_symbol"),
                                       "name": t.get("token_name"),
                                       "token_id": t.get("token_id"),
                                       "received": 0.0, "sent": 0.0,
                                       "transfer_count": 0})
            if t["direction"] == "received":
                row["received"] += t["value"]
            else:
                row["sent"] += t["value"]
            row["transfer_count"] += 1
        return sorted(agg.values(),
                      key=lambda r: r["received"] + r["sent"], reverse=True)

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        addr = self.get_option("TARGET").strip()
        limit = self._max_tx()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Tron Wallet Trace: {addr}")
        print(f"{'='*60}{Colors.RESET}\n")

        if not self.is_tron(addr):
            print_status("Not a Tron address (must start with T, 34 chars)", "error")
            self.results = {"address": addr, "chain": None, "valid": False}
            return False

        self._errors = []
        account, acc_ok = self._account(addr)
        transfers_data, tr_ok = self._transfers(addr, limit)
        transfers = transfers_data["transfers"]

        received = sum(t["value"] for t in transfers if t["direction"] == "received")
        sent = sum(t["value"] for t in transfers if t["direction"] == "sent")

        self.results = {
            "address": addr,
            "chain": "tron",
            "symbol": "TRX",
            "valid": True,
            "native_balance": account["native_balance"],
            "account_name": account["account_name"],
            "tx_count": account["tx_count"],
            "transfers_in": account["transfers_in"],
            "transfers_out": account["transfers_out"],
            "token_count": account["token_count"],
            "holdings": account["holdings"],
            "trc20_transfers": transfers,
            "trc20_received": round(received, 6),
            "trc20_sent": round(sent, 6),
            "counterparties": self._flow(transfers),
            "token_summary": self._token_summary(transfers),
            "risk_flag": transfers_data["risk_flag"],
            "labels": transfers_data["labels"],
            "fetch_errors": list(self._errors),
        }

        # Both explorer calls failed -> this is a FETCH FAILURE, never an empty
        # wallet. TronScan answers a real-but-empty account with HTTP 200, so
        # only when neither endpoint responded is the lookup inconclusive.
        if not acc_ok and not tr_ok:
            return self._fail()
        if self._errors:
            print_status(f"Partial data: {len(self._errors)} fetch error(s) - "
                         f"results may be incomplete", "warning")

        # ---- print summary ----
        nb = account["native_balance"]
        print_status(f"TRX balance: {nb}", "success" if nb else "info")
        if account["account_name"]:
            print_status(f"Account name: {account['account_name']}", "info")
        if transfers_data["labels"]:
            print_status(f"Explorer labels: {', '.join(transfers_data['labels'])}",
                         "success")
        if transfers_data["risk_flag"]:
            print_status("Explorer risk flag: TRUE (TronScan flagged this address)",
                         "warning")
        if account["tx_count"] is not None:
            print_status(f"Total txs: {account['tx_count']} "
                         f"(in {account['transfers_in']}, out {account['transfers_out']})",
                         "info")

        holdings = account["holdings"]
        if holdings:
            print(f"\n  {Colors.BOLD}TRC-20 holdings ({len(holdings)}):{Colors.RESET}")
            for h in holdings[:12]:
                print(f"    {Colors.GREEN}{(h['symbol'] or '?')[:10]:10}{Colors.RESET} "
                      f"{h['balance']:>22,.4f}")

        tok_sum = self.results["token_summary"]
        if tok_sum:
            print(f"\n  {Colors.BOLD}TRC-20 transfer flow:{Colors.RESET}")
            for t in tok_sum[:10]:
                print(f"    {Colors.GREEN}{(t['symbol'] or '?')[:8]:8}{Colors.RESET} "
                      f"in {round(t['received'], 4)} / out {round(t['sent'], 4)} "
                      f"{Colors.DIM}({t['transfer_count']} transfers){Colors.RESET}")

        flow = self.results["counterparties"]
        if flow:
            print(f"\n  {Colors.BOLD}Top counterparties:{Colors.RESET}")
            for p in flow[:10]:
                total = p["received_from"] + p["sent_to"]
                print(f"    {p['address'][:40]:42} "
                      f"{Colors.DIM}{round(total, 2)} ({p['tx_count']} tx){Colors.RESET}")

        print()
        return True
