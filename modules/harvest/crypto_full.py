"""Full crypto wallet intelligence — runs every wallet module, one report.

Bundles the four wallet modules into a single pass and folds their output into
one unified picture of an address:

  identity  - chain, address type (EOA / contract / script type), ENS, proxy
  holdings  - native balance + USD, token positions (crypto_portfolio)
  activity  - first/last seen, age (crypto_profile)
  flow      - received/sent totals, top counterparties, ERC-20 flow
              (crypto_transactions)
  signals   - the neutral, evidence-backed observations each module reported

Deliberately NO invented risk score: the only "flag" surfaced is the explorer's
own is_scam label. A fact (contract, reuse, proxy) is reported as a fact.
"""
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core.reporter import Reporter

from modules.harvest.crypto_balance import CryptoBalance
from modules.harvest.crypto_transactions import CryptoTransactions, EVM_CHAINS
from modules.harvest.crypto_profile import CryptoProfile
from modules.harvest.crypto_portfolio import CryptoPortfolio
from modules.harvest.crypto_tron import CryptoTron
from modules.harvest.crypto_sanctions import CryptoSanctions
from modules.harvest.crypto_identity import CryptoIdentity
from modules.harvest.crypto_multichain import CryptoMultichain
from modules.harvest.crypto_nft import CryptoNft


class CryptoFull(BaseModule):
    name = "harvest/crypto_full"
    description = ("Full wallet intelligence - runs every applicable wallet "
                   "module (BTC/LTC/ETH/DOGE + Tron) into one unified report")
    category = "harvest"
    target_type = "wallet"
    intrusive = False

    # Each chain runs ONLY the modules that have a data source for it, so a
    # module that does not apply is never counted as "failed".
    # BTC / LTC / EVM core, ordered so identity/holdings run before tx history.
    # (crypto_balance is omitted: profile+portfolio+transactions cover it, and
    # it is Ethereum-mainnet-only, so it would report wrong data on L2 chains.)
    MODULES = [
        ("harvest/crypto_sanctions", CryptoSanctions),
        ("harvest/crypto_profile", CryptoProfile),
        ("harvest/crypto_portfolio", CryptoPortfolio),
        ("harvest/crypto_transactions", CryptoTransactions),
    ]
    # DOGE: profile/portfolio have no DOGE source; crypto_balance is the
    # DOGE balance source and sanctions reports "no OFAC list" explicitly.
    DOGE_MODULES = [
        ("harvest/crypto_sanctions", CryptoSanctions),
        ("harvest/crypto_transactions", CryptoTransactions),
        ("harvest/crypto_balance", CryptoBalance),
    ]
    # Tron has its own explorer, so a Tron address uses this instead (plus the
    # chain-agnostic sanctions screen).
    TRON_MODULES = [
        ("harvest/crypto_sanctions", CryptoSanctions),
        ("harvest/crypto_tron", CryptoTron),
    ]
    # EVM-only extras: social-identity linkage and cross-chain presence. Only
    # meaningful for 0x addresses, so appended just for EVM chains.
    EVM_EXTRA = [
        ("harvest/crypto_identity", CryptoIdentity),
        ("harvest/crypto_multichain", CryptoMultichain),
        ("harvest/crypto_nft", CryptoNft),
    ]

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Wallet address (BTC / LTC / ETH / DOGE / Tron)")
        self.add_option("MAX_TX", "50", False,
                        "Transactions to pull for the flow analysis")
        self.add_option("CHAIN", "ethereum", False,
                        "EVM chain for 0x addresses: "
                        "ethereum/optimism/gnosis/zksync/scroll")
        self.add_option("SKIP", "", False,
                        "Comma-separated module names to skip")

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        max_tx = self.get_option("MAX_TX") or "50"
        chain_opt = self.get_option("CHAIN") or "ethereum"
        skip = {s.strip() for s in (self.get_option("SKIP") or "").split(",")
                if s.strip()}

        # Tron has a dedicated explorer and its own address format.
        if CryptoTron.is_tron(target):
            chain = "tron"
            module_list = self.TRON_MODULES
        else:
            chain = CryptoTransactions._detect_chain(target)
            # A 0x address is detected as "ethereum"; the CHAIN option picks
            # which EVM chain it actually is.
            if chain == "ethereum":
                opt = chain_opt.strip().lower()
                if opt in EVM_CHAINS:
                    chain = opt
            if chain == "dogecoin":
                module_list = self.DOGE_MODULES
            elif chain in EVM_CHAINS:
                module_list = self.MODULES + self.EVM_EXTRA
            else:
                module_list = self.MODULES

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print("  FULL WALLET INTELLIGENCE")
        print(f"  Target: {target}")
        print(f"  Chain:  {chain.upper() if chain else 'UNRECOGNISED'}")
        print(f"{'='*60}{Colors.RESET}\n")

        if not chain:
            print_status("Unrecognised address (BTC / LTC / ETH / DOGE / Tron)",
                         "error")
            self.results = {"address": target, "chain": None, "valid": False}
            return False

        results = {}
        ran, failed = [], []
        reasons = {}
        for idx, (mod_name, mod_cls) in enumerate(module_list, start=1):
            if mod_name in skip:
                continue
            print(f"\n{Colors.BOLD}{Colors.YELLOW}{'-'*52}")
            print(f"  [{idx}/{len(module_list)}] {mod_name}")
            print(f"{'-'*52}{Colors.RESET}")
            try:
                mod = mod_cls()
                mod.set_option("TARGET", target)
                opts = getattr(mod, "options", {})
                if "MAX_TX" in opts:
                    mod.set_option("MAX_TX", max_tx)
                if "CHAIN" in opts:
                    mod.set_option("CHAIN", chain_opt)
                if mod.run():
                    results[mod_name] = mod.get_results()
                    ran.append(mod_name)
                else:
                    failed.append(mod_name)
                    res = mod.get_results() or {}
                    errs = res.get("fetch_errors") or []
                    reasons[mod_name] = (errs[0] if errs
                                         else res.get("error") or "returned no data")
            except Exception as exc:
                failed.append(mod_name)
                reasons[mod_name] = f"{type(exc).__name__}: {exc}"
                print_status(f"{mod_name} error: {exc}", "error")

        unified = self._unify(target, chain, results)
        unified["modules_ran"] = ran
        unified["modules_failed"] = failed
        unified["failure_reasons"] = reasons
        unified["module_results"] = results

        # Feed the same entity store full_recon uses, so `db overlap` / `db
        # history` see wallet findings (social handles, counterparties, ENS).
        try:
            from core.correlate import correlate
            from modules.full_recon import FullRecon
            correlation = correlate(target, results, target_type="wallet")
            unified["entity_diff"] = FullRecon._persist_correlation(
                target, correlation)
            unified["entity_totals"] = correlation.get("totals", {})
        except Exception as exc:
            print_status(f"entity persistence skipped: {exc}", "warning")

        # Persist the bundle (best-effort).
        try:
            reporter = Reporter()
            reporter.save_module_result(target, "crypto_full", unified)
        except Exception as exc:
            print_status(f"report save failed: {exc}", "warning")

        self._print_summary(unified)
        self.results = unified
        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _unify(target, chain, results):
        if chain == "tron":
            return CryptoFull._unify_tron(target, results)

        profile = results.get("harvest/crypto_profile", {}) or {}
        portfolio = results.get("harvest/crypto_portfolio", {}) or {}
        txs = results.get("harvest/crypto_transactions", {}) or {}
        balance = results.get("harvest/crypto_balance", {}) or {}

        symbol = (profile.get("symbol") or portfolio.get("symbol")
                  or txs.get("symbol") or balance.get("symbol"))

        # Collect the neutral signals from every module that emits them.
        signals = CryptoFull._sanction_signal(results) + list(
            profile.get("signals") or [])

        identity = {
            "chain": chain,
            "symbol": symbol,
            "address_type": profile.get("address_type"),
            "ens_name": profile.get("ens_name"),
            "is_contract": profile.get("is_contract"),
            "proxy_type": profile.get("proxy_type"),
            "reputation": profile.get("reputation"),
            "is_scam": profile.get("is_scam"),
        }

        nft = results.get("harvest/crypto_nft", {}) or {}
        # DOGE has no portfolio source; crypto_balance supplies its balance.
        native = portfolio.get("native_balance")
        if native is None:
            native = (balance.get("data") or {}).get("balance")
        holdings = {
            "native_balance": native,
            "native_balance_usd": portfolio.get("native_balance_usd"),
            "token_count": portfolio.get("token_count", 0),
            "top_tokens": (portfolio.get("tokens") or [])[:10],
            "total_usd": portfolio.get("total_usd"),
            "nft_collection_count": nft.get("collection_count", 0),
            "nft_collections": (nft.get("collections") or [])[:10],
        }

        flow = {
            "transaction_count": (txs.get("transaction_count")
                                  or (balance.get("data") or {}).get("transaction_count")),
            "total_received": txs.get("total_received"),
            "total_sent": txs.get("total_sent"),
            "unique_counterparties": txs.get("unique_counterparties", 0),
            "top_counterparties": (txs.get("counterparties") or [])[:10],
            "token_flow": (txs.get("token_summary") or [])[:10],
        }

        # Social linkage (web3.bio) and cross-chain presence, when gathered.
        ident_mod = results.get("harvest/crypto_identity", {}) or {}
        social = {
            "links": ident_mod.get("links") or {},
            "handles": ident_mod.get("social_handles") or [],
            "identities": ident_mod.get("identities") or [],
            "urls": ident_mod.get("urls") or [],
        }
        if ident_mod.get("ens_name") and not identity.get("ens_name"):
            identity["ens_name"] = ident_mod.get("ens_name")

        multichain = results.get("harvest/crypto_multichain", {}) or {}
        presence = {
            "active_chains": multichain.get("active_chains") or [],
            "active_count": multichain.get("active_count", 0),
        }

        return {
            "address": target,
            "chain": chain,
            "symbol": symbol,
            "valid": True,
            "identity": identity,
            "holdings": holdings,
            "activity": profile.get("activity") or {},
            "flow": flow,
            "social": social,
            "presence": presence,
            "signals": signals,
        }

    @staticmethod
    def _sanction_signal(results):
        """A sanctions hit is the single most important fact — surface it first.

        A screening FAILURE (list unfetchable → sanctioned is None) must never be
        silently indistinguishable from "clean": emit an explicit unavailable
        signal so the report cannot false-clear a sanctioned wallet.
        """
        s = results.get("harvest/crypto_sanctions") or {}
        if s.get("sanctioned") is True:
            return [{"signal": "ofac_sanctioned",
                     "detail": "address is on the OFAC SDN sanctions list"}]
        if "harvest/crypto_sanctions" in results and (
                s.get("sanctioned") is None or s.get("list_available") is False):
            if s.get("reason") == "no_list_for_chain":
                detail = (f"no OFAC list is published for "
                          f"{(s.get('chain') or 'this chain').upper()} — "
                          f"NOT screened, not a clean result")
            else:
                detail = ("OFAC list could not be fetched — screening "
                          "INCONCLUSIVE, not a clean result")
            return [{"signal": "sanctions_screening_unavailable",
                     "detail": detail}]
        return []

    @staticmethod
    def _unify_tron(target, results):
        t = results.get("harvest/crypto_tron", {}) or {}
        signals = CryptoFull._sanction_signal(results)
        if t.get("risk_flag"):
            signals.append({
                "signal": "explorer_risk_flag",
                "detail": "TronScan has flagged this address as risky",
            })
        for label in (t.get("labels") or []):
            signals.append({"signal": "explorer_label", "detail": label})

        return {
            "address": target,
            "chain": "tron",
            "symbol": "TRX",
            "valid": True,
            "identity": {
                "chain": "tron",
                "symbol": "TRX",
                "address_type": "tron account",
                "ens_name": t.get("account_name"),
                "is_contract": None,
                "proxy_type": None,
                "reputation": None,
                "is_scam": t.get("risk_flag"),
            },
            "holdings": {
                "native_balance": t.get("native_balance"),
                "native_balance_usd": None,
                "token_count": t.get("token_count", 0),
                "top_tokens": (t.get("holdings") or [])[:10],
                "total_usd": None,
            },
            "activity": {},
            "flow": {
                "transaction_count": t.get("tx_count"),
                "total_received": t.get("trc20_received"),
                "total_sent": t.get("trc20_sent"),
                "unique_counterparties": len(t.get("counterparties") or []),
                "top_counterparties": (t.get("counterparties") or [])[:10],
                "token_flow": (t.get("token_summary") or [])[:10],
            },
            "signals": signals,
        }

    @staticmethod
    def _print_summary(u):
        ident = u["identity"]
        hold = u["holdings"]
        flow = u["flow"]

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}")
        print("  WALLET INTELLIGENCE SUMMARY")
        print(f"{'='*60}{Colors.RESET}")
        print(f"  Address:   {u['address']}")
        print(f"  Chain:     {ident.get('chain')}  ({ident.get('address_type')})")
        if ident.get("ens_name"):
            print(f"  ENS:       {ident['ens_name']}")
        if ident.get("reputation"):
            print(f"  Reputation:{ident['reputation']}")

        nb, nbu = hold.get("native_balance"), hold.get("native_balance_usd")
        if nb is not None:
            usd = f"  (${nbu:,.2f})" if nbu is not None else ""
            print(f"  Balance:   {nb} {u.get('symbol')}{usd}")
        if hold.get("token_count"):
            print(f"  Tokens:    {hold['token_count']} positions")
        if hold.get("nft_collection_count"):
            print(f"  NFTs:      {hold['nft_collection_count']} collections")
        if hold.get("total_usd") is not None:
            print(f"  Portfolio: ${hold['total_usd']:,.2f} (reported holdings)")

        if flow.get("transaction_count") is not None:
            print(f"  Txs:       {flow['transaction_count']}  "
                  f"(in {flow.get('total_received')} / "
                  f"out {flow.get('total_sent')})")
        if flow.get("unique_counterparties"):
            print(f"  Peers:     {flow['unique_counterparties']} unique counterparties")

        presence = u.get("presence") or {}
        if presence.get("active_count"):
            print(f"  Chains:    active on {presence['active_count']} "
                  f"({', '.join(presence['active_chains'])})")

        social = u.get("social") or {}
        if social.get("links"):
            print(f"\n  {Colors.BOLD}Social links:{Colors.RESET}")
            for kind, handle in social["links"].items():
                print(f"    {Colors.CYAN}{kind:10}{Colors.RESET} {handle}")

        if u["signals"]:
            print(f"\n  {Colors.BOLD}Signals (neutral):{Colors.RESET}")
            for s in u["signals"]:
                marker = (Colors.RED + "!" if s.get("signal") == "explorer_scam_flag"
                          else Colors.YELLOW + "~") + Colors.RESET
                print(f"    {marker} {s.get('signal')}: {Colors.DIM}{s.get('detail')}{Colors.RESET}")

        print(f"\n  Ran {len(u.get('modules_ran', []))} modules, "
              f"{len(u.get('modules_failed', []))} failed")
        for name, why in (u.get("failure_reasons") or {}).items():
            print(f"    {Colors.RED}x{Colors.RESET} {name}: "
                  f"{Colors.DIM}{why}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*60}{Colors.RESET}\n")
