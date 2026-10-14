import re
import time
import threading
import importlib
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from core.base_module import BaseModule
from core.utils import (
    Colors,
    print_status,
    is_valid_domain,
    is_valid_ip,
    is_valid_url,
)
from core.reporter import Reporter
from core.config import Config


# Meta modules that orchestrate others — never dispatched by this module.
# Aggregators that orchestrate other modules — never dispatched by full_recon,
# or it would re-run their children a second time. crypto_full bundles the four
# wallet modules, so full_recon runs those four leaves directly, not the bundle.
META_MODULES = {
    "full_recon", "identity_pivot", "monitor",
    # Aggregators that re-run other modules — excluded so full_recon runs each
    # leaf exactly once instead of running the bundle AND its children.
    "harvest/crypto_full", "web/full_web", "web/recon_full", "github/full_github",
}


# Which slash-separated tokens in a module's `target_type` are acceptable
# for each detected input type. A module matches if any of its tokens is here.
# (e.g. module declares "domain/ip" -> tokens {"domain","ip"})
TOKEN_ACCEPT = {
    "ip":       {"ip"},
    "cidr":     {"ip", "cidr"},
    "asn":      {"asn"},
    "url":      {"url", "commit_url"},
    "domain":   {"domain"},
    "email":    {"email"},
    "wallet":   {"wallet"},
    "phone":    {"phone"},
    "username": {"username", "owner", "org", "repo", "id", "sha"},
}


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ETH_RE   = re.compile(r"^0x[a-fA-F0-9]{40}$")
_BTC_RE   = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_TRON_RE  = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_ASN_RE   = re.compile(r"^AS\d+$", re.IGNORECASE)
_PHONE_RE = re.compile(r"^\+?[\d\s\-()]{10,20}$")


def derive_subtargets(target, detected, expand_email=True, expand_username=False):
    """Ordered (value, type) phases to dispatch against.

    An email carries two further pivots: its domain and its local part. Widening
    every module's target_type to accept "email" would be wrong (recon/dns_enum
    cannot resolve "bob@acme.com", it needs "acme.com"), so the split happens
    here and each module still receives a value of a type it already declares.

    The first phase whose type a module accepts is the one it runs against, so
    every module runs exactly once.
    """
    phases = [(target, detected)]
    if detected != "email":
        return phases

    local, _, domain = target.partition("@")
    if expand_email and domain:
        phases.append((domain, "domain"))
    # A local part matches plenty of unrelated accounts, so this stays opt-in.
    if expand_username and local:
        phases.append((local, "username"))
    return phases


def detect_target_type(target):
    """Classify TARGET into one of:
    ip, cidr, asn, url, domain, email, wallet, phone, username.
    """
    t = (target or "").strip()
    if not t:
        return "username"

    if _EMAIL_RE.match(t):
        return "email"

    if is_valid_url(t):
        return "url"

    if "/" in t:
        base, _, mask = t.partition("/")
        if is_valid_ip(base) and mask.isdigit() and 0 <= int(mask) <= 32:
            return "cidr"

    if _ASN_RE.match(t):
        return "asn"

    if _ETH_RE.match(t) or _BTC_RE.match(t) or _TRON_RE.match(t):
        return "wallet"

    if is_valid_ip(t):
        return "ip"

    if _PHONE_RE.match(t):
        digits = re.sub(r"\D", "", t)
        if 10 <= len(digits) <= 15:
            return "phone"

    if is_valid_domain(t):
        return "domain"

    return "username"


class FullRecon(BaseModule):
    name = "full_recon"
    description = "Dispatch every registered module whose target_type matches the given TARGET."
    category = "auto"
    target_type = "auto"

    def _register_options(self):
        self.add_option(
            "TARGET", "", True,
            "Target (domain / IP / CIDR / ASN / URL / email / username / phone / wallet)",
        )
        self.add_option(
            "SKIP", "", False,
            "Comma-separated module names to exclude (e.g. web/dir_bruteforce,recon/port_scan)",
        )
        self.add_option(
            "INCLUDE_INTRUSIVE", "false", False,
            "Set true to also run modules marked intrusive=True (attacks/brute-force)",
        )
        self.add_option(
            "INCLUDE_CATEGORIES", "recon,web,harvest,github", False,
            "Comma-separated categories to include (recon,web,harvest,github,auto)",
        )
        self.add_option(
            "MAX_FAILURES_PER_MODULE", "1", False,
            "Max attempts per module before giving up",
        )
        self.add_option(
            "THREADS", "5", False,
            "Parallel threads for module execution (1 = sequential)",
        )
        self.add_option(
            "TIMEOUT_PER_MODULE", "120", False,
            "Seconds to wait for each module before skipping it",
        )
        self.add_option(
            "EXPAND_EMAIL", "true", False,
            "For an email target, also run domain modules against its domain",
        )
        self.add_option(
            "EXPAND_USERNAME", "false", False,
            "For an email target, also run username modules against its local "
            "part (off by default: a local part matches unrelated accounts)",
        )
        self.add_option(
            "ENRICH_BREACH", "true", False,
            "After the scan, auto-check every discovered email for breaches "
            "(free, no key) and show which are exposed + how to see details",
        )
        self.add_option(
            "ENRICH_SANCTIONS", "true", False,
            "After the scan, auto-screen every discovered crypto wallet against "
            "the OFAC sanctions list (free, offline cache) and flag any hit",
        )

    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        # Deferred to avoid an import cycle at module load time.
        from core.console import MODULE_REGISTRY

        target = (self.get_option("TARGET") or "").strip()
        skip_list = {
            s.strip() for s in (self.get_option("SKIP") or "").split(",") if s.strip()
        }
        include_intrusive = (
            (self.get_option("INCLUDE_INTRUSIVE") or "false").strip().lower() == "true"
        )
        allowed_categories = {
            c.strip().lower()
            for c in (self.get_option("INCLUDE_CATEGORIES") or "").split(",")
            if c.strip()
        }
        if not allowed_categories:
            allowed_categories = {"recon", "web", "harvest", "github"}

        try:
            max_attempts = max(1, int(self.get_option("MAX_FAILURES_PER_MODULE") or "1"))
        except (TypeError, ValueError):
            max_attempts = 1

        try:
            threads = max(1, int(self.get_option("THREADS") or "5"))
        except (TypeError, ValueError):
            threads = 5

        try:
            mod_timeout = max(10, int(self.get_option("TIMEOUT_PER_MODULE") or "120"))
        except (TypeError, ValueError):
            mod_timeout = 120

        expand_email = (
            (self.get_option("EXPAND_EMAIL") or "true").strip().lower() == "true"
        )
        expand_username = (
            (self.get_option("EXPAND_USERNAME") or "false").strip().lower() == "true"
        )
        enrich_breach = (
            (self.get_option("ENRICH_BREACH") or "true").strip().lower() == "true"
        )
        enrich_sanctions = (
            (self.get_option("ENRICH_SANCTIONS") or "true").strip().lower() == "true"
        )

        detected = detect_target_type(target)
        phases = derive_subtargets(target, detected, expand_email, expand_username)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print("  FULL RECONNAISSANCE SCAN")
        print(f"  Target:        {target}")
        print(f"  Detected type: {detected}")
        if len(phases) > 1:
            derived = ", ".join(f"{value} ({kind})" for value, kind in phases[1:])
            print(f"  Also scanning:  {derived}")
        print(f"  Categories:    {','.join(sorted(allowed_categories))}")
        print(f"  Intrusive:     {'yes' if include_intrusive else 'no'}")
        print(f"  Max attempts:  {max_attempts}")
        print(f"  Threads:       {threads}")
        print(f"  Mod timeout:   {mod_timeout}s")
        print(f"{'='*60}{Colors.RESET}\n")

        # ---- Build the dispatch list by walking MODULE_REGISTRY ----------
        dispatch = []
        skipped = {}

        for mod_name, (mod_path, class_name) in MODULE_REGISTRY.items():
            if mod_name in META_MODULES:
                skipped[mod_name] = "meta module (not dispatched)"
                continue
            if mod_name in skip_list:
                skipped[mod_name] = "user SKIP"
                continue

            try:
                mod_mod = importlib.import_module(mod_path)
                mod_cls = getattr(mod_mod, class_name)
            except Exception as exc:
                skipped[mod_name] = f"import error: {type(exc).__name__}: {exc}"
                continue

            category = (getattr(mod_cls, "category", "") or "").lower()
            if category and category not in allowed_categories:
                skipped[mod_name] = f"category '{category}' excluded"
                continue

            tt_raw = (getattr(mod_cls, "target_type", "") or "").strip()
            tokens = {t.strip().lower() for t in tt_raw.split("/") if t.strip()}

            # First phase this module accepts wins, so it runs exactly once.
            value = None
            for phase_value, phase_kind in phases:
                if tt_raw.lower() == "any" or (
                        tokens & TOKEN_ACCEPT.get(phase_kind, set())):
                    value = phase_value
                    break

            if value is None:
                kinds = "/".join(kind for _, kind in phases)
                skipped[mod_name] = f"target_type '{tt_raw}' not for '{kinds}'"
                continue

            if bool(getattr(mod_cls, "intrusive", False)) and not include_intrusive:
                skipped[mod_name] = "intrusive (set INCLUDE_INTRUSIVE=true to enable)"
                continue

            dispatch.append((mod_name, mod_cls, value))

        total = len(dispatch)
        if total == 0:
            print_status(
                f"No modules match target type '{detected}'. "
                f"Nothing to run.", "warning",
            )

        # ---- Execute --------------------------------------------------
        start = time.time()
        ran = []
        failed = {}
        per_module = {}
        ran_against = {}
        finalized = set()   # modules already recorded (timed-out ones included)
        _lock = threading.Lock()

        def _run_one(idx, mod_name, mod_cls, value):
            suffix = "" if value == target else f" {Colors.DIM}<- {value}{Colors.RESET}"
            print(
                f" {Colors.CYAN}[{idx}/{total}]{Colors.RESET} "
                f"{Colors.BOLD}{mod_name}{Colors.RESET}{suffix} ..."
            )
            last_error = None
            success = False
            for attempt in range(1, max_attempts + 1):
                try:
                    mod = mod_cls()
                    mod.set_option("TARGET", value)
                    ok = mod.run()
                    if ok:
                        with _lock:
                            # The watchdog already timed this module out and the
                            # scan moved on — don't resurrect it from a late thread.
                            if mod_name in finalized:
                                return
                            finalized.add(mod_name)
                            per_module[mod_name] = mod.get_results()
                            ran.append(mod_name)
                            ran_against[mod_name] = value
                        print_status(f"{mod_name} ok", "success")
                        success = True
                        break
                    res = mod.get_results() or {}
                    errs = res.get("fetch_errors") or []
                    last_error = (errs[0] if errs
                                  else res.get("error") or "run() returned falsy")
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                if attempt < max_attempts:
                    print_status(
                        f"{mod_name} attempt {attempt} failed ({last_error}); retrying",
                        "warning",
                    )
            if not success:
                with _lock:
                    if mod_name in finalized:
                        return
                    finalized.add(mod_name)
                    failed[mod_name] = last_error or "unknown error"
                print_status(f"{mod_name} failed: {failed[mod_name]}", "error")

        if threads == 1:
            for idx, (mod_name, mod_cls, value) in enumerate(dispatch, start=1):
                _run_one(idx, mod_name, mod_cls, value)
        else:
            # NOT a `with` block: its __exit__ joins every worker, which would
            # re-block on a hung module and defeat the per-module timeout. We
            # shut down without waiting instead; a lingering thread's late
            # result is dropped by the `finalized` guard in _run_one.
            pool = ThreadPoolExecutor(max_workers=threads)
            try:
                future_map = {
                    pool.submit(_run_one, idx, mod_name, mod_cls, value):
                        (idx, mod_name)
                    for idx, (mod_name, mod_cls, value)
                    in enumerate(dispatch, start=1)
                }
                done_count = 0
                pending = set(future_map)
                # PER-MODULE timeout, enforced: wait at most mod_timeout for the
                # NEXT module to finish. A single hung host can no longer freeze
                # the whole scan the way one aggregate timeout did.
                while pending:
                    done, pending = wait(pending, timeout=mod_timeout,
                                         return_when=FIRST_COMPLETED)
                    if not done:
                        # Nothing advanced within mod_timeout: treat the rest as
                        # timed out. Their threads may still be alive; cancel the
                        # ones not started and finalize the names so a late
                        # result is ignored.
                        for fut in pending:
                            idx, mod_name = future_map[fut]
                            fut.cancel()
                            with _lock:
                                if mod_name not in finalized:
                                    finalized.add(mod_name)
                                    failed[mod_name] = (
                                        f"timed out (> {mod_timeout}s, no progress)")
                            print_status(f"{mod_name} timed out "
                                         f"(> {mod_timeout}s)", "error")
                        break
                    for fut in done:
                        done_count += 1
                        idx, mod_name = future_map[fut]
                        exc = fut.exception()
                        if exc:
                            with _lock:
                                if mod_name not in finalized:
                                    finalized.add(mod_name)
                                    failed[mod_name] = f"thread error: {exc}"
                            print_status(f"{mod_name} thread error: {exc}", "error")
                        print(f"  {Colors.DIM}[{done_count}/{total} done]"
                              f"{Colors.RESET}")
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        duration = round(time.time() - start, 2)

        # ---- Summary --------------------------------------------------
        reasons = {
            "type":      sum(1 for v in skipped.values() if v.startswith("target_type")),
            "intrusive": sum(1 for v in skipped.values() if v.startswith("intrusive")),
            "user":      sum(1 for v in skipped.values() if v == "user SKIP"),
            "category":  sum(1 for v in skipped.values() if v.startswith("category")),
            "meta":      sum(1 for v in skipped.values() if v.startswith("meta")),
            "import":    sum(1 for v in skipped.values() if v.startswith("import error")),
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}")
        print("  FULL RECON COMPLETE")
        print(f"  Target:    {target}  ({detected})")
        print(f"  Ran:       {len(ran)}/{total}")
        print(f"  Failed:    {len(failed)}")
        print(
            f"  Skipped:   {len(skipped)}  "
            f"(type={reasons['type']}, intrusive={reasons['intrusive']}, "
            f"user={reasons['user']}, category={reasons['category']}, "
            f"meta={reasons['meta']}, import={reasons['import']})"
        )
        print(f"  Duration:  {duration}s")
        print(f"{'='*60}{Colors.RESET}\n")

        # ---- Correlate every module's findings into one entity map ----
        correlation = {}
        entity_diff = {}
        try:
            from core.correlate import correlate

            correlation = correlate(target, per_module, target_type=detected)
            entity_diff = self._persist_correlation(target, correlation)
            self._print_correlation(correlation, entity_diff)
        except Exception as exc:
            print_status(f"correlation failed: {exc}", "warning")

        # ---- Auto-enrich discovered emails with a breach yes/no -----------
        breach_enrichment = {}
        if enrich_breach:
            breach_enrichment = self._enrich_breaches(correlation)

        # ---- Auto-screen discovered wallets against OFAC sanctions --------
        sanctions_enrichment = {}
        if enrich_sanctions:
            sanctions_enrichment = self._enrich_sanctions(correlation)

        # ---- Reports (best-effort; non-fatal) -------------------------
        try:
            reporter = Reporter()
            md_path, json_path = reporter.generate_full_report(target, per_module)
            html_path = reporter.generate_html_report(target, per_module)
            print_status(f"MD   -> {md_path}", "info")
            print_status(f"JSON -> {json_path}", "info")
            print_status(f"HTML -> {html_path}", "info")

            if correlation.get("entities"):
                recon_path = reporter.generate_correlation_report(
                    target, correlation,
                    scan_meta={
                        "modules_run": len(ran),
                        "modules_failed": len(failed),
                        "duration_seconds": duration,
                    },
                )
                print_status(f"RECON-> {recon_path}", "success")
        except Exception as exc:
            print_status(f"report generation failed: {exc}", "warning")

        # ---- Return structure per spec --------------------------------
        self.results = {
            "target": target,
            "target_type_detected": detected,
            "modules_run": ran,
            "modules_skipped": skipped,
            "modules_failed": failed,
            "per_module_results": per_module,
            "duration_seconds": duration,
            "correlation": correlation,
            "scan_phases": [{"value": v, "type": k} for v, k in phases],
            "modules_ran_against": ran_against,
            "entity_diff": entity_diff,
            "breach_enrichment": breach_enrichment,
            "sanctions_enrichment": sanctions_enrichment,
        }
        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _persist_correlation(target, correlation):
        """Store the entity map so later scans can be compared against it."""
        if not Config().get("database.enabled", True):
            return {}
        try:
            from core.database import Database

            db = Database()
            try:
                return db.save_correlation(target, correlation)
            finally:
                db.close()
        except Exception as exc:
            print_status(f"entity persistence failed: {exc}", "warning")
            return {}

    @staticmethod
    def _enrich_breaches(correlation, max_emails=5):
        """For each discovered email, a fast free breach yes/no, then tell the
        user which are exposed and the exact command to see the full leaks.

        This is the 'a module found an email -> was it leaked?' auto-step. It
        uses only the quick check-email endpoint (free, no key); the heavy
        detail is left to the breach_check module the hint points at."""
        emails = [e["value"] for e in
                  (correlation.get("entities") or {}).get("email", [])]
        if not emails:
            return {}
        emails = emails[:max_emails]
        try:
            from modules.harvest.breach_check import BreachCheck
        except Exception:
            return {}

        checker = BreachCheck()
        out = {}
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print("  AUTO BREACH CHECK (discovered emails)")
        print(f"{'='*60}{Colors.RESET}")
        for email in emails:
            try:
                breached, names = checker._check_email(email)
            except Exception:
                breached, names = None, []
            out[email] = {"breached": breached, "sample": names[:5]}
            if breached:
                print(f"  {Colors.RED}✗ {email}{Colors.RESET} — BREACHED"
                      + (f" ({len(names)}+ sources)" if names else ""))
                print(f"    {Colors.DIM}see details: use harvest/breach_check; "
                      f"set TARGET {email}; run{Colors.RESET}")
            elif breached is False:
                print(f"  {Colors.GREEN}✓ {email}{Colors.RESET} — no breach found")
            else:
                print(f"  {Colors.YELLOW}? {email}{Colors.RESET} — check "
                      f"unavailable (not a clean result)")
        exposed = sum(1 for v in out.values() if v["breached"])
        if exposed:
            print(f"\n  {Colors.BOLD}{exposed} of {len(out)} email(s) appear in "
                  f"breaches — run the command above for the leaked data.{Colors.RESET}")
        print()
        return out

    @staticmethod
    def _enrich_sanctions(correlation, max_wallets=10):
        """For each discovered crypto wallet, a free OFAC sanctions screen, then
        flag any hit and point at the full module.

        The 'a module found a wallet -> is it sanctioned?' auto-step. OFAC lists
        are a local weekly cache (offline, instant), so this is cheap. A chain
        with no published list (e.g. DOGE) or an unavailable list is reported as
        'not screened', never as clean."""
        wallets = [e["value"] for e in
                   (correlation.get("entities") or {}).get("wallet", [])]
        if not wallets:
            return {}
        wallets = wallets[:max_wallets]
        try:
            from modules.harvest.crypto_sanctions import CryptoSanctions
        except Exception:
            return {}

        out = {}
        flagged = 0
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print("  AUTO OFAC SANCTIONS SCREEN (discovered wallets)")
        print(f"{'='*60}{Colors.RESET}")
        for addr in wallets:
            sanctioned, reason = None, ""
            try:
                mod = CryptoSanctions()
                mod.set_option("TARGET", addr)
                mod.run()
                res = mod.get_results() or {}
                sanctioned = res.get("sanctioned")
                reason = res.get("reason", "") or ""
            except Exception:
                sanctioned = None
            out[addr] = {"sanctioned": sanctioned, "reason": reason}
            if sanctioned is True:
                flagged += 1
                print(f"  {Colors.RED}*** {addr} — SANCTIONED (OFAC SDN) ***{Colors.RESET}")
                print(f"    {Colors.DIM}details: use harvest/crypto_sanctions; "
                      f"set TARGET {addr}; run{Colors.RESET}")
            elif sanctioned is False:
                print(f"  {Colors.GREEN}✓ {addr}{Colors.RESET} — not on the OFAC list")
            else:
                print(f"  {Colors.YELLOW}? {addr}{Colors.RESET} — NOT screened"
                      + (f" ({reason})" if reason else "") + " (not a clean result)")
        if flagged:
            print(f"\n  {Colors.BOLD}{Colors.RED}{flagged} of {len(out)} wallet(s) "
                  f"are OFAC-sanctioned.{Colors.RESET}")
        print()
        return out

    @staticmethod
    def _print_correlation(correlation, entity_diff=None):
        totals = correlation.get("totals") or {}
        if not totals:
            return
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print("  CORRELATED ENTITIES")
        print(f"{'='*60}{Colors.RESET}")
        summary = "  ".join(f"{k}={v}" for k, v in totals.items())
        print(f"  {summary}")

        corroborated = correlation.get("corroborated") or []
        if corroborated:
            print(f"\n  {Colors.BOLD}Confirmed by 2+ modules:{Colors.RESET}")
            for entity in corroborated[:15]:
                print(
                    f"    {Colors.GREEN}+{Colors.RESET} {entity['value']}  "
                    f"{Colors.DIM}({entity['module_count']} modules, "
                    f"{entity['confidence']}){Colors.RESET}"
                )
        else:
            print(f"\n  {Colors.DIM}(nothing corroborated by 2+ modules){Colors.RESET}")

        pivots = correlation.get("pivot_suggestions") or []
        if pivots:
            print(f"\n  {Colors.BOLD}Worth pivoting on:{Colors.RESET}")
            for pivot in pivots[:5]:
                print(f"    {Colors.YELLOW}>{Colors.RESET} {pivot['value']} "
                      f"{Colors.DIM}({pivot['type']}){Colors.RESET}")

        diff = entity_diff or {}
        if diff.get("new") and diff.get("returning"):
            print(f"\n  {Colors.BOLD}New since the last scan "
                  f"({len(diff['new'])}):{Colors.RESET}")
            for entity in diff["new"][:10]:
                print(f"    {Colors.GREEN}NEW{Colors.RESET} {entity['value']} "
                      f"{Colors.DIM}({entity['type']}){Colors.RESET}")
        if diff.get("absent"):
            print(f"\n  {Colors.BOLD}Previously seen, not in this scan "
                  f"({len(diff['absent'])}):{Colors.RESET}")
            for entity in diff["absent"][:10]:
                print(f"    {Colors.YELLOW}-{Colors.RESET} {entity['value']} "
                      f"{Colors.DIM}({entity['type']}){Colors.RESET}")
            print(f"    {Colors.DIM}A module failing this run looks the same as "
                  f"an entity disappearing — verify before concluding.{Colors.RESET}")
        print()

