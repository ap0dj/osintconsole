"""Deep multi-type identity pivot.

Starts from ANY seed identifier (email / username / phone / wallet / domain /
ip) and chases every related identity it can discover via the project's own
modules, bidirectionally where possible.

Design:
    - A dispatch table maps each identity type to a list of pivot functions.
    - Each pivot function wraps one sub-module call and returns a list of
      (new_value, new_type, via_label) tuples.
    - A BFS over (value, type, depth) tuples walks the identity graph,
      honouring MAX_DEPTH and MAX_PER_TYPE (per hop).
    - Intrusive pivots (brute-forcing, variation probes) are opt-in via
      INCLUDE_INTRUSIVE; everything else is passive.
    - A single pivot or module failure NEVER aborts the whole pivot - every
      call is isolated with try/except, and modules missing from the registry
      are soft-skipped.
"""
import re
import time
import importlib
from core.base_module import BaseModule
from core.utils import (
    print_status, Colors, is_valid_ip, is_valid_domain, extract_entities,
)
from core.chains import detect_chain, is_ens_name
from core.reporter import Reporter


# ------------------------------------------------------------------ helpers

_VALID_TYPES = ("email", "username", "phone", "wallet", "domain", "ip")


def _detect_type(value):
    """Guess the identity type of a seed value.

    Order matters: email first (contains '@'), then IP, then wallet (unique
    prefixes/regex), then phone (digits), then domain, else username.
    """
    v = (value or "").strip()
    if not v:
        return "username"
    # email
    if "@" in v and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "email"
    # ip (v4 only - keeps parity with core.utils.is_valid_ip)
    if is_valid_ip(v):
        return "ip"
    # wallet: the shared strict classifier (ETH/BTC/LTC/DOGE/Tron). The old
    # loose Base58 class admitted 0/l/I/O and missed Tron entirely.
    if detect_chain(v):
        return "wallet"
    # phone (country-coded or 10-15 bare digits)
    if v.startswith("+") and re.match(r"^\+\d[\d\s\-()]{6,}$", v):
        return "phone"
    if re.match(r"^\d{10,15}$", v):
        return "phone"
    # domain (needs a dot)
    if is_valid_domain(v) and "." in v:
        return "domain"
    return "username"


def _intrusive(fn):
    """Decorator: mark a pivot function as intrusive (opt-in only)."""
    fn.intrusive = True
    return fn


def _canon(value, vtype):
    """Canonical form for graph identity (lowercases email/username/domain,
    and ETH hex wallets; Base58 wallets keep their significant case)."""
    if not isinstance(value, str):
        return value
    v = value.strip()
    if vtype in ("email", "username", "domain"):
        return v.lower()
    if vtype == "wallet" and v.lower().startswith("0x"):
        return v.lower()
    return v


# ================================================================ module

class IdentityPivot(BaseModule):
    name = "identity_pivot"
    description = (
        "Deep multi-type identity pivot - one seed (email / username / phone / "
        "wallet / domain / ip) auto-chases related identities across every "
        "relevant module into a full identity graph")
    category = "auto"
    target_type = "any"

    def _register_options(self):
        self.add_option(
            "TARGET", "", True,
            "Any identifier: email, username, phone, wallet, domain, or IP")
        self.add_option(
            "TARGET_TYPE", "", False,
            "Force seed type (email/username/phone/wallet/domain/ip); "
            "blank = auto-detect")
        self.add_option(
            "MAX_DEPTH", "2", False, "How many pivot hops to follow")
        self.add_option(
            "MAX_PER_TYPE", "5", False,
            "Max new entities to pivot per type per hop")
        self.add_option(
            "INCLUDE_INTRUSIVE", "false", False,
            "If 'true', also run intrusive pivots (subdomain brute-force, "
            "username variation probes)")
        self.add_option(
            "FOLLOW_COUNTERPARTIES", "false", False,
            "If 'true', a wallet also pivots to its top transaction "
            "counterparties (leads, not the same person - off by default)")
        self.add_option(
            "GRAPH", "true", False,
            "Generate an interactive visual relationship graph")
        self.add_option(
            "MIN_SCORE", "0", False,
            "Only show entities with relevance score >= this")

    # ------------------------------------------------------------ loader

    def _load(self, mod_name):
        """Lazy-load a registry module by its slash-notation name.
        Returns a fresh instance or None (soft import)."""
        try:
            from core.console import MODULE_REGISTRY
            if mod_name not in MODULE_REGISTRY:
                return None
            path, cls = MODULE_REGISTRY[mod_name]
            mod = importlib.import_module(path)
            return getattr(mod, cls)()
        except Exception:
            return None

    def _run_module(self, mod_name, target, extra_options=None):
        """Run a sub-module and return its results dict (or {} on failure).

        A single module failing must NEVER abort the pivot."""
        mod = self._load(mod_name)
        if mod is None:
            return {}
        try:
            mod.set_option("TARGET", target)
            if extra_options:
                for k, v in extra_options.items():
                    mod.set_option(k, v)
            try:
                ok = mod.run()
            except Exception as e:
                print_status(f"{mod_name} run error: {e}", "warning")
                return {}
            if not ok:
                return {}
            res = mod.get_results() or {}
            key = f"{mod_name} <= {target}"
            # Keep the first result if the same (module, target) runs twice.
            self._module_results.setdefault(key, res)
            return res
        except Exception as e:
            print_status(f"{mod_name} error: {e}", "warning")
            return {}

    # ---------------------------------------------------- entity extractors

    @staticmethod
    def _logins_in(obj):
        """Walk any nested dict/list and pull GitHub-style login / username
        / slug / handle fields."""
        found = set()

        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if (k in ("login", "username", "slug", "handle")
                            and isinstance(v, str) and v):
                        found.add(v.strip().lower())
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        walk(obj)
        return found

    # ======================================================= pivot funcs
    # Each returns a list of (new_value, new_type, via_label) tuples.

    # ------------------------------------------------------------- email
    def _pivot_email_to_username(self, email):
        """email local-part -> username candidate."""
        out = []
        local = email.split("@", 1)[0]
        if re.match(r"^[a-zA-Z0-9._-]{3,}$", local):
            out.append((local.lower(), "username", "email_local_part"))
        return out

    def _pivot_email_to_domain(self, email):
        """email -> right-hand domain."""
        domain = email.split("@", 1)[-1].strip().lower()
        if domain and is_valid_domain(domain):
            return [(domain, "domain", "email_domain")]
        return []

    def _pivot_email_breach(self, email):
        """email -> breach records; breach-source domains become seeds."""
        res = self._run_module("harvest/breach_check", email)
        out = []
        for b in (res.get("breaches") or []):
            dom = (b.get("domain") or "").strip().lower()
            if dom and is_valid_domain(dom):
                out.append((dom, "domain", "breach"))
        return out

    # ---------------------------------------------------------- username
    def _pivot_username_to_email(self, username):
        """username -> email via GitHub username_to_email (6 techniques) +
        anything username_osint happens to surface."""
        out = []
        res = self._run_module("github/username_to_email", username)
        for e in (res.get("all_emails") or []):
            if "@" in (e or ""):
                out.append((e.lower(), "email", "username_to_email"))
        # Harvest emails/handles that username_osint exposes incidentally.
        res2 = self._run_module("harvest/username_osint", username)
        if res2:
            ents = extract_entities(res2)
            for e in ents.get("email", []):
                out.append((e.lower(), "email", "username_osint"))
        return out

    def _pivot_username_to_github(self, username):
        """username -> emails via github/commit_emails (.patch trick)."""
        out = []
        res = self._run_module("github/commit_emails", username)
        for e in (res.get("unique_emails") or []):
            if "@" in (e or ""):
                out.append((e.lower(), "email", "commit_emails"))
        return out

    def _pivot_username_to_telegram(self, username):
        """username -> Telegram-sourced emails / phones / cross-platform
        handles (passive: preview + bio only, no variation probes)."""
        out = []
        res = self._run_module(
            "harvest/telegram_osint", username,
            extra_options={"VARIATIONS": "false",
                           "FETCH_PHOTO_HASH": "false"})
        if not res:
            return out
        contacts = res.get("bio_contacts") or {}
        for e in (contacts.get("emails") or []):
            out.append((e.lower(), "email", "telegram_bio"))
        for p in (contacts.get("phones") or []):
            digits = re.sub(r"[^\d+]", "", p)
            if digits and len(re.sub(r"\D", "", digits)) >= 7:
                out.append((digits, "phone", "telegram_bio"))
        for plat, handles in (res.get("bio_pivots") or {}).items():
            for h in (handles or []):
                if plat == "email" and "@" in h:
                    out.append((h.lower(), "email", "telegram_bio"))
                elif plat != "email":
                    out.append((h.lower(), "username",
                                f"telegram_bio_{plat}"))
        return out

    @_intrusive
    def _pivot_username_to_telegram_variations(self, username):
        """Variation-probe mode of telegram_osint (intrusive, opt-in)."""
        out = []
        res = self._run_module(
            "harvest/telegram_osint", username,
            extra_options={"VARIATIONS": "true",
                           "FETCH_PHOTO_HASH": "false"})
        for c in (res.get("candidates") or []):
            u = (c.get("username") or "").lower()
            if u and u != username.lower():
                out.append((u, "username", "telegram_variation"))
        return out

    def _pivot_username_to_discord(self, username):
        """username -> Discord candidates + bio-sourced cross-platform handles
        (passive: no variation probes)."""
        out = []
        res = self._run_module(
            "harvest/discord_osint", username,
            extra_options={"VARIATIONS": "false"})
        if not res:
            return out
        for c in (res.get("candidates") or []):
            u = (c.get("username") or "").lower()
            if u and u != username.lower():
                out.append((u, "username", "discord_candidate"))
        for plat, hits in (res.get("bio_pivots") or {}).items():
            for h in (hits or []):
                if plat == "email" and "@" in h:
                    out.append((h.lower(), "email", "discord_bio"))
                elif plat != "email":
                    out.append((h.lower(), "username",
                                f"discord_bio_{plat}"))
        return out

    # ------------------------------------------------------------- phone
    def _pivot_phone_to_osint(self, phone):
        """phone -> country / carrier / line-type enrichment (no new seeds).

        We still run the module so its results land in module_results and the
        country/carrier shows up in the final report."""
        self._run_module("harvest/phone_osint", phone)
        return []

    def _pivot_phone_to_telegram(self, phone):
        """phone -> best-effort Telegram public lookup.

        Discord/Signal don't expose a phone->account mapping without a user
        account, so we probe t.me/{digits} - cheap, truthful, and only emits a
        node when the preview page actually returns a real og:title."""
        out = []
        digits = re.sub(r"\D", "", phone)
        if not digits or len(digits) < 7:
            return out
        res = self._run_module(
            "harvest/telegram_osint", digits,
            extra_options={"VARIATIONS": "false",
                           "FETCH_PHOTO_HASH": "false"})
        if res and (res.get("preview") or {}).get("title"):
            out.append((digits, "username", "telegram_phone_handle"))
        return out

    # ------------------------------------------------------------ wallet
    def _pivot_wallet_identity(self, address):
        """EVM wallet -> the PERSON: social handles and ENS name verified to
        this exact address (crypto_identity / web3.bio).

        This is the wallet -> human bridge. Only identities bound to the same
        address are used; look-alike profiles on other addresses are ignored.
        """
        if detect_chain(address) != "ethereum":
            return []   # web3.bio linkage is EVM-only
        res = self._run_module("harvest/crypto_identity", address)
        out = []
        for entry in (res.get("social_handles") or []):
            platform, _, handle = str(entry).partition(":")
            handle = handle.strip().lstrip("@")
            if handle:
                out.append((handle.lower(), "username", f"web3bio_{platform}"))
        for ident in (res.get("identities") or []):
            name = (ident.get("identity") or "").strip().lower()
            if is_ens_name(name):
                out.append((name, "domain", "ens_name"))
        return out

    def _pivot_wallet_counterparties(self, address):
        """wallet -> top transaction counterparties (opt-in via
        FOLLOW_COUNTERPARTIES). These are wallets that MOVED money with the
        target — investigation leads, not the same person — so they are off by
        default. Uses the tracer's structured counterparty list, which excludes
        token contracts and change outputs (the old regex grep emitted USDT/USDC
        contract addresses as 'counterparty wallets')."""
        if not getattr(self, "_follow_counterparties", False):
            return []
        chain = detect_chain(address)
        mod = "harvest/crypto_tron" if chain == "tron" else "harvest/crypto_transactions"
        res = self._run_module(mod, address, extra_options={"MAX_TX": "25"})
        out = []
        for party in (res.get("counterparties") or [])[:5]:
            peer = (party.get("address") or "").strip()
            if peer and peer.lower() != address.lower() and detect_chain(peer):
                out.append((peer, "wallet", "tx_counterparty"))
        return out

    def _pivot_domain_ens(self, domain):
        """ENS name (vitalik.eth) -> the 0x address it resolves to."""
        if not is_ens_name(domain):
            return []
        res = self._run_module("harvest/crypto_ens", domain)
        addr = (res.get("address") or "").strip()
        if addr and detect_chain(addr):
            return [(addr.lower(), "wallet", "ens_resolve")]
        return []

    # ------------------------------------------------------------ domain
    def _pivot_domain_to_emails(self, domain):
        """domain -> discovered emails (Bing + crt.sh + MX role addresses)."""
        if is_ens_name(domain):
            return []   # ENS names are on-chain, not DNS
        res = self._run_module("harvest/domain_emails", domain)
        out = []
        for e in (res.get("emails_found") or []):
            out.append((e.lower(), "email", "domain_emails"))
        return out

    @_intrusive
    def _pivot_domain_to_subdomains(self, domain):
        """domain -> subdomains via recon/subdomain (crt.sh + brute-force).

        Intrusive because of the brute-force stage; opt in via
        INCLUDE_INTRUSIVE=true."""
        if is_ens_name(domain):
            return []
        res = self._run_module(
            "recon/subdomain", domain,
            extra_options={"USE_CRTSH": "true",
                           "USE_BRUTEFORCE": "true"})
        out = []
        for s in (res.get("subdomains") or []):
            if s and s.lower() != domain.lower():
                out.append((s.lower(), "domain", "subdomain"))
        for sub, ip in (res.get("resolved") or {}).items():
            if ip and ip != "unresolved" and is_valid_ip(ip):
                out.append((ip, "ip", "subdomain_resolved"))
        return out

    def _pivot_domain_to_mx(self, domain):
        """domain -> MX host (recon/email_server). MX host becomes a seed."""
        if is_ens_name(domain):
            return []
        res = self._run_module("recon/email_server", domain)
        out = []
        for mx in (res.get("mx_records") or []):
            host = (mx.get("host") or "").strip().lower().rstrip(".")
            if host and is_valid_domain(host) and host != domain.lower():
                out.append((host, "domain", "mx_record"))
        return out

    def _pivot_domain_whois(self, domain):
        """domain -> WHOIS registrant emails."""
        if is_ens_name(domain):
            return []
        res = self._run_module("recon/whois_lookup", domain)
        out = []
        emails = res.get("emails") or []
        if isinstance(emails, str):
            emails = [emails]
        for e in emails:
            e = (str(e) or "").strip().lower()
            if "@" in e:
                out.append((e, "email", "whois"))
        return out

    # ---------------------------------------------------------------- ip
    def _pivot_ip_reverse(self, ip):
        """ip -> PTR hostnames (new domain seeds)."""
        res = self._run_module("recon/reverse_dns", ip)
        out = []
        for _ip, hosts in (res.get("records") or {}).items():
            for h in (hosts or []):
                h = (h or "").strip().rstrip(".").lower()
                if h and is_valid_domain(h):
                    out.append((h, "domain", "reverse_dns"))
        return out

    def _pivot_ip_asn(self, ip):
        """ip -> hosting ASN; abuse / contact emails become email seeds."""
        res = self._run_module("recon/asn_lookup", ip)
        out = []
        for e in (res.get("abuse_contacts") or []):
            if "@" in str(e):
                out.append((str(e).lower(), "email", "asn_abuse"))
        for e in (res.get("email_contacts") or []):
            if "@" in str(e):
                out.append((str(e).lower(), "email", "asn_contact"))
        return out

    def _pivot_ip_reputation(self, ip):
        """ip -> reputation (DNSBL / ip-api / Shodan InternetDB).

        Enrichment only - the verdict ends up in module_results, no new
        seeds."""
        self._run_module("recon/ip_reputation", ip)
        return []

    def _pivot_ip_reverse_ip(self, ip):
        """ip -> related domains hosted on the same IP (HackerTarget)."""
        res = self._run_module("recon/reverse_ip", ip)
        out = []
        for d in (res.get("domains") or []):
            if d and is_valid_domain(d):
                out.append((d.lower(), "domain", "reverse_ip"))
        return out

    # ========================================================== dispatch

    def _build_dispatch(self):
        return {
            "email": [
                self._pivot_email_to_username,
                self._pivot_email_to_domain,
                self._pivot_email_breach,
            ],
            "username": [
                self._pivot_username_to_email,
                self._pivot_username_to_telegram,
                self._pivot_username_to_telegram_variations,  # intrusive
                self._pivot_username_to_discord,
                self._pivot_username_to_github,
            ],
            "phone": [
                self._pivot_phone_to_osint,
                self._pivot_phone_to_telegram,
            ],
            "wallet": [
                self._pivot_wallet_identity,
                self._pivot_wallet_counterparties,  # opt-in FOLLOW_COUNTERPARTIES
            ],
            "domain": [
                self._pivot_domain_ens,
                self._pivot_domain_to_emails,
                self._pivot_domain_to_subdomains,  # intrusive
                self._pivot_domain_to_mx,
                self._pivot_domain_whois,
            ],
            "ip": [
                self._pivot_ip_reverse,
                self._pivot_ip_asn,
                self._pivot_ip_reputation,
                self._pivot_ip_reverse_ip,
            ],
        }

    # ============================================================== run

    def run(self):
        if not self.validate():
            return False

        raw_seed = self.get_option("TARGET").strip()
        try:
            max_depth = max(0, int(self.get_option("MAX_DEPTH") or 2))
        except (TypeError, ValueError):
            max_depth = 2
        try:
            max_per_type = max(1, int(self.get_option("MAX_PER_TYPE") or 5))
        except (TypeError, ValueError):
            max_per_type = 5
        include_intrusive = (
            (self.get_option("INCLUDE_INTRUSIVE") or "false").strip().lower()
            == "true")
        try:
            min_score = max(0, int(self.get_option("MIN_SCORE") or 0))
        except (TypeError, ValueError):
            min_score = 0

        # Resolve seed type: option override, else autodetect.
        forced = (self.get_option("TARGET_TYPE") or "").strip().lower()
        seed_type = forced if forced in _VALID_TYPES else _detect_type(raw_seed)
        seed = _canon(raw_seed, seed_type)

        print(f"\n{Colors.BOLD}{Colors.CYAN}")
        print("=" * 62)
        print(f"  IDENTITY PIVOT (deep multi-type)")
        print(f"  Seed:        {seed}  ({seed_type})")
        print(f"  Depth<=      {max_depth}")
        print(f"  Per type<=   {max_per_type}")
        print(f"  Intrusive:   {include_intrusive}")
        print("=" * 62)
        print(f"{Colors.RESET}")

        start_ts = time.time()
        self._module_results = {}
        self._follow_counterparties = (
            (self.get_option("FOLLOW_COUNTERPARTIES") or "false").strip().lower()
            == "true")
        dispatch = self._build_dispatch()

        # Graph state
        nodes = {
            seed: {"type": seed_type, "depth": 0, "discovered_via": "seed"},
        }
        edges = []
        seen_edges = set()
        seen_queue = {seed}
        queue = [(seed, seed_type, 0)]
        per_type_hop = {}       # (type, hop_depth) -> count queued this hop
        depth_reached = 0

        while queue:
            entity, etype, depth = queue.pop(0)
            pivots = dispatch.get(etype) or []
            if not pivots:
                continue

            print(f"\n{Colors.BOLD}{Colors.YELLOW}{'-'*58}")
            print(f"  [depth {depth}] pivoting {entity}  ({etype})")
            print(f"{'-'*58}{Colors.RESET}")

            for pivot in pivots:
                is_intrusive = getattr(pivot, "intrusive", False)
                if is_intrusive and not include_intrusive:
                    continue
                pname = pivot.__name__.replace("_pivot_", "")
                try:
                    discovered = pivot(entity) or []
                except Exception as e:
                    print_status(f"{pname} failed: {e}", "warning")
                    continue

                # Record edges + new nodes, group output for a clean live print.
                grouped = {}
                for value, vtype, via in discovered:
                    if not value or vtype not in _VALID_TYPES:
                        continue
                    canon = _canon(value, vtype)
                    if canon == entity:
                        continue

                    edge_key = (entity, canon, via)
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append({"from": entity, "to": canon, "via": via})

                    if canon not in nodes:
                        nodes[canon] = {
                            "type": vtype,
                            "depth": depth + 1,
                            "discovered_via": via,
                        }
                        grouped.setdefault((vtype, via), []).append(canon)

                    # Queue for further traversal if within depth + per-type cap.
                    if (canon not in seen_queue
                            and depth < max_depth
                            and vtype in dispatch):
                        hop_key = (vtype, depth + 1)
                        per_type_hop[hop_key] = per_type_hop.get(hop_key, 0) + 1
                        if per_type_hop[hop_key] <= max_per_type:
                            seen_queue.add(canon)
                            queue.append((canon, vtype, depth + 1))

                # Live graph growth: `[depth 1] email -> username: a, b (via X)`
                for (vtype, via), values in grouped.items():
                    uniq = sorted(set(values))
                    sample = ", ".join(uniq[:5])
                    if len(uniq) > 5:
                        sample += f" (+{len(uniq) - 5} more)"
                    print_status(
                        f"[depth {depth + 1}] {etype} -> {vtype}: "
                        f"{sample} (via {via})",
                        "success")

        depth_reached = max((meta["depth"] for meta in nodes.values()),
                            default=0)
        duration = round(time.time() - start_ts, 2)

        # -------- Relevance scoring: closer to seed + more corroboration --
        incoming, mods_for = {}, {}
        for e in edges:
            incoming.setdefault(e["to"], set()).add(e["from"])
            mods_for.setdefault(e["to"], set()).add(e["via"])
        for node, meta in nodes.items():
            if node == seed:
                meta["score"] = 100
                continue
            d = meta.get("depth", 1)
            score = max(5, 100 - d * 35)
            score += 8 * len(incoming.get(node, ()))
            score += 8 * len(mods_for.get(node, ()))
            meta["score"] = min(score, 100)

        # -------- Serialise nodes (filtered by MIN_SCORE) ----------------
        nodes_out = []
        for v, meta in nodes.items():
            if v != seed and meta.get("score", 0) < min_score:
                continue
            nodes_out.append({
                "value": v,
                "type": meta.get("type"),
                "discovered_via": meta.get("discovered_via", "seed"),
                "depth": meta.get("depth", 0),
                "score": meta.get("score", 0),
            })

        per_type_counts = {}
        for n in nodes_out:
            if n["value"] == seed:
                continue
            per_type_counts[n["type"]] = per_type_counts.get(n["type"], 0) + 1

        report_data = {
            "seed": {"value": seed, "type": seed_type},
            "nodes": nodes_out,
            "edges": edges,
            "per_type_counts": per_type_counts,
            "depth_reached": depth_reached,
            "duration_seconds": duration,
            "module_results": self._module_results,
            "options": {
                "max_depth": max_depth,
                "max_per_type": max_per_type,
                "include_intrusive": include_intrusive,
                "min_score": min_score,
            },
        }

        # -------- MD/JSON report via Reporter ----------------------------
        md_path = json_path = None
        reporter = Reporter()
        try:
            md_path, json_path = reporter.generate_full_report(
                seed, self._module_results)
            report_data["report_md"] = md_path
            report_data["report_json"] = json_path
        except Exception as e:
            print_status(f"Report generation failed: {e}", "warning")

        # -------- Optional interactive relationship graph ---------------
        graph_path = None
        if (self.get_option("GRAPH") or "true").strip().lower() == "true":
            try:
                gnodes = [{
                    "id": n["value"],
                    "label": n["value"],
                    "group": "seed" if n["value"] == seed else n["type"],
                    "value": max(1, n["score"] // 8),
                    "title": (f"{n['type']} | depth {n['depth']} | "
                              f"via {n['discovered_via']} | "
                              f"relevance {n['score']}"),
                } for n in nodes_out]
                gedges = [{"from": e["from"], "to": e["to"], "label": e["via"]}
                          for e in edges]
                sections = []
                for etype in _VALID_TYPES:
                    items = [n for n in nodes_out
                             if n["type"] == etype and n["value"] != seed]
                    if not items:
                        continue
                    items.sort(key=lambda x: -x["score"])
                    rows = "".join(
                        f"<tr><td>{reporter._esc(x['value'])}</td>"
                        f"<td>{x['score']}</td>"
                        f"<td>{x['depth']}</td>"
                        f"<td>{reporter._esc(x['discovered_via'])}</td></tr>"
                        for x in items)
                    sections.append((
                        f"{etype} ({len(items)})",
                        "<table><tr><th>Value</th><th>Relevance</th>"
                        "<th>Depth</th><th>Discovered via</th></tr>"
                        f"{rows}</table>",
                    ))
                graph_path = reporter.generate_graph_html(
                    seed, gnodes, gedges, sections)
                report_data["report_graph"] = graph_path
            except Exception as e:
                print_status(f"Graph HTML failed: {e}", "warning")

        # -------- Final summary -----------------------------------------
        print(f"\n{Colors.BOLD}{Colors.GREEN}")
        print("=" * 62)
        print(f"  IDENTITY PIVOT COMPLETE  ({duration}s)")
        print(f"  Seed: {seed}  ({seed_type})   depth reached: {depth_reached}")
        print("=" * 62)
        print(f"{Colors.RESET}")

        if per_type_counts:
            parts = [f"{t}:{c}" for t, c in sorted(per_type_counts.items())]
            print(f"  Discovered: {', '.join(parts)}   "
                  f"(edges: {len(edges)})")
        else:
            print(f"  Discovered: nothing beyond the seed")

        for etype in _VALID_TYPES:
            items = [n for n in nodes_out
                     if n["type"] == etype and n["value"] != seed]
            if not items:
                continue
            items.sort(key=lambda x: -x["score"])
            print(f"\n  {Colors.CYAN}{etype} ({len(items)}):{Colors.RESET}")
            for n in items[:12]:
                print(f"    {Colors.GREEN}+{Colors.RESET} "
                      f"[{n['score']:>3}] {n['value']}  "
                      f"{Colors.DIM}(d={n['depth']}, "
                      f"via {n['discovered_via']}){Colors.RESET}")

        print(f"\n  {Colors.BOLD}Reports:{Colors.RESET}")
        if md_path:
            print(f"    {Colors.DIM}{md_path}{Colors.RESET}")
        if graph_path:
            print(f"    {Colors.GREEN}graph:{Colors.RESET} {graph_path}")
        print(f"\n{Colors.GREEN}{'='*62}{Colors.RESET}\n")

        self.results = report_data
        return True
