"""On-chain -> social identity via web3.bio (free, no key).

The strongest OSINT pivot for a wallet is off-chain identity. web3.bio resolves
an ENS name or 0x address into every linked profile across ENS / Basenames /
Lens / Farcaster, with the social handles each one publishes:

  wallet / name  ->  twitter, github, website, Lens, Farcaster, ...

The handles and URLs land in the results so the correlation engine folds them
in with the rest of a full_recon run. All public, read-only.
"""
import re

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin

_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9\-_.]+\.[A-Za-z]{2,}$")


class CryptoIdentity(FetchErrorsMixin, BaseModule):
    name = "harvest/crypto_identity"
    description = ("Resolve a wallet/ENS to linked social identities and handles "
                   "(Twitter/GitHub/website, ENS/Lens/Farcaster) via web3.bio")
    category = "harvest"
    target_type = "wallet/domain/username"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True, "ENS name (vitalik.eth) or 0x address")

    @staticmethod
    def _accepts(target):
        t = (target or "").strip()
        return bool(_ADDR_RE.match(t) or _NAME_RE.match(t))

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Crypto Identity: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        if not self._accepts(target):
            print_status("Enter an ENS name (name.eth) or a 0x address", "error")
            self.results = {"target": target, "valid": False}
            return False

        self._errors = []
        try:
            resp = http.get(f"https://api.web3.bio/profile/{target}", timeout=25)
        except Exception as exc:
            # A network failure is a FETCH FAILURE, never "no linked identities".
            self._note_error(f"web3.bio error: {exc}")
            self.results = {"target": target, "valid": True, "resolved": False}
            return self._fail()

        # 404 is web3.bio's documented "nothing linked to this identity" answer.
        if resp.status_code == 404:
            print_status("No linked identities found", "info")
            self.results = {"target": target, "valid": True, "resolved": False,
                            "identities": []}
            return True
        if resp.status_code != 200:
            # 429/5xx/anything else = the lookup failed; do not report it as an
            # address with no identities.
            self._note_error(f"web3.bio HTTP {resp.status_code}")
            self.results = {"target": target, "valid": True, "resolved": False}
            return self._fail()

        data = resp.json()
        if isinstance(data, dict):           # single-profile or error shape
            data = [data] if data.get("identity") else []
        profiles = [p for p in data if isinstance(p, dict)]

        # Which address OWNS this identity? For a 0x query it is the query
        # itself; for a name it is the address of the profile with that exact
        # name. web3.bio also returns look-alike profiles bound to OTHER
        # addresses (verified live: vitalik.eth -> vb62831.base.eth on a
        # different 0x); merging their handles would be a false link.
        owner = None
        if _ADDR_RE.match(target):
            owner = target.lower()
        else:
            for p in profiles:
                if (p.get("identity") or "").lower() == target.lower() and p.get("address"):
                    owner = p["address"].lower()
                    break
            if owner is None and profiles and profiles[0].get("address"):
                owner = profiles[0]["address"].lower()

        identities, related = [], []
        links = {}
        social_handles = set()
        urls = set()
        descriptions = []

        for prof in profiles:
            addr = (prof.get("address") or "").lower()
            same_owner = bool(owner) and addr == owner
            prof_links = {k: v.get("handle") for k, v in (prof.get("links") or {}).items()
                          if isinstance(v, dict) and v.get("handle")}
            entry = {
                "platform": prof.get("platform"),
                "identity": prof.get("identity"),
                "display_name": prof.get("displayName"),
                "avatar": prof.get("avatar"),
                "follower": (prof.get("social") or {}).get("follower"),
                "address": addr or None,
                "links": prof_links,
            }
            if not same_owner:
                related.append(entry)   # different address: a lead, not the same owner
                continue
            identities.append(entry)
            if prof.get("description"):
                descriptions.append(prof["description"])
            for kind, info in (prof.get("links") or {}).items():
                if not isinstance(info, dict):
                    continue
                handle = info.get("handle")
                if handle:
                    links.setdefault(kind, handle)
                    if kind in ("twitter", "github", "lens", "farcaster",
                                "telegram", "discord", "reddit"):
                        social_handles.add(f"{kind}:{handle}")
                if info.get("link"):
                    urls.add(info["link"])

        self.results = {
            "target": target,
            "valid": True,
            "resolved": bool(identities),
            "owner_address": owner,
            "addresses": [owner] if owner else [],
            "identities": identities,
            "related_identities": related,
            "links": links,
            "social_handles": sorted(social_handles),
            "urls": sorted(urls),
            "descriptions": descriptions,
        }

        if not identities:
            msg = "No identities verified to this address"
            if related:
                msg += (f" ({len(related)} look-alike profile(s) on other "
                        f"addresses kept separate)")
            print_status(msg, "info")
            return True

        print_status(f"{len(identities)} linked identity/identities", "success")
        for ident in identities:
            foll = (f"  ({ident['follower']} followers)"
                    if ident.get("follower") else "")
            print(f"    {Colors.GREEN}{(ident['platform'] or '?'):10}{Colors.RESET} "
                  f"{ident['identity']}{Colors.DIM}{foll}{Colors.RESET}")

        if links:
            print(f"\n  {Colors.BOLD}Social links (verified to {owner}):{Colors.RESET}")
            for kind, handle in links.items():
                print(f"    {Colors.CYAN}{kind:10}{Colors.RESET} {handle}")
        if related:
            print(f"\n  {Colors.DIM}{len(related)} look-alike profile(s) bound to a "
                  f"DIFFERENT address — kept separate, not merged:{Colors.RESET}")
            for r in related[:5]:
                print(f"    {Colors.DIM}{r['platform']:10} {r['identity']} "
                      f"({r['address']}){Colors.RESET}")
        print()
        return True
