"""Crypto address classification shared by the whole tool.

One strict classifier so every consumer (crypto modules, correlate,
identity_pivot, full_recon) agrees on what is and is not a wallet. Base58
excludes 0 O I l and bech32 bodies are lowercase, so malformed strings are
rejected instead of becoming false-positive wallets.
"""
import re

ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
BTC_RE = re.compile(r"^(bc1[ac-hj-np-z02-9]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$")
LTC_RE = re.compile(r"^(ltc1[ac-hj-np-z02-9]{11,71}|[LM][1-9A-HJ-NP-Za-km-z]{25,34})$")
DOGE_RE = re.compile(r"^D[1-9A-HJ-NP-Za-km-z]{33}$")

# ENS names are domain-shaped but are NOT DNS — they resolve on-chain.
ENS_TLDS = (".eth",)


def detect_chain(addr):
    """ethereum / tron / bitcoin / litecoin / dogecoin, or None."""
    a = (addr or "").strip()
    if ETH_RE.match(a):
        return "ethereum"
    if TRON_RE.match(a):
        return "tron"
    if BTC_RE.match(a):
        return "bitcoin"
    if LTC_RE.match(a):
        return "litecoin"
    if DOGE_RE.match(a):
        return "dogecoin"
    return None


def is_wallet(value):
    return detect_chain(value) is not None


def is_ens_name(value):
    v = (value or "").strip().lower()
    return v.endswith(ENS_TLDS) and len(v) > 4 and " " not in v
