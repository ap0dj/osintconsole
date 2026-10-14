import re
import socket
import datetime
import ipaddress


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
   ____       _       _    ____                      _
  / __ \\___  (_)___  | |_ / ___|___  _ __  ___  ___ | | ___
 / / _` / __|| / _ \\ | __| |   / _ \\| '_ \\/ __|/ _ \\| |/ _ \\
| | (_| \\__ \\| | | | | |_| |__| (_) | | | \\__ \\ (_) | |  __/
 \\ \\__,_|___/|_|_| |_|\\__|\\____\\___/|_| |_|___/\\___/|_|\\___|
  \\____/
{Colors.RESET}
{Colors.DIM}  [ OSINT & Reconnaissance Framework ]{Colors.RESET}
{Colors.DIM}  [ v1.0.0 | github.com/x ]{Colors.RESET}
{Colors.GREEN}  [ Modules: recon | web | harvest      ]{Colors.RESET}
"""
    print(banner)


def print_status(msg, status="info"):
    icons = {
        "info": f"{Colors.BLUE}[*]{Colors.RESET}",
        "success": f"{Colors.GREEN}[+]{Colors.RESET}",
        "warning": f"{Colors.YELLOW}[!]{Colors.RESET}",
        "error": f"{Colors.RED}[-]{Colors.RESET}",
        "question": f"{Colors.MAGENTA}[?]{Colors.RESET}",
    }
    icon = icons.get(status, icons["info"])
    print(f" {icon} {msg}")


def is_valid_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def is_valid_ip(ip):
    # inet_aton() accepts shorthand ("1.2"), bare integers ("7701234567") and
    # hex ("0x7f000001"), which made phone numbers and version strings register
    # as IPs. ip_address() requires full notation and also covers IPv6.
    try:
        ipaddress.ip_address(str(ip).strip())
        return True
    except ValueError:
        return False


def is_valid_url(url):
    pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    return bool(re.match(pattern, url, re.IGNORECASE))


def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def normalize_url(target, default_scheme="https"):
    """Ensure a target has a scheme and no trailing slash."""
    target = (target or "").strip()
    if not target.startswith(("http://", "https://")):
        target = f"{default_scheme}://{target}"
    return target.rstrip("/")


def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def print_progress(current, total, prefix="", length=30):
    pct = current / total if total > 0 else 0
    filled = int(length * pct)
    bar = "=" * filled + ">" + " " * (length - filled - 1)
    print(f"\r  {prefix}[{bar}] {pct*100:.0f}% ({current}/{total})", end="", flush=True)
    if current >= total:
        print()


EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
URL_RE = re.compile(r'https?://[^\s"\'<>]+')
USERNAME_RE = re.compile(r'(?<![\w@])@([A-Za-z0-9_]{3,32})(?![\w@])')
PHONE_RE = re.compile(r'\+?\d[\d\s\-()]{8,}\d')
# Base58 excludes 0 O I l; the old [A-HJ-NP-Z0-9] class was uppercase-only and
# included 0, so it matched NO real Base58 address (they are mostly lowercase)
# and NO real bech32 address (those are entirely lowercase). Correct alphabets:
_B58 = r'1-9A-HJ-NP-Za-km-z'
BTC_RE = re.compile(rf'\b(?:[13][{_B58}]{{25,34}}|bc1[ac-hj-np-z02-9]{{11,71}})\b')
ETH_RE = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
LTC_RE = re.compile(rf'\b(?:[LM][{_B58}]{{25,34}}|ltc1[ac-hj-np-z02-9]{{11,71}})\b')
ASN_RE = re.compile(r'\b(?:AS|ASN)\d{1,10}\b', re.I)


def extract_entities(data):
    """Walk any nested dict/list and pull out emails, IPs, domains, URLs,
    usernames, phones, wallets (BTC/ETH/LTC) and ASNs."""
    found = {
        "email": set(), "ip": set(), "domain": set(), "url": set(),
        "username": set(), "wallet": set(), "asn": set(),
    }
    phones = {}  # digits-only -> first-seen formatted form (dedupe by digits)

    def _walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, (list, tuple, set)):
            for v in obj:
                _walk(v)
        elif isinstance(obj, str):
            for m in EMAIL_RE.findall(obj):
                found["email"].add(m.lower())
            for m in IPV4_RE.findall(obj):
                found["ip"].add(m)
            for m in URL_RE.findall(obj):
                found["url"].add(m.rstrip(".,);"))
            for m in DOMAIN_RE.findall(obj):
                if not IPV4_RE.fullmatch(m):
                    found["domain"].add(m.lower())
            for m in USERNAME_RE.findall(obj):
                found["username"].add(m.lower())
            for m in PHONE_RE.findall(obj):
                digits = re.sub(r"\D", "", m)
                if 10 <= len(digits) <= 15 and digits not in phones:
                    phones[digits] = m.strip()
            for m in BTC_RE.findall(obj):
                found["wallet"].add(m)
            for m in ETH_RE.findall(obj):
                found["wallet"].add(m)
            for m in LTC_RE.findall(obj):
                found["wallet"].add(m)
            for m in ASN_RE.findall(obj):
                found["asn"].add(m.upper())

    _walk(data)
    emails = found["email"]
    for e in emails:
        domain = e.split("@")[-1]
        found["domain"].discard(domain)
    result = {k: sorted(v) for k, v in found.items()}
    result["phone"] = sorted(phones.values())
    return _drop_noise(result)


def _drop_noise(result):
    """Filter the regex hits through the correlation engine's classifier.

    These regexes run findall() over raw strings, so a scraped page yields every
    CDN host, analytics domain and template address it mentions. Imported lazily
    because core.correlate imports this module.
    """
    try:
        from core.correlate import classify, NOISE_HANDLES
    except ImportError:
        return result

    cleaned = {}
    for kind, values in result.items():
        if kind == "username":
            # classify() never returns "username" -- a bare handle matches too
            # much to identify by shape -- so only the obvious filler is dropped.
            cleaned[kind] = [v for v in values if v.lower() not in NOISE_HANDLES]
        elif kind == "phone":
            cleaned[kind] = [v for v in values if _looks_like_phone(v)]
        elif kind in ("email", "domain", "url", "ip"):
            cleaned[kind] = [v for v in values if classify(v) == kind]
        else:
            cleaned[kind] = values
    return cleaned


def _looks_like_phone(value):
    """Require international (+) or trunk (0) notation.

    A bare run of digits is a build number, id or timestamp far more often than
    a phone number. Local Iraqi numbers are written 07xx..., so the leading zero
    is kept as valid -- correlate.classify is stricter and wants the + only.
    """
    text = value.strip()
    return text.startswith("+") or re.sub(r"\D", "", text).startswith("0")


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _vis_len(text):
    """Printable width — ANSI colour codes occupy no columns."""
    return len(_ANSI_RE.sub("", str(text)))


def _pad(text, width):
    """Left-justify to `width` visible columns, ignoring ANSI codes so a
    coloured cell lines up with a plain one."""
    text = str(text)
    return text + " " * max(0, width - _vis_len(text))


def format_table(headers, rows, padding=2):
    if not rows:
        return ""
    col_widths = [_vis_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], _vis_len(cell))
    sep = "+" + "+".join("-" * (w + padding) for w in col_widths) + "+"
    header_line = "|" + "|".join(f" {_pad(h, col_widths[i])} " for i, h in enumerate(headers)) + "|"
    lines = [sep, header_line, sep]
    for row in rows:
        line = "|" + "|".join(
            f" {_pad(row[i] if i < len(row) else '', col_widths[i])} "
            for i in range(len(headers))) + "|"
        lines.append(line)
    lines.append(sep)
    return "\n".join(lines)
