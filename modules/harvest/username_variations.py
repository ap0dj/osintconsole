"""Smart username variation generator and bio handle extractor for OSINT pivoting.

Importable utility. No CLI, no BaseModule - just pure functions returning lists/dicts.
"""
import re

_PLATFORMS = {
    "telegram":  {"charset": re.compile(r"^[A-Za-z0-9_]+$"), "min": 5, "max": 32, "lower": False},
    "discord":   {"charset": re.compile(r"^[a-z0-9_.]+$"),   "min": 2, "max": 32, "lower": True},
    "instagram": {"charset": re.compile(r"^[A-Za-z0-9._]+$"),"min": 1, "max": 30, "lower": False},
    "github":    {"charset": re.compile(r"^[A-Za-z0-9-]+$"), "min": 1, "max": 39, "lower": False},
}

# 1 <-> i <-> l is a three-way confusable, so values are lists
_LOOKALIKES = {
    "0": ["o"], "o": ["0"],
    "1": ["i", "l"], "i": ["1", "l"], "l": ["1", "i"],
    "3": ["e"], "e": ["3"],
    "5": ["s"], "s": ["5"],
    "8": ["b"], "b": ["8"],
    "a": ["@"], "@": ["a"],
}

_YEAR_SUFFIXES = (2024, 2025, 2026, 2027, 2028, 2029, 2030)
_NUM_SUFFIXES = ("1", "2", "3", "7", "11", "22", "69", "77", "99", "007", "123", "321", "420", "1337")
_WORD_SUFFIXES = ("official", "real", "mr", "the", "iq", "the_real")

# Iraqi/Arabic transliteration families - users shuffle these constantly
_AR_TRANSLIT = {
    "mohammed": ("mohamed", "mohammad", "muhammad", "mhmd"),
    "ali":      ("aly",),
    "hussein":  ("hussain", "husein", "hossein"),
    "ahmed":    ("ahmad", "ahmd"),
    "omar":     ("umar", "omer"),
    "youssef":  ("yousef", "yusuf", "yousif"),
    "mustafa":  ("mostafa", "mostapha"),
    "ibrahim":  ("ebrahim", "ibraheem"),
    "laith":    ("laeth",),
    "zayd":     ("zaid", "zayed"),
    "haider":   ("haydar", "hayder"),
    "hassan":   ("hasan",),
    "khaled":   ("khalid",),
}

_YEAR_RE = re.compile(r"^(?P<base>.+?)(?P<year>\d{2,4})$")


def detect_birth_year(username: str) -> dict | None:
    if not username:
        return None
    m = _YEAR_RE.match(username)
    if not m:
        return None
    base = m.group("base").rstrip("_.-")
    digits = m.group("year")
    if not base:
        return None
    if len(digits) == 4:
        year = int(digits)
        if 1950 <= year <= 2015:
            return {"year": year, "confidence": 0.9, "base": base}
    elif len(digits) == 2:
        n = int(digits)
        if 50 <= n <= 99:
            return {"year": 1900 + n, "confidence": 0.75, "base": base}
        if 0 <= n <= 15:
            return {"year": 2000 + n, "confidence": 0.7, "base": base}
    return None


def swap_separators(username: str) -> list[str]:
    tokens = [t for t in re.split(r"[._-]", username) if t]
    out: set[str] = set()
    if len(tokens) == 1:
        s = tokens[0]
        out.add(s)
        # Split at letter<->digit boundary so "ali2009" seeds "ali_2009" etc.
        m = re.match(r"^([A-Za-z]+)(\d+)$", s)
        if m:
            name, nums = m.groups()
            for sep in (".", "_", "-"):
                out.add(f"{name}{sep}{nums}")
    else:
        for sep in ("", ".", "_", "-"):
            out.add(sep.join(tokens))
    return [v for v in out if v]


def numeric_variations(base: str, year_hint: int | None = None) -> list[str]:
    base = base.rstrip("_.-")
    if not base:
        return []
    out: list[str] = []
    seen: set[str] = set()
    def add(v: str) -> None:
        if v and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
    for suf in _NUM_SUFFIXES:
        add(base + suf)
        add(f"{base}_{suf}")
    for yr in _YEAR_SUFFIXES:
        add(f"{base}{yr}")
        add(f"{base}_{yr}")
        add(f"{base}{yr % 100:02d}")
    if year_hint is not None:
        short = year_hint % 100
        add(f"{base}{year_hint}")
        add(f"{base}_{year_hint}")
        add(f"{base}.{year_hint}")
        add(f"{base}{short:02d}")
        add(f"{base}_{short:02d}")
        add(f"{year_hint}{base}")
        add(f"{short:02d}{base}")
        for d in (-1, 1):
            add(f"{base}{year_hint + d}")
    return out


def character_tweaks(username: str) -> list[str]:
    s = username.lower()
    out: list[str] = []
    seen = {s}
    positions = [(i, _LOOKALIKES[ch]) for i, ch in enumerate(s) if ch in _LOOKALIKES]
    for i, repls in positions:
        for new in repls:
            v = s[:i] + new + s[i + 1:]
            if v not in seen:
                seen.add(v)
                out.append(v)
            if len(out) >= 20:
                return out
    for a in range(len(positions)):
        for b in range(a + 1, len(positions)):
            i1, r1 = positions[a]
            i2, r2 = positions[b]
            for n1 in r1:
                for n2 in r2:
                    chars = list(s)
                    chars[i1], chars[i2] = n1, n2
                    v = "".join(chars)
                    if v not in seen:
                        seen.add(v)
                        out.append(v)
                    if len(out) >= 20:
                        return out
    return out


def truncation_variants(username: str, min_len: int = 3) -> list[str]:
    out: list[str] = []
    seen = {username.lower()}
    def add(v: str) -> None:
        if len(v) >= min_len and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
    stripped = re.sub(r"\d+$", "", username)
    if stripped != username:
        add(stripped.rstrip("_.-"))
    for i in range(len(username) - 1, min_len - 1, -1):
        add(username[:i])
    if len(username) > min_len:
        kept = [username[0]] + [c for c in username[1:] if c.lower() not in "aeiou"]
        add("".join(kept))
    return out


def _arabic_variants(base: str) -> list[str]:
    out: list[str] = []
    for canon, alts in _AR_TRANSLIT.items():
        if base.startswith(canon):
            rest = base[len(canon):]
            out.extend(alt + rest for alt in alts)
        for alt in alts:
            if base.startswith(alt):
                rest = base[len(alt):]
                out.append(canon + rest)
                out.extend(a + rest for a in alts if a != alt)
    return out


def _dedupe_ci(items):
    seen: set[str] = set()
    out: list[str] = []
    for v in items:
        k = v.lower()
        if k and k not in seen:
            seen.add(k)
            out.append(v)
    return out


def generate_variations(username: str, max_variations: int = 100) -> list[str]:
    if not isinstance(username, str):
        return []
    u = username.strip()
    if not u:
        return []
    low = u.lower()
    year_info = detect_birth_year(low)
    base = year_info["base"] if year_info else (re.sub(r"\d+$", "", low).rstrip("_.-") or low)
    year = year_info["year"] if year_info else None

    tiers: list[list[str]] = [
        [u, low, *swap_separators(low), *swap_separators(base)],
        [*numeric_variations(base, year),
         *(f"{base}{s}" for s in _WORD_SUFFIXES),
         *(f"{base}_{s}" for s in _WORD_SUFFIXES)],
        [*truncation_variants(low), *truncation_variants(base)],
        _arabic_variants(base),
        character_tweaks(low),
    ]
    flat: list[str] = []
    for t in tiers:
        flat.extend(t)
    deduped = _dedupe_ci(flat)
    deduped = [v for v in deduped if 1 <= len(v) <= 30]
    return deduped[:max_variations]


def platform_filter(variations: list[str], platform: str) -> list[str]:
    rule = _PLATFORMS.get(platform.lower())
    if not rule:
        return list(variations)
    out: list[str] = []
    seen: set[str] = set()
    for v in variations:
        c = v.lower() if rule["lower"] else v
        if not (rule["min"] <= len(c) <= rule["max"]):
            continue
        if not rule["charset"].match(c):
            continue
        if platform == "github" and ("--" in c or c.startswith("-") or c.endswith("-")):
            continue
        if platform == "discord" and ".." in c:
            continue
        if platform == "telegram" and not c[0].isalpha():
            continue
        k = c.lower()
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


# Negative lookbehind keeps us off email local parts (user@domain)
_HANDLE_RE  = re.compile(r"(?<![A-Za-z0-9_])@([A-Za-z0-9._]{2,30})")
_HASHTAG_RE = re.compile(r"(?<!\w)#([A-Za-z0-9_]{1,50})")
_EMAIL_RE   = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_URL_RES = {
    "telegram":  re.compile(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_]{5,32})", re.I),
    "discord":   re.compile(r"discord(?:\.gg|\.com/invite|\.com/users)/([A-Za-z0-9_.-]+)", re.I),
    "github":    re.compile(r"github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})(?![A-Za-z0-9-])", re.I),
    "instagram": re.compile(r"instagram\.com/([A-Za-z0-9._]{1,30})", re.I),
    "twitter":   re.compile(r"(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,15})", re.I),
    "tiktok":    re.compile(r"tiktok\.com/@([A-Za-z0-9._]{2,24})", re.I),
    "youtube":   re.compile(r"youtube\.com/(?:@|c/|channel/|user/)([A-Za-z0-9._-]{1,50})", re.I),
}
_BUCKETS = ("telegram", "discord", "github", "instagram", "twitter", "tiktok", "youtube", "emails", "hashtags")


def extract_handles_from_bio(text: str) -> dict:
    result = {k: [] for k in _BUCKETS}
    if not text:
        return result
    seen = {k: set() for k in _BUCKETS}
    def push(bucket: str, val: str) -> None:
        if not val:
            return
        key = val.lower()
        if key not in seen[bucket]:
            seen[bucket].add(key)
            result[bucket].append(val)
    for platform, rx in _URL_RES.items():
        for m in rx.finditer(text):
            push(platform, m.group(1))
    # Bare @mentions are ambiguous - seed both twitter and instagram so pivoting hits both
    for m in _HANDLE_RE.finditer(text):
        h = m.group(1).rstrip(".")
        if len(h) >= 2:
            push("twitter", h)
            push("instagram", h)
    for m in _HASHTAG_RE.finditer(text):
        push("hashtags", m.group(1))
    for m in _EMAIL_RE.finditer(text):
        push("emails", m.group(0))
    return result


if __name__ == "__main__":
    import json

    print("=== generate_variations('ali2009') ===")
    vs = generate_variations("ali2009", max_variations=30)
    for v in vs:
        print(" ", v)

    print("\n=== detect_birth_year samples ===")
    for u in ("ali2009", "laith98", "mustafa2003", "foobar", "x1999", "noob42"):
        print(f"  {u!r:20} -> {detect_birth_year(u)}")

    print("\n=== platform_filter(ali2009 variants, 'telegram') ===")
    for v in platform_filter(generate_variations("ali2009", 60), "telegram")[:12]:
        print(" ", v)

    print("\n=== extract_handles_from_bio(demo) ===")
    bio = "hi im @cooluser check my gh github.com/foo and t.me/foo_bot discord.gg/abc123"
    print(json.dumps(extract_handles_from_bio(bio), indent=2, ensure_ascii=False))
