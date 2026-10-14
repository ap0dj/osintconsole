#!/usr/bin/env python3
"""OsintConsole — interactive setup / bootstrap script.

Single entry point that prepares a fresh (or existing) checkout for use:

    python setup.py           # full interactive run (prompts for API keys)
    python setup.py --yes     # non-interactive, skips the key wizard
    python setup.py --check   # read-only status report, installs nothing
    python setup.py --keys-only  # just the API key wizard
    python setup.py -v        # verbose: show pip + subprocess output

Phases run in order (any phase is safe to re-run; nothing is clobbered):
    1. Environment check          (Python >= 3.10, pip, project root)
    2. Core dependencies          (pip install -r requirements.txt)
    3. Optional enhancements      (per-package: PySocks, selenium, mmh3, ...)
    4. External tool detection    (nmap / git / chrome in PATH)
    5. Config initialization      (merge new defaults into config.json)
    6. API keys wizard            (interactive, skippable)
    7. Database initialization    (create osint.db schema)
    8. Smoke tests                (import modules, one safe HTTP GET)
    9. Final summary

Only stdlib is imported at the top. Anything from the project (core.*) is
imported lazily, after phase 2 has installed its dependencies.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from typing import Any, Callable

# --------------------------------------------------------------------------- #
#  Colors + tiny helpers                                                      #
# --------------------------------------------------------------------------- #
G = "\033[92m"   # green
R = "\033[91m"   # red
Y = "\033[93m"   # yellow
B = "\033[94m"   # blue
C = "\033[96m"   # cyan
D = "\033[2m"    # dim
BOLD = "\033[1m"
X = "\033[0m"    # reset

OK = f"{G}[OK]{X}"
BAD = f"{R}[X] {X}"
WARN = f"{Y}[!] {X}"
INFO = f"{B}[*] {X}"

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")

VERBOSE = False
CHECK_ONLY = False

OPTIONAL_PACKAGES = [
    # (pip-name, import-name, feature-impact)
    ("PySocks",       "socks",         "Tor / SOCKS5 proxy support"),
    ("selenium",      "selenium",      "High-quality web screenshots"),
    ("mmh3",          "mmh3",          "Correct Shodan favicon hashes"),
    ("cryptography",  "cryptography",  "Full SSL cert parsing (self-signed)"),
    ("Pillow",        "PIL",           "EXIF extraction from images"),
    ("pyreadline3",   "pyreadline3",   "Tab completion + history on Windows"),
]

# Order matches "OSINT value" from the task spec.
API_KEY_WIZARD = [
    ("github",             "GitHub Personal Access Token",
     "github/* modules, commit mining, repo analysis",
     "https://github.com/settings/tokens  (classic PAT, no scopes needed)"),
    ("shodan",             "Shodan API Key",
     "recon/shodan_search — host/service lookups",
     "https://account.shodan.io/"),
    ("discord_bot",        "Discord Bot Token",
     "harvest/discord_osint — guild + user intel via bot API",
     "https://discord.com/developers/applications"),
    ("telegram_bot",       "Telegram Bot Token",
     "harvest/telegram_osint — channel/user resolution",
     "https://t.me/BotFather"),
    ("virustotal",         "VirusTotal API Key",
     "domain / URL / file reputation lookups",
     "https://virustotal.com/gui/my-apikey"),
    ("hunter",             "Hunter.io API Key",
     "harvest/domain_emails — company email discovery",
     "https://hunter.io"),
    ("securitytrails",     "SecurityTrails API Key",
     "recon/dns_history — passive DNS history",
     "https://securitytrails.com"),
    ("abuseipdb",          "AbuseIPDB API Key",
     "recon/ip_reputation — abuse reports",
     "https://abuseipdb.com"),
    ("numverify",          "numverify API Key",
     "harvest/phone_osint — carrier / line type",
     "https://numverify.com"),
    ("abstractapi_phone",  "AbstractAPI Phone Key",
     "harvest/phone_osint — richer phone metadata",
     "https://abstractapi.com"),
    ("ipqualityscore",     "IPQualityScore API Key",
     "recon/ip_reputation, phone fraud scoring",
     "https://ipqualityscore.com"),
    ("nvd",                "NVD API Key",
     "recon/cve_lookup — higher rate limit",
     "https://nvd.nist.gov"),
]


def step(msg: str, status: str = "info") -> None:
    """Print a single-line status entry."""
    prefix = {"ok": OK, "bad": BAD, "warn": WARN, "info": INFO, "run": f"{C}[>]{X}"}.get(status, INFO)
    print(f"  {prefix} {msg}")


def header(title: str) -> None:
    bar = "-" * 60
    print(f"\n{BOLD}{C}{bar}{X}")
    print(f"{BOLD}{C}  {title}{X}")
    print(f"{BOLD}{C}{bar}{X}")


def run_cmd(cmd: list[str], capture: bool = True) -> tuple[int, str, str]:
    """Run a subprocess; return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=capture, text=True,
            encoding="utf-8", errors="replace",
        )
        return proc.returncode, (proc.stdout or ""), (proc.stderr or "")
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)


# --------------------------------------------------------------------------- #
#  Phase 1 — environment                                                      #
# --------------------------------------------------------------------------- #
def phase_env() -> dict[str, Any]:
    header("Phase 1 / 9  —  Environment")

    pyver = sys.version_info
    ok_py = pyver >= (3, 10)
    step(f"Python {pyver.major}.{pyver.minor}.{pyver.micro}  "
         f"({'ok' if ok_py else '>= 3.10 required'})",
         "ok" if ok_py else "bad")
    if not ok_py:
        return {"ok": False, "details": f"Python {pyver.major}.{pyver.minor} too old"}

    step(f"Platform: {platform.system()} {platform.release()} ({platform.machine()})", "info")

    rc, out, _ = run_cmd([sys.executable, "-m", "pip", "--version"])
    if rc == 0:
        step(f"pip: {out.strip().splitlines()[0] if out else 'available'}", "ok")
    else:
        step("pip is not available — rerun with a Python that has pip", "bad")
        return {"ok": False, "details": "pip missing"}

    marker = os.path.join(PROJECT_ROOT, "core", "console.py")
    if not os.path.isfile(marker):
        step(f"Not in a project root (missing {marker})", "bad")
        return {"ok": False, "details": "wrong directory"}
    step(f"Project root: {PROJECT_ROOT}", "ok")

    return {"ok": True, "details": f"{platform.system()}, Python {pyver.major}.{pyver.minor}"}


# --------------------------------------------------------------------------- #
#  Phase 2 — core deps                                                        #
# --------------------------------------------------------------------------- #
CORE_IMPORTS = [("dns", "dnspython"), ("whois", "python-whois"),
                ("requests", "requests"), ("bs4", "beautifulsoup4"),
                ("urllib3", "urllib3")]


def _try_import(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


def phase_core() -> dict[str, Any]:
    header("Phase 2 / 9  —  Core dependencies")

    req = os.path.join(PROJECT_ROOT, "requirements.txt")
    if not os.path.isfile(req):
        step("requirements.txt is missing — nothing to install", "warn")
    elif CHECK_ONLY:
        step(f"--check: skipping `pip install -r requirements.txt`", "info")
    else:
        step("Running pip install -r requirements.txt (this may take a minute)", "run")
        rc, out, err = run_cmd(
            [sys.executable, "-m", "pip", "install", "-r", req, "--disable-pip-version-check"]
        )
        if VERBOSE:
            if out: print(D + out.strip() + X)
            if err: print(D + err.strip() + X)
        already = sum(1 for ln in out.splitlines() if "already satisfied" in ln.lower())
        installed = sum(1 for ln in out.splitlines()
                        if ln.lstrip().lower().startswith("successfully installed"))
        if rc == 0:
            step(f"pip install OK  ({already} already satisfied, {installed} install batch)", "ok")
        else:
            step("pip install exited non-zero; continuing but core imports may fail", "warn")
            if not VERBOSE and err:
                print(D + err.strip().splitlines()[-1][:200] + X)

    ok_count = 0
    for mod, pip_name in CORE_IMPORTS:
        if _try_import(mod):
            step(f"import {mod}  (from {pip_name})", "ok")
            ok_count += 1
        else:
            step(f"import {mod}  FAILED  (pip install {pip_name})", "bad")

    all_ok = ok_count == len(CORE_IMPORTS)
    return {
        "ok": all_ok,
        "details": f"{ok_count}/{len(CORE_IMPORTS)} core imports",
        "ok_count": ok_count,
        "total": len(CORE_IMPORTS),
    }


# --------------------------------------------------------------------------- #
#  Phase 3 — optional deps                                                    #
# --------------------------------------------------------------------------- #
def phase_optional() -> dict[str, Any]:
    header("Phase 3 / 9  —  Optional enhancements")

    is_win = sys.platform == "win32"
    results: list[tuple[str, bool, str]] = []

    for pip_name, import_name, impact in OPTIONAL_PACKAGES:
        if pip_name == "pyreadline3" and not is_win:
            step(f"{pip_name:14} skipped (not Windows)", "info")
            results.append((pip_name, True, "n/a"))
            continue

        if _try_import(import_name):
            step(f"{pip_name:14} already present  —  {impact}", "ok")
            results.append((pip_name, True, "present"))
            continue

        if CHECK_ONLY:
            step(f"{pip_name:14} not installed     —  {impact}  (--check: skipping)", "warn")
            results.append((pip_name, False, "missing"))
            continue

        step(f"{pip_name:14} installing...", "run")
        rc, out, err = run_cmd(
            [sys.executable, "-m", "pip", "install", pip_name, "--disable-pip-version-check"]
        )
        if VERBOSE and (out or err):
            print(D + (out + err).strip() + X)
        if rc == 0 and _try_import(import_name):
            step(f"{pip_name:14} installed         —  {impact}", "ok")
            results.append((pip_name, True, "installed"))
        else:
            step(f"{pip_name:14} install failed    —  degrades: {impact}", "warn")
            results.append((pip_name, False, "failed"))

    ok_count = sum(1 for _, ok, _ in results if ok)
    return {
        "ok": True,  # optional means never fatal
        "details": f"{ok_count}/{len(results)} optional ok",
        "ok_count": ok_count,
        "total": len(results),
        "results": results,
    }


# --------------------------------------------------------------------------- #
#  Phase 4 — external tools                                                   #
# --------------------------------------------------------------------------- #
def phase_tools() -> dict[str, Any]:
    header("Phase 4 / 9  —  External tools (detection only)")

    tools = [
        ("nmap",   ["nmap"],
         "optional: recon/port_scan uses it for extended scanning"),
        ("git",    ["git"],
         "optional: cloning repos for github/* source inspection"),
        ("chrome", ["chrome", "chromium", "google-chrome", "chrome.exe", "chromium.exe"],
         "optional: selenium backend for web/screenshot"),
    ]
    found = 0
    results = []
    for label, candidates, impact in tools:
        path = None
        for cand in candidates:
            path = shutil.which(cand)
            if path:
                break
        if path:
            step(f"{label:7} found at {path}", "ok")
            found += 1
            results.append((label, True))
        else:
            step(f"{label:7} not in PATH  —  {impact}", "warn")
            results.append((label, False))

    return {
        "ok": True,
        "details": f"{found}/{len(tools)} tools found",
        "ok_count": found,
        "total": len(tools),
        "results": results,
    }


# --------------------------------------------------------------------------- #
#  Phase 5 — config                                                           #
# --------------------------------------------------------------------------- #
def phase_config() -> dict[str, Any]:
    header("Phase 5 / 9  —  Configuration")

    sys.path.insert(0, PROJECT_ROOT)
    try:
        from core.config import DEFAULT_CONFIG, _deep_merge
    except Exception as e:
        step(f"Cannot import core.config: {e}", "bad")
        return {"ok": False, "details": str(e)}

    created = False
    if not os.path.isfile(CONFIG_PATH):
        if CHECK_ONLY:
            step("config.json missing (--check: would create defaults)", "warn")
        else:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
            step(f"Created config.json with defaults", "ok")
            created = True
    else:
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception as e:
            step(f"config.json is corrupt ({e}); leaving as-is", "warn")
            existing = None

        if isinstance(existing, dict):
            merged = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
            _deep_merge(merged, existing)
            added_keys = sorted(set(_flatten_keys(merged)) - set(_flatten_keys(existing)))
            if added_keys and not CHECK_ONLY:
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(merged, f, indent=2, ensure_ascii=False)
                step(f"config.json updated: added {len(added_keys)} new default keys", "ok")
                if VERBOSE:
                    for k in added_keys:
                        print(f"      {D}+ {k}{X}")
            elif added_keys:
                step(f"config.json missing {len(added_keys)} default keys (--check: not writing)", "warn")
            else:
                step(f"config.json present and complete", "ok")

    for d in ("results", "workspaces"):
        p = os.path.join(PROJECT_ROOT, d)
        if os.path.isdir(p):
            step(f"directory {d}/ already exists", "ok")
        elif CHECK_ONLY:
            step(f"directory {d}/ missing (--check: not creating)", "warn")
        else:
            os.makedirs(p, exist_ok=True)
            step(f"created directory {d}/", "ok")

    return {"ok": True, "details": "config.json ready" + (" (new)" if created else "")}


def _flatten_keys(d: dict, prefix: str = "") -> list[str]:
    """List all leaf-and-branch keys of a nested dict in dot form."""
    out = []
    for k, v in d.items():
        path = f"{prefix}.{k}" if prefix else k
        out.append(path)
        if isinstance(v, dict):
            out.extend(_flatten_keys(v, path))
    return out


# --------------------------------------------------------------------------- #
#  Phase 6 — API keys wizard                                                  #
# --------------------------------------------------------------------------- #
def phase_apikeys(interactive: bool) -> dict[str, Any]:
    header("Phase 6 / 9  —  API keys wizard")

    try:
        from core.config import Config
    except Exception as e:
        step(f"Cannot import core.config: {e}", "bad")
        return {"ok": False, "details": str(e)}

    cfg = Config()
    if not interactive:
        existing = sum(1 for v in (cfg.get("api_keys") or {}).values() if v)
        step(f"Skipping wizard (--yes or non-interactive).  {existing} key(s) already set.", "info")
        return {"ok": True, "details": f"{existing} key(s) preset", "set_count": existing}

    print()
    print(f"  {D}For each service: paste the key, press Enter to skip, or type 'q' to quit the wizard.{X}")
    print(f"  {D}Keys are saved immediately — you can also use `apikeys set <name> <value>` later.{X}")

    saved_now = 0
    for name, title, feature, where in API_KEY_WIZARD:
        current = cfg.get(f"api_keys.{name}") or ""
        current_str = (f"{G}set{X} ({current[:4]}...{current[-4:]})"
                       if len(current) > 8
                       else (f"{G}set{X}" if current else f"{D}not set{X}"))
        print()
        print(f"  {BOLD}{'-' * 56}{X}")
        print(f"  {BOLD}{title}{X}")
        print(f"  Enables: {feature}")
        print(f"  Where:   {C}{where}{X}")
        print(f"  Current: {current_str}")
        try:
            raw = input(f"  Enter key (Enter to skip, 'q' to quit wizard): ").strip()
        except EOFError:
            step("stdin closed, stopping wizard", "warn")
            break
        if raw.lower() in ("q", "quit", "exit"):
            step("Wizard stopped by user", "info")
            break
        if not raw:
            continue
        cfg.set(f"api_keys.{name}", raw)
        cfg.save()
        step(f"{name} saved", "ok")
        saved_now += 1

    # Discord user token — opt-in with explicit warning.
    print()
    print(f"  {BOLD}{'-' * 56}{X}")
    print(f"  {BOLD}Discord USER token{X}  {R}(advanced / risky){X}")
    print(f"  {Y}! Enables deep OSINT but VIOLATES Discord ToS.{X}")
    print(f"  {Y}! Your account can be banned. Only set if you accept this risk.{X}")
    print(f"  {D}  (Press Enter to skip — this is almost always the right choice.){X}")
    try:
        raw = input(f"  Enter user token (Enter to skip): ").strip()
    except EOFError:
        raw = ""
    if raw:
        cfg.set("api_keys.discord_user_token", raw)
        cfg.save()
        step("discord_user_token saved", "ok")
        saved_now += 1

    total_set = sum(1 for v in (cfg.get("api_keys") or {}).values() if v)
    return {
        "ok": True,
        "details": f"{saved_now} newly saved, {total_set} total",
        "set_count": total_set,
    }


# --------------------------------------------------------------------------- #
#  Phase 7 — database                                                         #
# --------------------------------------------------------------------------- #
def phase_db() -> dict[str, Any]:
    header("Phase 7 / 9  —  Database")

    try:
        from core.database import Database
    except Exception as e:
        step(f"Cannot import core.database: {e}", "bad")
        return {"ok": False, "details": str(e)}

    try:
        db = Database()
        db_path = db.path
        try:
            db.close()
        except Exception:
            pass
        step(f"SQLite ready at {os.path.relpath(db_path, PROJECT_ROOT)}", "ok")
        return {"ok": True, "details": os.path.relpath(db_path, PROJECT_ROOT)}
    except Exception as e:
        step(f"Database init failed: {e}", "bad")
        return {"ok": False, "details": str(e)}


# --------------------------------------------------------------------------- #
#  Phase 8 — smoke tests                                                      #
# --------------------------------------------------------------------------- #
def phase_smoke() -> dict[str, Any]:
    header("Phase 8 / 9  —  Smoke tests")

    try:
        from core.console import Console, MODULE_REGISTRY
    except Exception as e:
        step(f"Cannot import core.console: {e}", "bad")
        return {"ok": False, "details": str(e), "module_count": 0}

    try:
        _ = Console()
        step("Console() instantiated", "ok")
    except Exception as e:
        step(f"Console() failed: {e}", "bad")
        return {"ok": False, "details": str(e), "module_count": len(MODULE_REGISTRY)}

    count = len(MODULE_REGISTRY)
    if count >= 80:
        step(f"MODULE_REGISTRY has {count} modules  (expected >= 80)", "ok")
    else:
        step(f"MODULE_REGISTRY has only {count} modules  (expected >= 80)", "warn")

    sample = ["recon/dns_enum", "web/headers", "harvest/username_osint",
              "github/user_profile", "full_recon"]
    loaded = 0
    import importlib
    for name in sample:
        entry = MODULE_REGISTRY.get(name)
        if not entry:
            step(f"load {name}  not in registry", "warn")
            continue
        try:
            mod_path, cls_name = entry
            mod = importlib.import_module(mod_path)
            getattr(mod, cls_name)()
            step(f"load {name}", "ok")
            loaded += 1
        except Exception as e:
            step(f"load {name}  FAILED: {e}", "warn")

    http_ok = False
    try:
        from core import http
        resp = http.get("https://api.github.com/", timeout=5)
        code = getattr(resp, "status_code", None)
        if code == 200:
            step("HTTP smoke: GET https://api.github.com/  ->  200", "ok")
            http_ok = True
        else:
            step(f"HTTP smoke returned {code}  (non-fatal, maybe offline / rate-limited)", "warn")
    except Exception as e:
        step(f"HTTP smoke failed: {e}  (non-fatal)", "warn")

    return {
        "ok": loaded >= 4 and count >= 80,
        "details": f"{loaded}/{len(sample)} sample modules; HTTP {'ok' if http_ok else 'skipped'}",
        "module_count": count,
        "loaded_sample": loaded,
        "http_ok": http_ok,
    }


# --------------------------------------------------------------------------- #
#  Phase 9 — summary                                                          #
# --------------------------------------------------------------------------- #
def phase_summary(results: dict[str, dict[str, Any]]) -> None:
    header("Setup complete")

    env = results.get("env", {})
    core = results.get("core", {})
    opt = results.get("optional", {})
    tools = results.get("tools", {})
    cfg = results.get("config", {})
    keys = results.get("keys", {})
    db = results.get("db", {})
    smoke = results.get("smoke", {})

    def line(label: str, val: str, ok: bool | None = None) -> None:
        mark = ""
        if ok is True:
            mark = f"  {G}OK{X}"
        elif ok is False:
            mark = f"  {R}FAIL{X}"
        print(f"  {BOLD}{label:<16}{X}{val}{mark}")

    print()
    line("Modules:",       f"{smoke.get('module_count', 0)} loaded",
         smoke.get('module_count', 0) >= 80)
    line("Core deps:",     f"{core.get('ok_count', 0)}/{core.get('total', 0)} ok",
         core.get("ok"))
    opt_extra = ""
    if sys.platform != "win32":
        opt_extra = f" {D}(pyreadline3 skipped — not Windows){X}"
    line("Optional deps:", f"{opt.get('ok_count', 0)}/{opt.get('total', 0)} ok{opt_extra}")
    tool_names_ok = ", ".join(n for n, ok in tools.get("results", []) if ok) or "none"
    tool_names_bad = ", ".join(n for n, ok in tools.get("results", []) if not ok)
    tool_summary = f"{tools.get('ok_count', 0)}/{tools.get('total', 0)} found"
    if tool_names_ok != "none":
        tool_summary += f"  ({tool_names_ok} present"
        if tool_names_bad:
            tool_summary += f"; {tool_names_bad} missing"
        tool_summary += ")"
    line("External tools:", tool_summary)
    line("Config:",        cfg.get("details", "unknown"), cfg.get("ok"))
    line("API keys set:",  str(keys.get("set_count", 0)))
    line("Database:",      db.get("details", "unknown"), db.get("ok"))

    # Overall verdict.
    fatal_fail = not core.get("ok") or not env.get("ok")
    if fatal_fail:
        verdict = f"{R}FAILED{X} — fix the errors above before using OsintConsole."
    elif smoke.get("ok") and db.get("ok") and cfg.get("ok"):
        verdict = f"{G}READY{X}"
    else:
        verdict = f"{Y}PARTIAL{X} — core is fine, some non-essential checks warned."

    print()
    print(f"  {BOLD}Status:{X}      {verdict}")
    print(f"  {BOLD}Next step:{X}   {C}python main.py{X}")
    print()
    print(f"  {D}Tip: `python setup.py --keys-only` re-opens the API key wizard anytime.{X}")
    print()


# --------------------------------------------------------------------------- #
#  CLI                                                                        #
# --------------------------------------------------------------------------- #
HELP_TEXT = """OsintConsole setup / bootstrap

Usage:
  python setup.py                 full interactive run
  python setup.py --yes           non-interactive (skip API key wizard)
  python setup.py --check         read-only status report (installs nothing)
  python setup.py --keys-only     run only the API key wizard
  python setup.py --verbose       show pip + subprocess output
  python setup.py --help          this message

What it does: Python/pip check -> pip install -r requirements.txt ->
optional deps -> external tools -> config.json merge -> API key wizard
-> SQLite init -> smoke tests -> summary. Idempotent and safe to re-run.
"""


def parse_args(argv: list[str]) -> dict[str, bool]:
    flags = {"yes": False, "check": False, "verbose": False, "keys_only": False, "help": False}
    aliases = {
        "-y": "yes", "--yes": "yes",
        "--check": "check",
        "-v": "verbose", "--verbose": "verbose",
        "--keys-only": "keys_only", "--keys": "keys_only",
        "-h": "help", "--help": "help",
    }
    for a in argv:
        key = aliases.get(a)
        if key is None:
            print(f"{WARN} Unknown argument: {a}")
            print(HELP_TEXT)
            sys.exit(2)
        flags[key] = True
    return flags


def banner() -> None:
    print(f"""
{BOLD}{C}  OsintConsole  —  Setup{X}
  {D}{PROJECT_ROOT}{X}
""")


def main() -> int:
    global VERBOSE, CHECK_ONLY
    flags = parse_args(sys.argv[1:])
    if flags["help"]:
        print(HELP_TEXT)
        return 0
    VERBOSE = flags["verbose"]
    CHECK_ONLY = flags["check"]

    banner()
    if CHECK_ONLY:
        step("Running in --check mode: no installs or writes will be performed", "info")

    results: dict[str, dict[str, Any]] = {}

    if flags["keys_only"]:
        step("--keys-only: skipping install / detection phases", "info")
        sys.path.insert(0, PROJECT_ROOT)
        results["keys"] = phase_apikeys(interactive=not flags["yes"])
        print()
        print(f"  {OK} Done.  Run {C}python main.py{X} to launch OsintConsole.")
        return 0

    # Phase 1
    results["env"] = phase_env()
    if not results["env"]["ok"]:
        step("Environment check failed — stopping.", "bad")
        return 1

    # Phase 2
    results["core"] = phase_core()
    if not results["core"]["ok"] and not CHECK_ONLY:
        step("Core imports failed — refusing to continue to module-dependent phases.", "bad")
        phase_summary(results)
        return 1

    # Phases 3-8
    results["optional"] = phase_optional()
    results["tools"] = phase_tools()
    results["config"] = phase_config()
    results["keys"] = phase_apikeys(interactive=not flags["yes"] and not CHECK_ONLY)
    results["db"] = phase_db() if not CHECK_ONLY else {"ok": True, "details": "skipped (--check)"}
    results["smoke"] = phase_smoke()

    phase_summary(results)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Setup cancelled. Rerun anytime: python setup.py{X}")
        sys.exit(130)
