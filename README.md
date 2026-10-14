# OsintConsole

[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

OsintConsole is an interactive OSINT and reconnaissance framework written in Python. You open the
console, pick a module, set a target, and run it — findings are saved automatically, entities
(emails, IPs, domains, usernames, wallets) are extracted and linked across scans, so a single seed
can grow into a full picture of a target.

It ships with 110 passive modules covering DNS and network recon, web analysis, email / username /
social OSINT, GitHub intelligence, and multi-chain crypto tracing — all driven from one console,
backed by a SQLite store, a correlation engine, and HTML and graph reports.

**Documentation:** https://osintconsole.pages.dev

## Features

- **110 modules** across 5 categories — recon (27), web (26), harvest (42), GitHub (12), automation (3)
- **Interactive console** — `use` / `set` / `run` / `chain` / `workspace`
- **Correlation engine + SQLite store** — entities linked across scans, with cross-target pivoting
- **`full_recon`** — run every applicable module against a target, with auto-enrichment (discovered emails → breach check, wallets → OFAC screening)
- **`identity_pivot`** — expand a single email / username / domain / IP / phone / wallet into a relationship graph
- **Crypto tracing** — balances, transactions, ENS, wallet → social identity, and OFAC sanctions across multiple chains
- **Reports** — JSON / Markdown / HTML plus an interactive relationship graph
- **Passive by design** — proxy / Tor support, host-scoped auth sessions, and an SSRF guard

## Install

Requires **Python 3.10+**.

```bash
git clone https://github.com/ap0dj/osintconsole.git
cd osintconsole
pip install -r requirements.txt
cp config.example.json config.json    # Windows: copy config.example.json config.json
python main.py
```

Or run the setup helper, which installs the dependencies and can walk you through the optional API keys:

```bash
python setup.py          # interactive
python setup.py --yes    # non-interactive (skips the key wizard)
python setup.py --check  # read-only status report, installs nothing
```

Optional packages (`PySocks` for Tor, `selenium` for screenshots) enable a few extra features; the tool runs fine without them.

## Usage

```
osintconsole > use harvest/username_osint
osintconsole(harvest/username_osint) > set TARGET johndoe
osintconsole(harvest/username_osint) > run
```

Run every applicable module against a target at once:

```
osintconsole > full_recon example.com
```

The full module list, command reference, and API-key setup are in the
[documentation](https://osintconsole.pages.dev).

## License

MIT — see [LICENSE](LICENSE).
