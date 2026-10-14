#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

from core.console import Console
from core.config import Config
from core import http


def main():
    try:
        # In-memory GET cache for the session: when several modules hit the
        # same endpoint in one scan (crt.sh, Blockscout /addresses, ...) the
        # repeat is served locally — fewer requests on a shared CGNAT IP.
        # Monitor bypasses it. Toggle with http.cache_enabled.
        if Config().get("http.cache_enabled", True):
            http.enable_cache()
        console = Console()
        console.start()
    except KeyboardInterrupt:
        print("\n\033[92m[*] Goodbye!\033[0m")
        sys.exit(0)


if __name__ == "__main__":
    main()
