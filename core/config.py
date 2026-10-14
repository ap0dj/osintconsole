import json
import os
import sys

DEFAULT_CONFIG = {
    "output_dir": "results",
    "timeout": 10,
    "threads": 10,
    "verbose": False,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "api_keys": {
        "shodan": "",
        "virustotal": "",
        "hunter": "",
        "securitytrails": "",
        "github": "",
        "telegram_bot": "",
        "numverify": "",
        "abstractapi_phone": "",
        "ipqualityscore": "",
        "abuseipdb": "",
        "greynoise": "",
        "nvd": "",
        "discord_bot": "",
        "discord_user_token": "",
        "censys_id": "",
        "censys_secret": "",
        "urlscan": "",
        "otx": "",
        "oathnet": "",
        "intelx": "",
        "hibp": "",
        "breachdirectory": "",
        "rapidapi": "",
    },
    "proxy": {
        "enabled": False,
        "http": "",
        "https": "",
        "tor": False,
        "tor_address": "socks5h://127.0.0.1:9050",
    },
    "database": {
        "enabled": True,
        "path": "osint.db",
    },
    "http": {
        "retries": 2,
        "backoff": 0.5,
        "min_interval": 0.5,
        "cache_ttl": 300,
        "cache_enabled": True,     # in-memory GET cache for the session (monitor bypasses)
        "headers": {},
        "cookies": "",
        "auth_hosts": [],          # hosts the configured auth header/cookie may be sent to
        "ssrf_guard": True,        # block loopback/link-local/metadata fetch targets
        "block_private": False,    # also block RFC1918 LAN (off: owner may scan own network)
    },
    "dns_servers": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
    "port_scan": {
        "top_ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                      993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888],
    },
}


def _deep_merge(base, override):
    """Recursively merge override into base so new default keys survive saved config."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


class Config:
    _instance = None
    _config = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._config = DEFAULT_CONFIG.copy()
            cls._config_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
            cls._instance._load()
        return cls._instance

    def _load(self):
        if not os.path.exists(self._config_file):
            return
        try:
            with open(self._config_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                _deep_merge(self._config, saved)
        except (json.JSONDecodeError, OSError) as e:
            # Keep defaults; backup the broken file so we can inspect later.
            # Warn loudly — otherwise the operator's saved keys/settings vanish silently.
            backup = self._config_file + ".broken"
            try:
                os.rename(self._config_file, backup)
                where = f" (backed up to {os.path.basename(backup)})"
            except OSError:
                where = ""
            sys.stderr.write(
                f"[!] config.json could not be read ({e}); reverted to defaults"
                f"{where}. Your saved API keys/settings are NOT loaded.\n")

    def proxies(self):
        """Return a requests-style proxies dict based on current config, or None."""
        proxy = self._config.get("proxy", {})
        if not proxy.get("enabled"):
            return None
        if proxy.get("tor"):
            addr = proxy.get("tor_address") or "socks5h://127.0.0.1:9050"
            return {"http": addr, "https": addr}
        result = {}
        if proxy.get("http"):
            result["http"] = proxy["http"]
        if proxy.get("https"):
            result["https"] = proxy["https"]
        return result or None

    def save(self):
        tmp = self._config_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._config, f, indent=2, ensure_ascii=False)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, self._config_file)

    def get(self, key, default=None):
        keys = key.split(".")
        val = self._config
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k, default)
            else:
                return default
        return val

    def set(self, key, value):
        keys = key.split(".")
        d = self._config
        for k in keys[:-1]:
            nxt = d.get(k)
            if not isinstance(nxt, dict):
                nxt = {}
                d[k] = nxt
            d = nxt
        d[keys[-1]] = value

    @property
    def data(self):
        return self._config
