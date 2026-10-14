"""Proxy-aware HTTP helper used across modules.

Respects proxy / Tor settings from Config, applies a default User-Agent and
timeout, and adds reliability: per-host rate limiting, retry-with-backoff on
transient failures, a per-host circuit breaker, and optional in-memory or
on-disk GET caching.
"""
import os
import time
import json
import contextlib
import random
import shutil
import hashlib
import threading
from urllib.parse import urlparse
import requests
from core.config import Config

_LOCK = threading.Lock()
_LAST_REQUEST = {}
_CACHE = {}
_CACHE_MAX = 500
_cache_state = {"enabled": False, "ttl": 300, "disk": False, "dir": ".http_cache"}

# Per-host concurrency caps. Under parallel full_recon ~8 modules can hit the
# same free host (crt.sh, hackertarget) at once and trip a per-IP limit — worse
# on the owner's shared CGNAT IP. These semaphores bound simultaneous in-flight
# requests per host; they are created lazily under _SEM_LOCK.
_SEM_LOCK = threading.Lock()
_HOST_SEM = {}
_HOST_LIMITS = {
    "crt.sh": 1,
    "api.hackertarget.com": 1,
    "dogechain.info": 1,
    "api.blockchair.com": 1,
    "otx.alienvault.com": 2,
}
_DEFAULT_HOST_LIMIT = 4


def _host_semaphore(host):
    host = (host or "").lower()
    with _SEM_LOCK:
        sem = _HOST_SEM.get(host)
        if sem is None:
            sem = threading.BoundedSemaphore(
                _HOST_LIMITS.get(host, _DEFAULT_HOST_LIMIT))
            _HOST_SEM[host] = sem
        return sem

# Per-host consecutive connection failures -> {host: (fails, last_failure_ts)}.
# Without a breaker a dead uplink makes every one of ~100 parallel modules burn
# its full retry budget, turning a fast failure into several minutes of hanging.
_BREAKER = {}

RETRYABLE_STATUS = {429, 500, 502, 503, 504}

RETRYABLE_EXC = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
)

# Only these round-trip safely through the text-based disk cache.
_CACHEABLE_TYPES = ("text/", "json", "xml", "javascript", "html")


class CircuitOpen(requests.exceptions.RequestException):
    """Raised instead of connecting while a host's breaker is open."""


class CachedResponse:
    """Minimal stand-in for requests.Response, rebuilt from the disk cache."""

    from_cache = True
    cookies = ()

    def __init__(self, record):
        self.status_code = record["status_code"]
        self.url = record.get("url", "")
        self.headers = record.get("headers", {})
        self.text = record.get("text", "")

    @property
    def content(self):
        return self.text.encode("utf-8", "ignore")

    @property
    def ok(self):
        return self.status_code < 400

    def json(self, **_kwargs):
        return json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(
                f"{self.status_code} for {self.url}", response=self)


def enable_cache(ttl=None, disk=None, cache_dir=None):
    config = Config()
    _cache_state["enabled"] = True
    _cache_state["ttl"] = ttl if ttl is not None else config.get("http.cache_ttl", 300)
    _cache_state["disk"] = (
        bool(disk) if disk is not None else bool(config.get("http.cache_disk", False))
    )
    if cache_dir:
        _cache_state["dir"] = cache_dir


def disable_cache():
    _cache_state["enabled"] = False


@contextlib.contextmanager
def cache_bypassed():
    """Temporarily turn the cache off — for callers that need FRESH data, such
    as monitor, whose whole job is spotting what changed since the last run."""
    prev = _cache_state["enabled"]
    _cache_state["enabled"] = False
    try:
        yield
    finally:
        _cache_state["enabled"] = prev


# Responses larger than this are not held in the memory cache (crawler pages,
# archive snapshots) so a long scan cannot balloon memory.
_CACHE_MAX_BYTES = 2_000_000


def _cache_key(url, params):
    """Stable key for dict, list-of-pairs or string params (modules use all)."""
    if isinstance(params, dict):
        p = repr(sorted(params.items()))
    elif isinstance(params, (list, tuple)):
        p = repr(sorted(params))
    else:
        p = repr(params)
    return (url, p)


def clear_cache():
    _CACHE.clear()
    if os.path.isdir(_cache_state["dir"]):
        shutil.rmtree(_cache_state["dir"], ignore_errors=True)


def _defaults(url, kwargs):
    config = Config()
    kwargs.setdefault("timeout", config.get("timeout", 10))
    headers = kwargs.get("headers") or {}
    headers.setdefault("User-Agent", config.get("user_agent"))

    # Authenticated-session support, HOST-SCOPED: the configured auth header /
    # cookie is attached ONLY to hosts in http.auth_hosts, never to every
    # third-party API. Empty allowlist = attach to nothing (secure default) so a
    # session cookie set for site A can't leak to shodan/github/thum.io. Also
    # dropped on verify=False requests (TLS off -> MITM could capture creds).
    auth_hosts = config.get("http.auth_hosts") or []
    host = urlparse(url).hostname or ""
    scoped = (isinstance(auth_hosts, list) and auth_hosts
              and _host_matches(host, auth_hosts)
              and kwargs.get("verify", True) is not False)
    if scoped:
        custom = config.get("http.headers") or {}
        if isinstance(custom, dict):
            for k, v in custom.items():
                headers.setdefault(k, v)
        cookies = config.get("http.cookies")
        if cookies:
            headers.setdefault("Cookie", cookies)
    kwargs["headers"] = headers
    proxies = config.proxies()
    if proxies and "proxies" not in kwargs:
        kwargs["proxies"] = proxies
    return kwargs


def _num(key, default):
    try:
        return type(default)(Config().get(key, default))
    except (TypeError, ValueError):
        return default


class SSRFBlocked(requests.exceptions.RequestException):
    """Raised when a request target resolves to a blocked internal address."""


def _host_matches(host, patterns):
    host = (host or "").lower()
    for p in patterns:
        p = str(p).strip().lower()
        if p.startswith("*."):
            p = p[2:]
        if p and (host == p or host.endswith("." + p)):
            return True
    return False


def _ip_blocked(ip_obj, block_private):
    # Loopback, link-local (incl. the 169.254.169.254 cloud-metadata IP),
    # multicast, reserved and unspecified are never legitimate recon targets
    # and are the classic SSRF escalation paths — always blocked.
    if (ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast
            or ip_obj.is_reserved or ip_obj.is_unspecified):
        return True
    # RFC1918 LAN is only blocked when the operator opts in — this owner may
    # legitimately scan their own 192.168/10.x network.
    return block_private and ip_obj.is_private


def _ssrf_check(url):
    """Reject a URL whose host resolves to a blocked internal address.

    Default-on; bypass per call with allow_internal=True. Protects the
    auto-fetch path (scraped/chained entities fed back in as TARGET) from being
    tricked into hitting loopback or the cloud-metadata endpoint.
    """
    import ipaddress
    import socket

    if not bool(Config().get("http.ssrf_guard", True)):
        return
    host = urlparse(url).hostname
    if not host:
        return
    block_private = bool(Config().get("http.block_private", False))
    candidates = []
    try:
        candidates = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            candidates = [ipaddress.ip_address(info[4][0])
                          for info in socket.getaddrinfo(host, None)]
        except (socket.gaierror, ValueError, OSError):
            return  # unresolvable — let the request fail naturally
    for ip_obj in candidates:
        if _ip_blocked(ip_obj, block_private):
            raise SSRFBlocked(
                f"blocked internal/metadata address {ip_obj} for host {host}")


_CRED_PARAMS = ("key", "apikey", "api_key", "token", "access_key", "secret",
                "apiKey", "auth")


def _redact_url(url):
    """Blank out credential-bearing query params before caching/logging a URL."""
    try:
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        parts = urlsplit(url)
        if not parts.query:
            return url
        q = [(k, "REDACTED" if k.lower() in {p.lower() for p in _CRED_PARAMS}
              else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit(parts._replace(query=urlencode(q)))
    except Exception:
        return url


def _sleep_for(backoff, attempt):
    """Exponential backoff plus jitter, so parallel workers don't retry in lockstep."""
    return backoff * (2 ** attempt) * (1 + random.random())


def _retry_after(resp):
    """Seconds from a Retry-After header (numeric form), capped; else None."""
    raw = resp.headers.get("Retry-After") if resp is not None else None
    if not raw:
        return None
    try:
        return min(float(raw), 30.0)
    except (TypeError, ValueError):
        return None


def _breaker_check(host):
    threshold = _num("http.breaker_threshold", 5)
    if threshold <= 0:
        return
    with _LOCK:
        fails, opened_at = _BREAKER.get(host, (0, 0.0))
        if fails < threshold:
            return
        if time.time() - opened_at < _num("http.breaker_cooldown", 60.0):
            raise CircuitOpen(
                f"circuit open for {host} after {fails} consecutive failures")
        _BREAKER.pop(host, None)


def _breaker_record(host, ok):
    with _LOCK:
        if ok:
            _BREAKER.pop(host, None)
        else:
            fails, _ = _BREAKER.get(host, (0, 0.0))
            _BREAKER[host] = (fails + 1, time.time())


def reset_breakers():
    with _LOCK:
        _BREAKER.clear()


def breaker_state():
    with _LOCK:
        return dict(_BREAKER)


def _disk_path(cache_key):
    digest = hashlib.sha256(repr(cache_key).encode("utf-8")).hexdigest()
    return os.path.join(_cache_state["dir"], digest[:2], f"{digest}.json")


def _disk_read(cache_key):
    try:
        with open(_disk_path(cache_key), encoding="utf-8") as f:
            record = json.load(f)
        if time.time() - record["ts"] < _cache_state["ttl"]:
            return CachedResponse(record)
    except (OSError, ValueError, KeyError):
        pass
    return None


def _disk_write(cache_key, resp):
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if not any(t in ctype for t in _CACHEABLE_TYPES):
        return
    path = _disk_path(cache_key)
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({
                "ts": time.time(),
                "status_code": resp.status_code,
                "url": _redact_url(resp.url),
                # Never persist response Set-Cookie / auth echoes to disk.
                "headers": {k: v for k, v in resp.headers.items()
                            if k.lower() not in (
                                "set-cookie", "authorization", "www-authenticate")},
                "text": resp.text,
            }, f)
        os.replace(tmp, path)
    except (OSError, ValueError, UnicodeError):
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _rate_limit(url):
    delay = _num("http.min_interval", 0.0)
    if delay <= 0:
        return
    host = urlparse(url).netloc
    now = time.time()
    with _LOCK:
        last = _LAST_REQUEST.get(host, 0)
        wait = delay - (now - last)
        # reserve this slot now so parallel callers for the same host coordinate
        _LAST_REQUEST[host] = now + max(0, wait)
    if wait > 0:
        time.sleep(wait)


def request(method, url, **kwargs):
    allow_internal = kwargs.pop("allow_internal", False)
    kwargs = _defaults(url, kwargs)
    if not allow_internal:
        _ssrf_check(url)   # raises SSRFBlocked for loopback/metadata/etc.
    use_cache = kwargs.pop("cache", False) or _cache_state["enabled"]
    if kwargs.get("stream"):
        use_cache = False
    method_u = method.upper()

    host = urlparse(url).netloc

    cache_key = None
    if use_cache and method_u == "GET":
        cache_key = _cache_key(url, kwargs.get("params"))
        hit = _CACHE.get(cache_key)
        if hit and (time.time() - hit[0]) < _cache_state["ttl"]:
            return hit[1]
        if _cache_state["disk"]:
            cached = _disk_read(cache_key)
            if cached is not None:
                return cached

    retries = max(0, _num("http.retries", 2))
    backoff = _num("http.backoff", 0.5)
    resp = None
    # Cap simultaneous in-flight requests to this host (CGNAT-friendly).
    with _host_semaphore(host):
        for attempt in range(retries + 1):
            _breaker_check(host)
            _rate_limit(url)
            try:
                resp = requests.request(method, url, **kwargs)
                # Only retry status codes for safe, idempotent methods
                if (method_u in ("GET", "HEAD")
                        and resp.status_code in RETRYABLE_STATUS
                        and attempt < retries):
                    # Respect the server's Retry-After when it asks us to wait.
                    time.sleep(_retry_after(resp) or _sleep_for(backoff, attempt))
                    continue
                break
            except RETRYABLE_EXC:
                if attempt < retries:
                    time.sleep(_sleep_for(backoff, attempt))
                    continue
                _breaker_record(host, False)
                raise

    # A throttle / server-error response is a FAILURE for the breaker — not a
    # healthy reset. Otherwise a host that only ever 429s stays "healthy" and the
    # breaker (which exists to back off exactly this) never trips.
    throttled = resp is not None and resp.status_code in RETRYABLE_STATUS
    _breaker_record(host, not throttled)

    if (cache_key is not None and resp is not None and resp.status_code < 300
            and len(resp.content or b"") <= _CACHE_MAX_BYTES):
        if _cache_state["disk"]:
            _disk_write(cache_key, resp)
        with _LOCK:
            if len(_CACHE) >= _CACHE_MAX:
                # drop oldest 20%
                keys_sorted = sorted(_CACHE.keys(), key=lambda k: _CACHE[k][0])
                for k in keys_sorted[: _CACHE_MAX // 5]:
                    _CACHE.pop(k, None)
            _CACHE[cache_key] = (time.time(), resp)
    return resp


def get(url, **kwargs):
    return request("GET", url, **kwargs)


def post(url, **kwargs):
    return request("POST", url, **kwargs)


def head(url, **kwargs):
    return request("HEAD", url, **kwargs)


def session():
    """A requests.Session pre-configured with proxy + default UA.

    Configured auth (http.headers/http.cookies) is intentionally NOT baked into
    the session here: a session object has no single host, so attaching it would
    leak the credential to every host the session later touches. Host-scoped auth
    is applied per-request in _defaults() instead.
    """
    config = Config()
    s = requests.Session()
    s.headers.update({"User-Agent": config.get("user_agent")})
    proxies = config.proxies()
    if proxies:
        s.proxies.update(proxies)
    return s
