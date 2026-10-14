import base64
import time
from collections import Counter
from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_ip, is_valid_domain
from core.config import Config
from core import http


class CensysSearch(BaseModule):
    name = "recon/censys_search"
    description = "Censys.io passive recon - hosts, services, certs (needs API id/secret; crt.sh fallback)"
    category = "recon"
    target_type = "domain/ip"

    HOSTS_SEARCH = "https://search.censys.io/api/v2/hosts/search"
    HOST_VIEW = "https://search.censys.io/api/v2/hosts/{ip}"
    CERTS_SEARCH = "https://search.censys.io/api/v2/certificates/search"
    CRTSH_URL = "https://crt.sh/"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Domain, IPv4, or raw Censys query")
        self.add_option("MODE", "auto", False, "auto | host | hosts_search | certs")
        self.add_option("PER_PAGE", "25", False, "Results per page (max 100)")

    # ------------------------------------------------------------------
    # Auth helper
    # ------------------------------------------------------------------
    def _auth_header(self, api_id, api_secret):
        token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Accept": "application/json"}

    def _handle_status(self, resp, label):
        """Map 401/403/429 to warning; return True if request is usable."""
        if resp is None:
            self.results.setdefault("warnings", []).append(f"{label}: no response")
            return False
        if resp.status_code == 200:
            return True
        if resp.status_code == 401:
            msg = f"{label}: 401 unauthorized - check censys_id/censys_secret"
        elif resp.status_code == 403:
            msg = f"{label}: 403 forbidden - plan does not allow this endpoint"
        elif resp.status_code == 429:
            msg = f"{label}: 429 rate limited - slow down or upgrade plan"
        else:
            msg = f"{label}: HTTP {resp.status_code}"
        print_status(msg, "warning")
        self.results.setdefault("warnings", []).append(msg)
        return False

    # ------------------------------------------------------------------
    # Endpoint callers
    # ------------------------------------------------------------------
    def _hosts_search(self, query, headers, per_page):
        try:
            resp = http.get(self.HOSTS_SEARCH, headers=headers,
                            params={"q": query, "per_page": per_page})
            if not self._handle_status(resp, "hosts_search"):
                return []
            data = resp.json() or {}
            return (data.get("result") or {}).get("hits", []) or []
        except Exception as e:
            msg = f"hosts_search error: {e}"
            print_status(msg, "warning")
            self.results.setdefault("warnings", []).append(msg)
            return []

    def _host_view(self, ip, headers):
        try:
            resp = http.get(self.HOST_VIEW.format(ip=ip), headers=headers)
            if not self._handle_status(resp, "host_view"):
                return {}
            data = resp.json() or {}
            return (data.get("result") or {})
        except Exception as e:
            msg = f"host_view error: {e}"
            print_status(msg, "warning")
            self.results.setdefault("warnings", []).append(msg)
            return {}

    def _certs_search(self, query, headers, per_page):
        try:
            resp = http.get(self.CERTS_SEARCH, headers=headers,
                            params={"q": query, "per_page": per_page})
            if not self._handle_status(resp, "certs_search"):
                return []
            data = resp.json() or {}
            return (data.get("result") or {}).get("hits", []) or []
        except Exception as e:
            msg = f"certs_search error: {e}"
            print_status(msg, "warning")
            self.results.setdefault("warnings", []).append(msg)
            return []

    def _crtsh_fallback(self, domain):
        """No-key subdomain/cert enumeration via crt.sh."""
        try:
            resp = http.get(self.CRTSH_URL, params={"q": domain, "output": "json"})
            if resp is None or resp.status_code != 200:
                return []
            data = resp.json() or []
            seen, certs = set(), []
            for row in data:
                fp = row.get("serial_number") or row.get("id")
                if fp in seen:
                    continue
                seen.add(fp)
                names = [n.strip() for n in (row.get("name_value") or "").splitlines() if n.strip()]
                certs.append({
                    "fingerprint_sha256": str(row.get("serial_number") or ""),
                    "names": names,
                    "issuer": row.get("issuer_name"),
                    "validity_period": {
                        "not_before": row.get("not_before"),
                        "not_after": row.get("not_after"),
                    },
                    "source": "crt.sh",
                })
            return certs
        except Exception as e:
            msg = f"crt.sh fallback error: {e}"
            print_status(msg, "warning")
            self.results.setdefault("warnings", []).append(msg)
            return []

    # ------------------------------------------------------------------
    # Normalizers
    # ------------------------------------------------------------------
    def _norm_host(self, hit):
        services = []
        for s in hit.get("services", []) or []:
            services.append({
                "port": s.get("port"),
                "service_name": s.get("service_name"),
                "transport_protocol": s.get("transport_protocol"),
                "extended_service_name": s.get("extended_service_name"),
            })
        return {
            "ip": hit.get("ip"),
            "services": services,
            "autonomous_system": hit.get("autonomous_system") or {},
            "location": hit.get("location") or {},
            "dns": hit.get("dns") or {},
            "operating_system": hit.get("operating_system") or {},
            "last_updated_at": hit.get("last_updated_at"),
        }

    def _norm_cert(self, hit):
        parsed = hit.get("parsed") or {}
        return {
            "fingerprint_sha256": hit.get("fingerprint_sha256") or parsed.get("fingerprint_sha256"),
            "names": hit.get("names") or parsed.get("names") or [],
            "issuer": (parsed.get("issuer") or {}).get("common_name")
                      or (parsed.get("issuer_dn")) or hit.get("issuer_dn"),
            "validity_period": parsed.get("validity_period") or {
                "not_before": parsed.get("validity", {}).get("start"),
                "not_after": parsed.get("validity", {}).get("end"),
            },
            "source": "censys",
        }

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        mode = (self.get_option("MODE") or "auto").strip().lower()
        try:
            per_page = max(1, min(100, int(self.get_option("PER_PAGE") or 25)))
        except ValueError:
            per_page = 25

        config = Config()
        api_id = config.get("api_keys.censys_id") or ""
        api_secret = config.get("api_keys.censys_secret") or ""
        has_key = bool(api_id and api_secret)
        headers = self._auth_header(api_id, api_secret) if has_key else {}

        self.results = {
            "target": target,
            "mode_used": None,
            "api_key_present": has_key,
            "hosts": [],
            "certificates": [],
            "stats": {"total_hits": 0, "duration_sec": 0.0},
            "warnings": [],
        }

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Censys Search: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        if not has_key:
            print_status("No Censys API id/secret set (api_keys.censys_id / .censys_secret)",
                         "warning")
            print_status("Falling back to crt.sh for certificate transparency only", "info")
            self.results["warnings"].append("no_api_key: using crt.sh fallback")

        # Auto-detect mode
        if mode == "auto":
            if is_valid_ip(target):
                mode = "host"
            elif is_valid_domain(target):
                mode = "hosts_search"
            else:
                mode = "hosts_search"  # raw query
        self.results["mode_used"] = mode
        print_status(f"Mode: {mode} | per_page={per_page} | key={'yes' if has_key else 'no'}",
                     "info")

        t0 = time.time()

        # ---- HOST (single IP view) ----
        if mode == "host":
            if not is_valid_ip(target):
                print_status(f"MODE=host but '{target}' is not a valid IPv4", "error")
                return False
            if not has_key:
                print_status("host mode needs an API key", "error")
                return False
            print_status(f"Querying host view: {target}", "info")
            host = self._host_view(target, headers)
            if host:
                normalized = self._norm_host(host)
                self.results["hosts"].append(normalized)
                print_status(f"IP {normalized['ip']} - "
                             f"AS: {(normalized['autonomous_system'] or {}).get('name', '?')} "
                             f"({(normalized['autonomous_system'] or {}).get('asn', '?')})",
                             "success")
                loc = normalized["location"] or {}
                if loc:
                    print_status(f"Location: {loc.get('city', '?')}, "
                                 f"{loc.get('country', '?')}", "success")
                for s in normalized["services"][:15]:
                    print_status(f"  Port {s['port']}/{s['transport_protocol']}: "
                                 f"{s['service_name']} "
                                 f"{s.get('extended_service_name') or ''}", "success")

        # ---- HOSTS SEARCH ----
        elif mode == "hosts_search":
            if not has_key:
                print_status("hosts_search needs an API key - skipping", "warning")
            else:
                if is_valid_domain(target):
                    q = f"names: {target}"
                elif is_valid_ip(target):
                    q = f"ip: {target}"
                else:
                    q = target  # raw query
                print_status(f"Hosts search: {q}", "info")
                hits = self._hosts_search(q, headers, per_page)
                for h in hits:
                    self.results["hosts"].append(self._norm_host(h))
                print_status(f"Hosts found: {len(hits)}", "success" if hits else "warning")
                for h in self.results["hosts"][:10]:
                    asn = (h["autonomous_system"] or {}).get("asn", "?")
                    svc_names = ",".join(sorted({s.get("service_name") or "?"
                                                 for s in h["services"]})[:6])
                    print_status(f"  {h['ip']:<16} AS{asn} [{svc_names}]", "success")

            # Also pull certs for a domain target
            if is_valid_domain(target):
                if has_key:
                    cq = f"parsed.names: {target}"
                    print_status(f"Certs search: {cq}", "info")
                    certs = self._certs_search(cq, headers, per_page)
                    for c in certs:
                        self.results["certificates"].append(self._norm_cert(c))
                    print_status(f"Certs found: {len(certs)}",
                                 "success" if certs else "warning")
                else:
                    print_status("Querying crt.sh (public CT log)...", "info")
                    certs = self._crtsh_fallback(target)
                    self.results["certificates"].extend(certs[:per_page * 4])
                    print_status(f"crt.sh certs: {len(certs)}",
                                 "success" if certs else "warning")

        # ---- CERTS ONLY ----
        elif mode == "certs":
            if has_key:
                q = f"parsed.names: {target}" if is_valid_domain(target) else target
                print_status(f"Certs search: {q}", "info")
                certs = self._certs_search(q, headers, per_page)
                for c in certs:
                    self.results["certificates"].append(self._norm_cert(c))
            if (not has_key or not self.results["certificates"]) and is_valid_domain(target):
                print_status("Querying crt.sh (public CT log)...", "info")
                certs = self._crtsh_fallback(target)
                self.results["certificates"].extend(certs[:per_page * 4])
            print_status(f"Certs found: {len(self.results['certificates'])}",
                         "success" if self.results["certificates"] else "warning")

        else:
            print_status(f"Unknown MODE '{mode}' (use auto|host|hosts_search|certs)", "error")
            return False

        # ------------------------------------------------------------------
        # Final summary block
        # ------------------------------------------------------------------
        duration = round(time.time() - t0, 2)
        total = len(self.results["hosts"]) + len(self.results["certificates"])
        self.results["stats"] = {"total_hits": total, "duration_sec": duration}

        svc_counter = Counter()
        port_counter = Counter()
        as_counter = Counter()
        for h in self.results["hosts"]:
            asn_info = h.get("autonomous_system") or {}
            if asn_info.get("name"):
                as_counter[f"AS{asn_info.get('asn')} {asn_info.get('name')}"] += 1
            for s in h.get("services", []):
                if s.get("service_name"):
                    svc_counter[s["service_name"]] += 1
                if s.get("port") is not None:
                    port_counter[s["port"]] += 1

        ct_counter = Counter()
        for c in self.results["certificates"]:
            for n in (c.get("names") or [])[:3]:
                ct_counter[n.lower().lstrip("*.")] += 1

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Summary: {target}")
        print(f"{'='*58}{Colors.RESET}")
        print_status(f"Total hits: {total}  |  Duration: {duration}s", "info")
        print_status(f"Hosts: {len(self.results['hosts'])}  |  "
                     f"Certificates: {len(self.results['certificates'])}", "info")
        if svc_counter:
            top = ", ".join(f"{s}({n})" for s, n in svc_counter.most_common(6))
            print_status(f"Top services: {top}", "success")
        if port_counter:
            top = ", ".join(f"{p}({n})" for p, n in port_counter.most_common(8))
            print_status(f"Top ports: {top}", "success")
        if as_counter:
            top = "; ".join(f"{a}({n})" for a, n in as_counter.most_common(3))
            print_status(f"Top AS: {top}", "success")
        if ct_counter:
            top = ", ".join(f"{n}({c})" for n, c in ct_counter.most_common(8))
            print_status(f"Top CT names: {top}", "success")
        if self.results["warnings"]:
            print_status(f"Warnings: {len(self.results['warnings'])}", "warning")
            for w in self.results["warnings"][:5]:
                print_status(f"  - {w}", "warning")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return total > 0 or bool(self.results["hosts"])
