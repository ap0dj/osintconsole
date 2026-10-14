from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_ip
from core.config import Config
from core import http


COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
CONTEXT_URL = "https://api.greynoise.io/v2/noise/context/{ip}"
RIOT_URL = "https://api.greynoise.io/v2/riot/{ip}"

VALID_MODES = ("auto", "community", "context", "riot")
MAX_IPS = 10


class Greynoise(BaseModule):
    name = "recon/greynoise"
    description = "GreyNoise - classify IPs as internet noise, benign RIOT services, or targeted scanners"
    category = "recon"
    target_type = "ip"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Single IP or comma-separated list (max 10)")
        self.add_option("MODE", "auto", False, "auto | community | context | riot")

    # ---------- API probes ----------

    def _community(self, ip, warnings):
        url = COMMUNITY_URL.format(ip=ip)
        try:
            resp = http.get(url, headers={"Accept": "application/json"})
        except Exception as e:
            warnings.append(f"community {ip}: {e}")
            return None
        if resp.status_code == 429:
            warnings.append(f"community {ip}: rate limited (429)")
            return None
        if resp.status_code == 404:
            # 404 for community = IP not observed
            try:
                return resp.json()
            except Exception:
                return {"ip": ip, "noise": False, "riot": False,
                        "classification": "unknown", "message": "IP not observed"}
        if resp.status_code != 200:
            warnings.append(f"community {ip}: HTTP {resp.status_code}")
            return None
        try:
            return resp.json()
        except Exception as e:
            warnings.append(f"community {ip}: bad JSON ({e})")
            return None

    def _context(self, ip, key, warnings):
        url = CONTEXT_URL.format(ip=ip)
        try:
            resp = http.get(url, headers={"key": key, "Accept": "application/json"})
        except Exception as e:
            warnings.append(f"context {ip}: {e}")
            return None
        if resp.status_code == 429:
            warnings.append(f"context {ip}: rate limited (429)")
            return None
        if resp.status_code == 401:
            warnings.append("context: invalid API key (401)")
            return None
        if resp.status_code not in (200, 404):
            warnings.append(f"context {ip}: HTTP {resp.status_code}")
            return None
        try:
            return resp.json()
        except Exception as e:
            warnings.append(f"context {ip}: bad JSON ({e})")
            return None

    def _riot(self, ip, key, warnings):
        url = RIOT_URL.format(ip=ip)
        try:
            resp = http.get(url, headers={"key": key, "Accept": "application/json"})
        except Exception as e:
            warnings.append(f"riot {ip}: {e}")
            return None
        if resp.status_code == 429:
            warnings.append(f"riot {ip}: rate limited (429)")
            return None
        if resp.status_code == 401:
            warnings.append("riot: invalid API key (401)")
            return None
        if resp.status_code not in (200, 404):
            warnings.append(f"riot {ip}: HTTP {resp.status_code}")
            return None
        try:
            return resp.json()
        except Exception as e:
            warnings.append(f"riot {ip}: bad JSON ({e})")
            return None

    # ---------- Per-IP orchestration ----------

    def _probe_ip(self, ip, mode, key, warnings):
        """Run the requested probes for one IP and merge them into a record."""
        community = context = riot = None

        if mode in ("auto", "community"):
            community = self._community(ip, warnings)
        if key and mode in ("auto", "context"):
            context = self._context(ip, key, warnings)
        if key and mode in ("auto", "riot"):
            riot = self._riot(ip, key, warnings)

        record = {
            "classification": "unknown",
            "noise": False,
            "riot": False,
            "actor": None,
            "tags": [],
            "first_seen": None,
            "last_seen": None,
            "raw_data": {"scan_ports": [], "web_paths": [], "user_agents": []},
            "riot_info": {},
            "message": None,
            "community_link": None,
        }

        if community:
            record["noise"] = bool(community.get("noise"))
            record["riot"] = bool(community.get("riot"))
            record["classification"] = community.get("classification") or "unknown"
            record["actor"] = community.get("name") or record["actor"]
            record["last_seen"] = community.get("last_seen") or record["last_seen"]
            record["message"] = community.get("message")
            record["community_link"] = community.get("link")

        if context:
            record["noise"] = bool(context.get("seen")) or record["noise"]
            record["classification"] = context.get("classification") or record["classification"]
            record["actor"] = context.get("actor") or record["actor"]
            record["tags"] = context.get("tags") or []
            record["first_seen"] = context.get("first_seen") or record["first_seen"]
            record["last_seen"] = context.get("last_seen") or record["last_seen"]
            raw = context.get("raw_data") or {}
            scan = raw.get("scan") or []
            ports = sorted({s.get("port") for s in scan if isinstance(s, dict) and s.get("port")})
            record["raw_data"] = {
                "scan_ports": ports,
                "web_paths": (raw.get("web") or {}).get("paths") or [],
                "user_agents": (raw.get("web") or {}).get("useragents") or [],
            }

        if riot and riot.get("riot"):
            record["riot"] = True
            record["riot_info"] = {
                "category": riot.get("category"),
                "name": riot.get("name"),
                "description": riot.get("description"),
                "last_updated": riot.get("last_updated"),
                "trust_level": riot.get("trust_level"),
            }
            if record["classification"] == "unknown":
                record["classification"] = "benign"

        return ip, record

    # ---------- Rendering ----------

    def _render_ip(self, ip, rec):
        cls = (rec.get("classification") or "unknown").lower()
        if cls == "malicious":
            color = Colors.RED
        elif cls == "benign" or rec.get("riot"):
            color = Colors.GREEN
        elif rec.get("noise"):
            color = Colors.YELLOW
        else:
            color = Colors.DIM

        label = cls.upper()
        tags_bits = []
        if rec.get("noise"):
            tags_bits.append("noise")
        if rec.get("riot"):
            tags_bits.append("riot")
        tag_str = f" [{','.join(tags_bits)}]" if tags_bits else ""
        print(f" {color}{Colors.BOLD}{ip}{Colors.RESET} {color}{label}{Colors.RESET}{tag_str}")

        if rec.get("actor"):
            print_status(f"  actor: {rec['actor']}", "success")
        if rec.get("tags"):
            preview = ", ".join(rec["tags"][:6])
            more = "" if len(rec["tags"]) <= 6 else f" (+{len(rec['tags']) - 6} more)"
            print_status(f"  tags: {preview}{more}", "info")
        if rec.get("riot_info"):
            ri = rec["riot_info"]
            print_status(f"  RIOT: {ri.get('name')} ({ri.get('category')}) "
                         f"trust={ri.get('trust_level')}", "success")
        ports = rec.get("raw_data", {}).get("scan_ports") or []
        if ports:
            preview = ", ".join(str(p) for p in ports[:10])
            print_status(f"  scan ports: {preview}", "info")
        if rec.get("last_seen"):
            print_status(f"  last seen: {rec['last_seen']}", "info")
        if rec.get("community_link"):
            print_status(f"  link: {rec['community_link']}", "info")

    # ---------- Main ----------

    def run(self):
        if not self.validate():
            return False

        raw_target = self.get_option("TARGET").strip()
        mode = (self.get_option("MODE") or "auto").strip().lower()
        if mode not in VALID_MODES:
            print_status(f"MODE must be one of: {', '.join(VALID_MODES)}", "error")
            return False

        config = Config()
        key = (config.get("api_keys.greynoise") or "").strip()

        ips, bad = [], []
        for part in raw_target.split(","):
            p = part.strip()
            if not p:
                continue
            if is_valid_ip(p):
                if p not in ips:
                    ips.append(p)
            else:
                bad.append(p)
        if bad:
            print_status(f"Skipping invalid IP(s): {', '.join(bad)}", "warning")
        if not ips:
            print_status("No valid IPs supplied", "error")
            return False
        if len(ips) > MAX_IPS:
            print_status(f"Trimming to first {MAX_IPS} IPs (got {len(ips)})", "warning")
            ips = ips[:MAX_IPS]

        if mode in ("context", "riot") and not key:
            print_status(f"MODE={mode} requires an API key (config set api_keys.greynoise ...)", "error")
            return False

        header_mode = mode if mode != "auto" else ("auto+key" if key else "auto (community only)")
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  GreyNoise [{header_mode}] : {len(ips)} IP(s)")
        print(f"{'='*58}{Colors.RESET}\n")
        if not key and mode == "auto":
            print_status("No GreyNoise key - running community endpoint only", "info")

        warnings = []
        results_map = {}
        with ThreadPoolExecutor(max_workers=min(5, len(ips))) as pool:
            futures = {pool.submit(self._probe_ip, ip, mode, key, warnings): ip for ip in ips}
            for fut in as_completed(futures):
                try:
                    ip, record = fut.result()
                    results_map[ip] = record
                    self._render_ip(ip, record)
                except Exception as e:
                    warnings.append(f"{futures[fut]}: {e}")

        # ----- Stats + summary -----
        classifications = Counter()
        noise_count = riot_count = 0
        actors = Counter()
        all_tags = Counter()
        for rec in results_map.values():
            classifications[(rec.get("classification") or "unknown").lower()] += 1
            if rec.get("noise"):
                noise_count += 1
            if rec.get("riot"):
                riot_count += 1
            if rec.get("actor"):
                actors[rec["actor"]] += 1
            for t in rec.get("tags") or []:
                all_tags[t] += 1

        stats = {
            "queried": len(results_map),
            "noise_count": noise_count,
            "riot_count": riot_count,
            "malicious_count": classifications.get("malicious", 0),
            "benign_count": classifications.get("benign", 0),
            "unknown_count": classifications.get("unknown", 0),
        }

        self.results = {
            "target": raw_target,
            "ips_checked": len(results_map),
            "results": results_map,
            "stats": stats,
            "warnings": warnings,
        }

        for w in warnings:
            print_status(w, "warning")

        verdict_color = (Colors.RED if stats["malicious_count"]
                         else Colors.GREEN if stats["benign_count"] or stats["riot_count"]
                         else Colors.YELLOW if stats["noise_count"] else Colors.DIM)
        print(f"\n{Colors.BOLD}{verdict_color}{'='*58}")
        print(f"  Summary: {stats['queried']} IP(s)  "
              f"malicious={stats['malicious_count']}  benign={stats['benign_count']}  "
              f"unknown={stats['unknown_count']}")
        print(f"  noise={stats['noise_count']}  riot={stats['riot_count']}")
        print(f"{'='*58}{Colors.RESET}")
        if actors:
            top = ", ".join(f"{a} ({n})" for a, n in actors.most_common(5))
            print_status(f"Top actors: {top}", "info")
        if all_tags:
            top_t = ", ".join(f"{t} ({n})" for t, n in all_tags.most_common(5))
            print_status(f"Top tags: {top_t}", "info")
        print()
        return True
