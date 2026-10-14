"""Continuous-monitoring module for the OSINT console.

Re-runs any registered module against a target and diffs the freshly
discovered entities (emails, IPs, domains, URLs) against the most recent
run stored in the SQLite database, reporting what is NEW or REMOVED since
last time.  The first run simply records a baseline.
"""
import json
import importlib
import time

from core.base_module import BaseModule
from core.utils import print_status, Colors, extract_entities
from core import http


def _parse_results(raw):
    """Safely turn a stored JSON results value into a dict/list."""
    if not raw:
        return {}
    if isinstance(raw, (dict, list)):
        return raw
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, (dict, list)) else {}


def _flatten_entities(entities):
    """Flatten {type: [values]} into a set of 'type:value' strings."""
    flat = set()
    for etype, values in (entities or {}).items():
        for value in values:
            flat.add(f"{etype}:{value}")
    return flat


def _plural(n, word="entity", plural="entities"):
    return f"{n} {word if n == 1 else plural}"


class Monitor(BaseModule):
    name = "monitor"
    description = "Re-run a module on a target and diff results vs the last run (new/removed entities)"
    category = "auto"
    target_type = "any"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target to monitor")
        self.add_option("MODULE", "", True, "Module to run (e.g. recon/subdomain)")
        self.add_option("REPEAT", "0", False, "Number of extra runs after the first (0 = run once)")
        self.add_option("INTERVAL", "60", False, "Seconds to wait between runs")

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        module_name = self.get_option("MODULE")

        try:
            repeat = int(self.get_option("REPEAT") or 0)
        except (ValueError, TypeError):
            repeat = 0
        try:
            interval = int(self.get_option("INTERVAL") or 60)
        except (ValueError, TypeError):
            interval = 60

        # Lazy imports to avoid circular dependencies at module-load time.
        from core.console import MODULE_REGISTRY
        from core.database import Database

        # Guard against monitoring ourselves (meaningless / would recurse).
        if module_name in (self.name, "monitor"):
            print_status("Cannot monitor the 'monitor' module itself", "error")
            return False

        # Resolve the target module from the registry.
        if module_name not in MODULE_REGISTRY:
            print_status(
                f"Module '{module_name}' is not in the registry. "
                f"Use 'modules' to list available modules.", "error")
            return False

        module_path, class_name = MODULE_REGISTRY[module_name]
        try:
            target_cls = getattr(importlib.import_module(module_path), class_name)
        except Exception as e:
            print_status(f"Failed to load module '{module_name}': {e}", "error")
            return False

        total = repeat + 1

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print("  OSINT MONITOR")
        print(f"  Target: {target}")
        print(f"  Module: {module_name}")
        if repeat > 0:
            print(f"  Runs:   {total} (interval {interval}s)")
        print(f"{'='*60}{Colors.RESET}\n")

        all_new = []
        all_removed = []

        db = Database()
        try:
            for i in range(total):
                if total > 1:
                    print(f"\n[Monitor] Run {i + 1}/{total} — {target} via {module_name}")

                # --- Fetch the previous run (baseline) BEFORE running again. ---
                prev_rows = db.get_scans(target=target, module=module_name, limit=1)
                first_run = not prev_rows
                prev_flat = set()
                if first_run:
                    print_status("No previous run found - establishing baseline", "info")
                else:
                    prev_results = _parse_results(prev_rows[0].get("results"))
                    prev_flat = _flatten_entities(extract_entities(prev_results))
                    when = (prev_rows[0].get("timestamp") or "?")[:19]
                    print_status(
                        f"Previous run from {when} ({_plural(len(prev_flat))})", "info")

                # --- Run the target module fresh. ---
                print_status(f"Running {module_name} on {target} ...", "info")
                try:
                    instance = target_cls()
                    instance.set_option("TARGET", target)
                    # Monitor exists to detect change, so it must never be
                    # served a cached response from an earlier run.
                    with http.cache_bypassed():
                        success = instance.run()
                except Exception as e:
                    print_status(f"Target module raised an error: {e}", "error")
                    return False

                if not success:
                    print_status(
                        f"Target module '{module_name}' reported failure - "
                        f"baseline left unchanged", "warning")
                    return False

                current_results = instance.get_results() or {}
                current_entities = extract_entities(current_results)
                current_flat = _flatten_entities(current_entities)

                # --- Diff against the previous run. ---
                if first_run:
                    new_entities, removed_entities = [], []
                else:
                    new_entities = sorted(current_flat - prev_flat)
                    removed_entities = sorted(prev_flat - current_flat)

                # --- Persist the fresh scan + its entities. ---
                db.save_scan(target, module_name, current_results)
                for etype, values in current_entities.items():
                    for value in values:
                        db.save_entity(target, etype, value, module_name)

                # --- Report. ---
                print(f"\n{Colors.BOLD}{Colors.CYAN}{'-'*60}")
                print("  MONITOR SUMMARY")
                print(f"{'-'*60}{Colors.RESET}")

                if first_run:
                    print_status(
                        f"Baseline recorded: {_plural(len(current_flat))}", "success")
                    for etype in ("email", "ip", "domain", "url"):
                        vals = current_entities.get(etype) or []
                        if vals:
                            print(f"   {Colors.CYAN}{etype:<7}{Colors.RESET} {len(vals)}")
                elif not new_entities and not removed_entities:
                    print_status(
                        f"No changes since last run ({_plural(len(current_flat))})", "info")
                else:
                    if new_entities:
                        print_status(f"{_plural(len(new_entities))} NEW:", "success")
                        for ent in new_entities:
                            print(f"   {Colors.GREEN}[+] {ent}{Colors.RESET}")
                    if removed_entities:
                        print_status(f"{_plural(len(removed_entities))} REMOVED:", "warning")
                        for ent in removed_entities:
                            print(f"   {Colors.YELLOW}[-] {ent}{Colors.RESET}")

                print(f"{Colors.BOLD}{Colors.CYAN}{'-'*60}{Colors.RESET}\n")

                # Accumulate across all runs.
                all_new.extend(new_entities)
                all_removed.extend(removed_entities)

                if i < total - 1:
                    print_status(f"Sleeping {interval}s before next run ...", "info")
                    time.sleep(interval)

            self.results = {
                "target": target,
                "module": module_name,
                "first_run": first_run,
                "new_entities": all_new,
                "removed_entities": all_removed,
                "total_current": len(current_flat),
            }

            if repeat > 0:
                print("[*] Tip: for persistent monitoring, run this from a scheduled task or cron job")

            return True
        finally:
            db.close()
