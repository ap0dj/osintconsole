from abc import ABC, abstractmethod
from core.utils import print_status


class BaseModule(ABC):
    name = ""
    description = ""
    category = ""
    target_type = "domain"
    intrusive = False  # True = actively probes/attacks the target (not passive recon)
    author = "OsintConsole"
    version = "1.0"

    def __init__(self):
        self.options = {}
        self.results = {}
        self.required_options = []
        self._register_options()

    def _register_options(self):
        pass

    def add_option(self, name, value="", required=True, description=""):
        self.options[name] = {
            "value": value,
            "required": required,
            "description": description,
        }
        if required:
            self.required_options.append(name)

    def set_option(self, name, value):
        name_upper = name.upper()
        for key in self.options:
            if key.upper() == name_upper:
                self.options[key]["value"] = value
                return True
        return False

    def get_option(self, name):
        name_upper = name.upper()
        for key in self.options:
            if key.upper() == name_upper:
                return self.options[key]["value"]
        return None

    def validate(self):
        for opt_name in self.required_options:
            if not self.options.get(opt_name, {}).get("value"):
                print_status(f"Required option '{opt_name}' is not set", "error")
                return False
        return True

    @abstractmethod
    def run(self):
        pass

    def get_results(self):
        return self.results

    def api_keys_used(self):
        """The api_key names this module references in its own source, so the
        user can see what a key would unlock before running it. Derived by
        scanning the source (no per-module declaration to drift out of date)."""
        import inspect
        import re
        try:
            src = inspect.getsource(inspect.getmodule(self))
            return sorted(set(re.findall(r"api_keys\.([A-Za-z_][A-Za-z0-9_]*)", src)))
        except Exception:
            return []

    def show_info(self):
        from core.utils import Colors
        print(f"\n  {Colors.BOLD}Module:{Colors.RESET}      {self.name}")
        print(f"  {Colors.BOLD}Category:{Colors.RESET}    {self.category}")
        print(f"  {Colors.BOLD}Description:{Colors.RESET} {self.description}")
        print(f"  {Colors.BOLD}Target:{Colors.RESET}      {self.target_type}")
        print(f"  {Colors.BOLD}Author:{Colors.RESET}      {self.author}")
        print(f"  {Colors.BOLD}Version:{Colors.RESET}     {self.version}")
        keys = self.api_keys_used()
        if keys:
            from core.config import Config
            cfg = Config()
            parts = []
            for k in keys:
                is_set = bool((cfg.get(f"api_keys.{k}") or "").strip())
                mark = f"{Colors.GREEN}set{Colors.RESET}" if is_set else f"{Colors.YELLOW}not set{Colors.RESET}"
                parts.append(f"{k} ({mark})")
            print(f"  {Colors.BOLD}API keys:{Colors.RESET}    {', '.join(parts)}")
        print()

    def show_options(self):
        from core.utils import Colors, format_table
        headers = ["Option", "Value", "Required", "Description"]
        rows = []
        for name, opt in self.options.items():
            rows.append([
                name,
                opt["value"] if opt["value"] else "",
                "yes" if opt["required"] else "no",
                opt["description"],
            ])
        print(f"\n{Colors.BOLD}  Module Options ({self.name}):{Colors.RESET}\n")
        print(format_table(headers, rows))
        print()
