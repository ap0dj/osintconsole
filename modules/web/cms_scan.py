import re
from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core import http


COMMON_WP_PLUGINS = [
    "contact-form-7", "woocommerce", "yoast-seo", "wordpress-seo", "elementor",
    "akismet", "jetpack", "wordfence", "all-in-one-seo-pack", "wpforms-lite",
    "classic-editor", "really-simple-ssl", "updraftplus", "wp-super-cache",
]


class CmsScan(BaseModule):
    name = "web/cms_scan"
    description = "Detect CMS (WordPress/Joomla/Drupal) + enumerate version, users, plugins, themes"
    category = "web"
    target_type = "domain/url"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("ENUM_PLUGINS", "true", False, "Probe common WordPress plugins")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    def _get(self, url):
        try:
            return http.get(url, verify=self._verify_tls, allow_redirects=True, timeout=12)
        except Exception:
            return None

    def _detect(self, base, home_body):
        body = home_body.lower()
        if ("wp-content" in body or "wp-includes" in body
                or "/wp-json" in body or "wordpress" in body):
            return "WordPress"
        if ("/administrator" in body or 'name="generator" content="joomla'
                in body or "/media/jui/" in body or "com_content" in body):
            return "Joomla"
        if ("drupal.settings" in body or "drupal-" in body
                or "/sites/default/" in body or "x-generator" in body):
            return "Drupal"
        # header-based fallback
        return None

    def _wordpress(self, base, enum_plugins):
        data = {"users": [], "plugins": [], "themes": [], "version": None,
                "xmlrpc": False, "endpoints": []}

        home = self._get(base)
        html = home.text if home else ""

        m = re.search(r'name="generator" content="WordPress ([\d.]+)"', html)
        if m:
            data["version"] = m.group(1)
        if not data["version"]:
            readme = self._get(f"{base}/readme.html")
            if readme and readme.status_code == 200:
                rm = re.search(r"Version ([\d.]+)", readme.text)
                if rm:
                    data["version"] = rm.group(1)

        # Users via REST API
        users = self._get(f"{base}/wp-json/wp/v2/users")
        if users and users.status_code == 200:
            try:
                for u in users.json():
                    data["users"].append({"id": u.get("id"), "name": u.get("name"),
                                          "slug": u.get("slug")})
            except Exception:
                pass
        # Users via author scan
        if not data["users"]:
            for i in range(1, 4):
                r = self._get(f"{base}/?author={i}")
                if r and "/author/" in r.url:
                    slug = r.url.rstrip("/").split("/author/")[-1]
                    if slug:
                        data["users"].append({"id": i, "slug": slug})

        # Plugins/themes from HTML
        data["plugins"] = sorted(set(re.findall(r"wp-content/plugins/([^/'\"]+)", html)))
        data["themes"] = sorted(set(re.findall(r"wp-content/themes/([^/'\"]+)", html)))

        # Probe common plugins
        if enum_plugins:
            for plugin in COMMON_WP_PLUGINS:
                if plugin in data["plugins"]:
                    continue
                r = self._get(f"{base}/wp-content/plugins/{plugin}/readme.txt")
                if r and r.status_code == 200 and "=== " in (r.text or ""):
                    ver = re.search(r"Stable tag:\s*([\d.]+)", r.text)
                    data["plugins"].append(plugin + (f" ({ver.group(1)})" if ver else ""))

        # xmlrpc + login
        xml = self._get(f"{base}/xmlrpc.php")
        if xml and xml.status_code in (200, 405):
            data["xmlrpc"] = True
            data["endpoints"].append(f"{base}/xmlrpc.php")
        login = self._get(f"{base}/wp-login.php")
        if login and login.status_code == 200:
            data["endpoints"].append(f"{base}/wp-login.php")

        return data

    def _joomla(self, base):
        data = {"version": None, "endpoints": []}
        man = self._get(f"{base}/administrator/manifests/files/joomla.xml")
        if man and man.status_code == 200:
            m = re.search(r"<version>([\d.]+)</version>", man.text)
            if m:
                data["version"] = m.group(1)
        admin = self._get(f"{base}/administrator/")
        if admin and admin.status_code == 200:
            data["endpoints"].append(f"{base}/administrator/")
        return data

    def _drupal(self, base):
        data = {"version": None, "endpoints": []}
        for path in ("CHANGELOG.txt", "core/CHANGELOG.txt"):
            r = self._get(f"{base}/{path}")
            if r and r.status_code == 200:
                m = re.search(r"Drupal ([\d.]+)", r.text)
                if m:
                    data["version"] = m.group(1)
                    break
        user = self._get(f"{base}/user/login")
        if user and user.status_code == 200:
            data["endpoints"].append(f"{base}/user/login")
        return data

    def run(self):
        if not self.validate():
            return False

        base = normalize_url(self.get_option("TARGET"))
        enum_plugins = self.get_option("ENUM_PLUGINS").lower() == "true"
        self._verify_tls = self.get_option("VERIFY_TLS").lower() != "false"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  CMS Scan: {base}")
        print(f"{'='*58}{Colors.RESET}\n")

        home = self._get(base)
        if not home:
            print_status("Could not reach target", "error")
            return False

        cms = self._detect(base, home.text or "")
        # header generator fallback
        gen = home.headers.get("X-Generator", "")
        if not cms and "drupal" in gen.lower():
            cms = "Drupal"

        if not cms:
            print_status("No known CMS detected (WordPress/Joomla/Drupal)", "warning")
            self.results = {"target": base, "cms": None}
            return True

        print_status(f"CMS detected: {cms}", "success")
        details = {}
        if cms == "WordPress":
            details = self._wordpress(base, enum_plugins)
        elif cms == "Joomla":
            details = self._joomla(base)
        elif cms == "Drupal":
            details = self._drupal(base)

        if details.get("version"):
            print_status(f"Version: {details['version']}", "success")
        for u in details.get("users", []):
            print_status(f"User: {u.get('slug') or u.get('name')} (id={u.get('id')})", "warning")
        for p in details.get("plugins", []):
            print_status(f"Plugin: {p}", "info")
        for t in details.get("themes", []):
            print_status(f"Theme: {t}", "info")
        if details.get("xmlrpc"):
            print_status("xmlrpc.php enabled (brute-force/DDoS amplification risk)", "warning")

        self.results = {
            "target": base,
            "cms": cms,
            "version": details.get("version"),
            "users": details.get("users", []),
            "plugins": details.get("plugins", []),
            "themes": details.get("themes", []),
            "xmlrpc_enabled": details.get("xmlrpc", False),
            "endpoints": details.get("endpoints", []),
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  {cms} {details.get('version') or ''} | "
              f"{len(details.get('users', []))} user(s), "
              f"{len(details.get('plugins', []))} plugin(s)")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
