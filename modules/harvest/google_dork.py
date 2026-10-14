import requests
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config

DORK_TEMPLATES = {
    "Sensitive Files": [
        'site:{target} filetype:pdf',
        'site:{target} filetype:doc OR filetype:docx',
        'site:{target} filetype:xls OR filetype:xlsx',
        'site:{target} filetype:ppt OR filetype:pptx',
        'site:{target} filetype:txt',
        'site:{target} filetype:csv',
        'site:{target} filetype:log',
        'site:{target} filetype:bak',
        'site:{target} filetype:sql',
        'site:{target} filetype:xml',
        'site:{target} filetype:json',
        'site:{target} filetype:conf OR filetype:config',
    ],
    "Login Pages": [
        'site:{target} inurl:login',
        'site:{target} inurl:admin',
        'site:{target} inurl:signin',
        'site:{target} inurl:auth',
        'site:{target} intitle:"login"',
        'site:{target} intitle:"admin panel"',
        'site:{target} inurl:dashboard',
        'site:{target} inurl:panel',
        'site:{target} inurl:wp-admin',
        'site:{target} inurl:administrator',
    ],
    "Sensitive Information": [
        'site:{target} "password" filetype:txt',
        'site:{target} "username" "password"',
        'site:{target} "api_key" OR "apikey" OR "api-key"',
        'site:{target} "secret" OR "token" filetype:json',
        'site:{target} "BEGIN RSA PRIVATE KEY"',
        'site:{target} "AWS_ACCESS_KEY"',
        'site:{target} inurl:.env',
        'site:{target} inurl:config.php',
        'site:{target} "DB_PASSWORD" OR "DB_USER"',
        'site:{target} intitle:"index of"',
    ],
    "Exposed Directories": [
        'site:{target} intitle:"index of /"',
        'site:{target} intitle:"index of" "parent directory"',
        'site:{target} intitle:"index of" ".git"',
        'site:{target} inurl:"/backup"',
        'site:{target} inurl:"/uploads"',
        'site:{target} inurl:"/temp" OR inurl:"/tmp"',
    ],
    "Error Messages": [
        'site:{target} "SQL syntax" OR "mysql_fetch"',
        'site:{target} "Warning:" "on line"',
        'site:{target} "Fatal error"',
        'site:{target} "Stack Trace" OR "Traceback"',
        'site:{target} "Server Error in" "Application"',
        'site:{target} intext:"Error 500"',
    ],
    "Subdomains & URLs": [
        'site:*.{target}',
        'site:*.*.{target}',
        'site:{target} -www',
    ],
    "Technology Detection": [
        'site:{target} inurl:wp-content',
        'site:{target} "powered by" OR "built with"',
        'site:{target} inurl:phpinfo',
        'site:{target} inurl:server-status',
        'site:{target} inurl:server-info',
    ],
    "Email & Contact": [
        'site:{target} intext:"@{target}"',
        'site:{target} "email" "contact"',
        '"{target}" email filetype:csv OR filetype:txt',
    ],
}


class GoogleDork(BaseModule):
    name = "harvest/google_dork"
    description = "Google dork query generator for OSINT reconnaissance"
    category = "harvest"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain")
        self.add_option("CATEGORY", "all", False, "Dork category: all, files, login, sensitive, dirs, errors, subdomains, tech, email")
        self.add_option("EXECUTE", "false", False, "Execute dorks via Bing (true/false)")

    def _execute_dork_bing(self, query):
        config = Config()
        try:
            resp = requests.get(
                f"https://www.bing.com/search?q={query}",
                headers={"User-Agent": config.get("user_agent")},
                timeout=10,
            )
            if resp.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")
                results = []
                for li in soup.find_all("li", class_="b_algo"):
                    link = li.find("a")
                    if link:
                        results.append({
                            "title": link.text,
                            "url": link.get("href", ""),
                        })
                return results
        except Exception:
            pass
        return []

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        category = self.get_option("CATEGORY") or "all"
        execute = self.get_option("EXECUTE").lower() == "true"

        print_status(f"Generating Google dorks for {target}", "info")

        category_map = {
            "files": "Sensitive Files",
            "login": "Login Pages",
            "sensitive": "Sensitive Information",
            "dirs": "Exposed Directories",
            "errors": "Error Messages",
            "subdomains": "Subdomains & URLs",
            "tech": "Technology Detection",
            "email": "Email & Contact",
        }

        generated = {}
        search_results = {}

        for cat_name, dorks in DORK_TEMPLATES.items():
            if category != "all" and cat_name != category_map.get(category, category):
                continue

            cat_dorks = []
            for dork_template in dorks:
                dork = dork_template.format(target=target)
                cat_dorks.append(dork)
                print_status(f"[{cat_name}] {dork}", "info")

                if execute:
                    results = self._execute_dork_bing(dork)
                    if results:
                        search_results[dork] = results
                        for r in results:
                            print_status(f"  -> {r['url']}", "success")

            generated[cat_name] = cat_dorks

        total_dorks = sum(len(d) for d in generated.values())
        self.results = {
            "target": target,
            "total_dorks": total_dorks,
            "dorks": generated,
            "search_results": search_results if execute else "Not executed (set EXECUTE=true)",
        }

        print_status(f"Generated {total_dorks} dork queries across {len(generated)} categories", "info")
        return True
