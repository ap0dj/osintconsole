import os
import re
from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_url
from core.config import Config
from core import http


class Screenshot(BaseModule):
    name = "web/screenshot"
    description = "Capture a screenshot of a URL (headless Selenium if available, else thum.io)"
    category = "web"
    target_type = "url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "URL to screenshot")
        self.add_option("WIDTH", "1280", False, "Viewport width")
        self.add_option("OUTPUT_DIR", "results/screenshots", False, "Where to save the PNG")
        self.add_option("ALLOW_THIRDPARTY", "false", False,
                        "Allow the thum.io fallback (sends the target URL to a "
                        "third party — off by default for passive recon)")
        self.add_option("NO_SANDBOX", "false", False,
                        "Pass Chrome --no-sandbox (needed only when running as "
                        "root; weakens the renderer sandbox — leave false)")

    def _normalize_url(self, url):
        if not url.startswith("http"):
            url = "https://" + url
        return url

    def _safe_name(self, url):
        name = re.sub(r"[^a-zA-Z0-9]+", "_", url.replace("https://", "").replace("http://", ""))
        return name.strip("_")[:80] + ".png"

    def _try_selenium(self, url, out_path, width):
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
        except ImportError:
            return False, "selenium not installed"
        try:
            opts = Options()
            opts.add_argument("--headless=new")
            opts.add_argument("--disable-gpu")
            # --no-sandbox removes Chrome's renderer sandbox while loading an
            # untrusted target page; only enable it when the operator must run
            # as root and accepts the risk.
            if (self.get_option("NO_SANDBOX") or "false").strip().lower() == "true":
                opts.add_argument("--no-sandbox")
            opts.add_argument(f"--window-size={width},900")
            opts.add_argument(f"user-agent={Config().get('user_agent')}")
            driver = webdriver.Chrome(options=opts)
            try:
                driver.set_page_load_timeout(25)
                driver.get(url)
                driver.save_screenshot(out_path)
            finally:
                driver.quit()
            return True, "selenium"
        except Exception as e:
            return False, f"selenium failed: {e}"

    def _try_thumio(self, url, out_path, width):
        try:
            api = f"https://image.thum.io/get/width/{width}/{url}"
            resp = http.get(api, timeout=40)
            if resp.status_code == 200 and resp.content[:4] in (b"\x89PNG", b"\xff\xd8\xff\xe0"):
                with open(out_path, "wb") as f:
                    f.write(resp.content)
                return True, "thum.io"
            return False, f"thum.io status {resp.status_code}"
        except Exception as e:
            return False, f"thum.io failed: {e}"

    def _page_info(self, url):
        info = {}
        try:
            resp = http.get(url, timeout=15)
            info["status_code"] = resp.status_code
            info["final_url"] = resp.url
            title = re.search(r"<title[^>]*>(.*?)</title>", resp.text,
                              re.IGNORECASE | re.DOTALL)
            if title:
                info["title"] = title.group(1).strip()[:200]
            server = resp.headers.get("Server")
            if server:
                info["server"] = server
        except Exception:
            pass
        return info

    def run(self):
        if not self.validate():
            return False

        url = self._normalize_url(self.get_option("TARGET").strip())
        width = int(self.get_option("WIDTH") or 1280)
        out_dir = self.get_option("OUTPUT_DIR")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, self._safe_name(url))

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Screenshot: {url}")
        print(f"{'='*58}{Colors.RESET}\n")

        print_status("Fetching page info...", "info")
        info = self._page_info(url)
        if info.get("title"):
            print_status(f"Title: {info['title']}", "success")
        if info.get("status_code"):
            print_status(f"Status: {info['status_code']}", "info")

        print_status("Attempting capture (local Selenium)...", "info")
        ok, method = self._try_selenium(url, out_path, width)
        if not ok:
            allow_tp = (self.get_option("ALLOW_THIRDPARTY") or "false"
                        ).strip().lower() == "true"
            if allow_tp:
                print_status(f"Selenium unavailable ({method}); "
                             f"falling back to thum.io (sends URL off-site)",
                             "warning")
                ok, method = self._try_thumio(url, out_path, width)
            else:
                print_status(f"Selenium unavailable ({method}); thum.io fallback "
                             f"off (set ALLOW_THIRDPARTY=true to enable)", "warning")

        self.results = {
            "url": url,
            "page_info": info,
            "captured": ok,
            "method": method if ok else None,
            "screenshot_path": out_path if ok else None,
        }

        if ok:
            print_status(f"Screenshot saved: {out_path} (via {method})", "success")
        else:
            print_status(f"Capture failed: {method}", "error")

        print(f"\n{Colors.GREEN}{'='*58}{Colors.RESET}\n")
        return ok
