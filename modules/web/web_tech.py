import re
from bs4 import BeautifulSoup
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config
from core import http

TECH_SIGNATURES = {
    "WordPress": {
        "html": [r"wp-content", r"wp-includes", r"wp-json", r"/xmlrpc\.php"],
        "headers": {"X-Powered-By": r"WordPress"},
        "meta": {"generator": r"WordPress"},
    },
    "Joomla": {
        "html": [r"/media/jui/", r"/components/com_"],
        "headers": {},
        "meta": {"generator": r"Joomla"},
    },
    "Drupal": {
        "html": [r"Drupal\.settings", r"/sites/default/files"],
        "headers": {"X-Generator": r"Drupal", "X-Drupal-Cache": r".*"},
    },
    "React": {"html": [r"react\.production\.min\.js", r"react-dom", r"_reactRoot", r"__NEXT_DATA__"]},
    "Vue.js": {"html": [r"vue\.min\.js", r"vue\.js", r"v-bind:", r"v-on:", r"Vue\."]},
    "Angular": {"html": [r"ng-version", r"angular\.min\.js", r"ng-app", r"ng-controller"]},
    "jQuery": {"html": [r"jquery[\.-].*\.js", r"jQuery\s*\("]},
    "Bootstrap": {"html": [r"bootstrap[\.-].*\.css", r"bootstrap[\.-].*\.js"]},
    "Tailwind CSS": {"html": [r"tailwindcss", r"tailwind\.min\.css"]},
    "Nginx": {"headers": {"Server": r"nginx"}},
    "Apache": {"headers": {"Server": r"Apache"}},
    "IIS": {"headers": {"Server": r"Microsoft-IIS"}},
    "Cloudflare": {"headers": {"Server": r"cloudflare", "CF-RAY": r".*"}},
    "PHP": {"headers": {"X-Powered-By": r"PHP"}},
    "ASP.NET": {"headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".*"}},
    "Express.js": {"headers": {"X-Powered-By": r"Express"}},
    "Laravel": {"html": [r"laravel", r"csrf-token"], "headers": {}},
    "Django": {"html": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"]},
    "Ruby on Rails": {"headers": {"X-Powered-By": r"Phusion Passenger"}, "html": [r"csrf-token.*authenticity"]},
    "Next.js": {"html": [r"__NEXT_DATA__", r"_next/static"]},
    "Nuxt.js": {"html": [r"__NUXT__", r"_nuxt/"]},
    "Gatsby": {"html": [r"gatsby", r"___gatsby"]},
    "Shopify": {"html": [r"cdn\.shopify\.com", r"Shopify\.theme"]},
    "Wix": {"html": [r"wix\.com", r"X-Wix-"]},
    "Squarespace": {"html": [r"squarespace\.com", r"squarespace-cdn"]},
    "Google Analytics": {"html": [r"google-analytics\.com", r"GoogleAnalyticsObject", r"gtag/js"]},
    "Google Tag Manager": {"html": [r"googletagmanager\.com"]},
    "reCAPTCHA": {"html": [r"recaptcha", r"g-recaptcha"]},
}

# Expanded signatures for the modern web stack. Keys use "html" (not "body") to
# match the existing detection loop's expected key. .update() will overwrite any
# older entries of the same name with the newer markers (e.g. Shopify, Gatsby).
EXTRA_TECH = {
    # Modern frameworks
    "Vite": {"html": [r'/@vite/client', r'vite\.config'], "headers": {}},
    "Svelte/SvelteKit": {"html": [r'window\.__SVELTE', r'svelte-\w+', r'/_app/immutable/']},
    "SolidJS": {"html": [r'solid-js', r'_\$HY']},
    "Astro": {"html": [r'astro-island', r'/_astro/', r'astro:'], "headers": {}},
    "Remix": {"html": [r'window\.__remixContext', r'/build/_shared/']},
    "Qwik": {"html": [r'q:container', r'q:base']},
    "Alpine.js": {"html": [r'alpine\.js', r'x-data=', r'window\.Alpine']},
    "Lit": {"html": [r'lit-html', r'lit-element']},
    # Latest Next/Nuxt/Gatsby markers (newer builds)
    "Next.js 13+": {"html": [r'/_next/static/chunks/app/', r'__NEXT_DATA__', r'next/font']},
    "Nuxt 3": {"html": [r'nuxt-link', r'window\.__NUXT__']},
    "Gatsby": {"html": [r'___gatsby', r'/page-data/']},
    # Headless CMS
    "Strapi": {"html": [], "headers": {"x-powered-by": r"strapi"}},
    "Sanity.io": {"html": [r'cdn\.sanity\.io']},
    "Contentful": {"html": [r'ctfassets\.net']},
    # eCommerce
    "Shopify": {"html": [r'Shopify\.theme', r'/cdn\.shopify\.com'],
                "headers": {"x-shopify-stage": r".*"}},
    "Magento": {"html": [r'Mage\.Cookies', r'mage-messages'], "headers": {}},
    "PrestaShop": {"html": [r'prestashop'], "headers": {"x-powered-by": r"PrestaShop"}},
    # Servers
    "Caddy": {"html": [], "headers": {"server": r"Caddy"}},
    "OpenResty": {"html": [], "headers": {"server": r"openresty"}},
    "LiteSpeed": {"html": [], "headers": {"server": r"LiteSpeed"}},
    "HAProxy": {"html": [], "headers": {"server": r"haproxy"}},
    # Analytics / CDN / Monitoring (passive)
    "Datadog RUM": {"html": [r'datadoghq\.com/rum']},
    "Sentry": {"html": [r'sentry-cdn\.com', r'window\.Sentry']},
    "PostHog": {"html": [r'posthog\.com/static/']},
    "Mixpanel": {"html": [r'mixpanel\.com/track']},
    # Modern CDN
    "Vercel Edge": {"html": [],
                    "headers": {"x-vercel-id": r".*", "x-vercel-cache": r".*"}},
    "Netlify Edge": {"html": [], "headers": {"x-nf-request-id": r".*"}},
    "Cloudflare Workers": {"html": [], "headers": {"cf-worker": r".*"}},
}
TECH_SIGNATURES.update(EXTRA_TECH)


class WebTech(BaseModule):
    name = "web/web_tech"
    description = "Web technology detection - frameworks, CMS, libraries, servers"
    category = "web"
    target_type = "domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        config = Config()
        print_status(f"Detecting technologies on {target}", "info")

        try:
            # verify=False intentional: fingerprinting must work on internal/broken-TLS targets too
            resp = http.get(
                target,
                timeout=config.get("timeout", 10),
                verify=False,
            )
        except Exception as e:
            print_status(f"Failed to connect: {e}", "error")
            return False

        html = resp.text
        headers = resp.headers
        detected = {}

        soup = BeautifulSoup(html, "html.parser")

        for tech, sigs in TECH_SIGNATURES.items():
            found = False
            evidence = []

            if "html" in sigs:
                for pattern in sigs["html"]:
                    if re.search(pattern, html, re.IGNORECASE):
                        found = True
                        evidence.append(f"HTML pattern: {pattern}")
                        break

            if "headers" in sigs:
                for header, pattern in sigs["headers"].items():
                    val = headers.get(header, "")
                    if val and re.search(pattern, val, re.IGNORECASE):
                        found = True
                        evidence.append(f"Header: {header}={val}")

            if "meta" in sigs:
                for attr, pattern in sigs["meta"].items():
                    meta_tag = soup.find("meta", attrs={"name": attr})
                    if meta_tag:
                        content = meta_tag.get("content", "")
                        if re.search(pattern, content, re.IGNORECASE):
                            found = True
                            evidence.append(f"Meta: {attr}={content}")

            if found:
                detected[tech] = evidence
                print_status(f"Detected: {tech}", "success")

        scripts = []
        for script in soup.find_all("script", src=True):
            scripts.append(script["src"])

        stylesheets = []
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href", "")
            if href:
                stylesheets.append(href)

        meta_info = {}
        for meta in soup.find_all("meta"):
            name = meta.get("name", meta.get("property", ""))
            content = meta.get("content", "")
            if name and content:
                meta_info[name] = content

        self.results = {
            "target": target,
            "status_code": resp.status_code,
            "detected_technologies": detected,
            "external_scripts": scripts[:20],
            "stylesheets": stylesheets[:20],
            "meta_tags": meta_info,
            "page_title": soup.title.string.strip() if soup.title and soup.title.string else "",
        }

        print_status(f"Detection complete. Found {len(detected)} technologies", "info")
        return True
