"""Wappalyzer-style deep passive technology fingerprinting.

A power upgrade over web/web_tech: 100+ signatures across CMS, frameworks,
servers, CDN/WAF, analytics, JS libs, ecommerce, headless CMS, auth, monitoring,
site builders, live chat, and CDN asset providers. Each signature can declare
multiple detection vectors (HTML body, <script src>, <meta>, headers, cookies,
<link rel=icon>, robots.txt) plus implied / mutually-exclusive peers and
regex-based version extraction.
"""
import re
import time
from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core.config import Config
from core import http


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------
# Each entry supports:
#   category   : one tag used to group detections in the summary
#   website    : vendor URL (shown in output)
#   html       : list of regexes searched in the response body
#   scripts    : list of regexes searched in each <script src="...">
#   meta       : dict {meta-name: regex} matched against <meta name=...>
#   headers    : dict {header-name: regex} - header name matched case-insensitive
#   cookies    : dict {cookie-name: regex} - name matched case-insensitive
#   icon       : regex matched against <link rel=icon> href
#   robots     : list of regexes searched in /robots.txt
#   version    : regex with named group (?P<version>...) run across the full
#                page+headers to extract a version string
#   implies    : techs implied by this one (resolved up to IMPLIES_DEPTH)
#   excludes   : techs removed from the result if this one matched
#   confidence : 50-100 score reported with the detection
SIGNATURES = {
    # ------------------------------- CMS ----------------------------------
    "WordPress": {
        "category": "cms", "website": "https://wordpress.org",
        "html": [r"/wp-content/", r"/wp-includes/", r"/xmlrpc\.php"],
        "scripts": [r"/wp-content/", r"/wp-includes/js/"],
        "meta": {"generator": r"WordPress\s*(?P<version>[\d\.]+)?"},
        "headers": {"x-powered-by": r"WordPress", "link": r"wp-json"},
        "cookies": {"wordpress_logged_in_": r".*", "wp-settings-": r".*"},
        "robots": [r"/wp-admin/", r"/wp-content/"],
        "version": r"content=['\"]WordPress\s+(?P<version>[\d\.]+)",
        "confidence": 100,
    },
    "Drupal": {
        "category": "cms", "website": "https://www.drupal.org",
        "html": [r"Drupal\.settings", r"/sites/default/files/", r"drupal\.js"],
        "meta": {"generator": r"Drupal\s*(?P<version>\d+)?"},
        "headers": {"x-generator": r"Drupal\s*(?P<version>\d+)?",
                    "x-drupal-cache": r".*", "x-drupal-dynamic-cache": r".*"},
        "confidence": 100,
    },
    "Joomla": {
        "category": "cms", "website": "https://www.joomla.org",
        "html": [r"/media/jui/", r"/components/com_", r"/templates/system/"],
        "meta": {"generator": r"Joomla!?\s*-?\s*(?P<version>[\d\.]+)?"},
        "confidence": 100,
    },
    "Ghost": {
        "category": "cms", "website": "https://ghost.org",
        "html": [r"ghost-sdk", r"content=\"Ghost ", r"/ghost/api/"],
        "meta": {"generator": r"Ghost\s*(?P<version>[\d\.]+)?"},
        "confidence": 100,
    },
    "Magento": {
        "category": "cms", "website": "https://magento.com",
        "html": [r"Mage\.Cookies", r"mage-messages", r"skin/frontend/",
                 r"var\s+BLANK_URL\s*=\s*['\"]js/blank\.html"],
        "cookies": {"frontend": r".*", "mage-cache-sessid": r".*"},
        "confidence": 100,
    },
    "Shopify": {
        "category": "cms", "website": "https://www.shopify.com",
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"shopify-features"],
        "scripts": [r"cdn\.shopify\.com"],
        "headers": {"x-shopify-stage": r".*", "x-shopid": r".*",
                    "x-sorting-hat-shopid": r".*"},
        "confidence": 100,
    },
    "Wix": {
        "category": "cms", "website": "https://www.wix.com",
        "html": [r"static\.wixstatic\.com", r"wix\.com"],
        "meta": {"generator": r"Wix\.com"},
        "headers": {"x-wix-request-id": r".*", "x-wix-published-version": r".*"},
        "confidence": 100,
    },
    "Squarespace": {
        "category": "cms", "website": "https://www.squarespace.com",
        "html": [r"squarespace\.com", r"static1\.squarespace\.com",
                 r"squarespace-cdn"],
        "headers": {"server": r"Squarespace"},
        "confidence": 100,
    },
    "Webflow": {
        "category": "cms", "website": "https://webflow.com",
        "html": [r"webflow\.com", r"data-wf-page", r"\.webflow\."],
        "meta": {"generator": r"Webflow"},
        "confidence": 100,
    },
    "Umbraco": {
        "category": "cms", "website": "https://umbraco.com",
        "html": [r"/umbraco/", r"UmbracoVersion"],
        "headers": {"x-umbraco-version": r"(?P<version>[\d\.]+)"},
        "confidence": 100,
    },
    "DNN": {
        "category": "cms", "website": "https://www.dnnsoftware.com",
        "html": [r"/DesktopModules/", r"DotNetNuke", r"DNNVariable"],
        "headers": {"x-dnn-moniker": r".*"},
        "cookies": {"dnn_isMobile": r".*", ".DOTNETNUKE": r".*"},
        "confidence": 100,
    },
    "Craft CMS": {
        "category": "cms", "website": "https://craftcms.com",
        "headers": {"x-powered-by": r"Craft CMS\s*(?P<version>[\d\.]+)?"},
        "cookies": {"CraftSessionId": r".*"},
        "confidence": 100,
    },
    "TYPO3": {
        "category": "cms", "website": "https://typo3.org",
        "html": [r"typo3temp/", r"typo3conf/"],
        "meta": {"generator": r"TYPO3\s*(?P<version>[\d\.]+)?\s*CMS"},
        "confidence": 100,
    },
    "PrestaShop": {
        "category": "cms", "website": "https://www.prestashop.com",
        "html": [r"var\s+prestashop\s*=", r"/modules/prestablog/"],
        "headers": {"x-powered-by": r"PrestaShop"},
        "cookies": {"PrestaShop-": r".*"},
        "confidence": 100,
    },
    "OpenCart": {
        "category": "cms", "website": "https://www.opencart.com",
        "html": [r"catalog/view/javascript/", r"index\.php\?route=common"],
        "cookies": {"OCSESSID": r".*"},
        "confidence": 100,
    },
    "WooCommerce": {
        "category": "ecommerce", "website": "https://woocommerce.com",
        "html": [r"woocommerce", r"/plugins/woocommerce/",
                 r"wc-ajax", r"woocommerce-page"],
        "meta": {"generator": r"WooCommerce\s*(?P<version>[\d\.]+)?"},
        "implies": ["WordPress"], "confidence": 100,
    },
    "BigCommerce": {
        "category": "ecommerce", "website": "https://www.bigcommerce.com",
        "html": [r"cdn\d*\.bigcommerce\.com", r"/stencil/"],
        "headers": {"x-bc-sw-cache-status": r".*",
                    "x-bc-apigw-id": r".*"},
        "confidence": 100,
    },

    # ----------------------------- Frameworks -----------------------------
    "Django": {
        "category": "framework", "website": "https://www.djangoproject.com",
        "html": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
        "cookies": {"csrftoken": r".*", "sessionid": r".*"},
        "confidence": 90,
    },
    "Ruby on Rails": {
        "category": "framework", "website": "https://rubyonrails.org",
        "html": [r"csrf-param[\"'] content=[\"']authenticity_token",
                 r"data-turbolinks", r"data-turbo-track"],
        "headers": {"x-powered-by": r"Phusion Passenger",
                    "server": r"Phusion Passenger"},
        "cookies": {"_rails_": r".*"},
        "confidence": 95,
    },
    "Laravel": {
        "category": "framework", "website": "https://laravel.com",
        "html": [r"laravel", r"csrf-token", r"livewire"],
        "cookies": {"laravel_session": r".*", "XSRF-TOKEN": r".*"},
        "confidence": 90,
    },
    "Symfony": {
        "category": "framework", "website": "https://symfony.com",
        "headers": {"x-powered-by": r"Symfony\s*(?P<version>[\d\.]+)?",
                    "x-debug-token-link": r".*"},
        "cookies": {"sf_redirect": r".*"},
        "confidence": 100,
    },
    "Spring": {
        "category": "framework", "website": "https://spring.io",
        "headers": {"x-application-context": r".*"},
        "cookies": {"JSESSIONID": r".*"},
        "confidence": 70,
    },
    "ASP.NET": {
        "category": "framework", "website": "https://dotnet.microsoft.com",
        "headers": {"x-powered-by": r"ASP\.NET",
                    "x-aspnet-version": r"(?P<version>[\d\.]+)",
                    "x-aspnetmvc-version": r"(?P<version>[\d\.]+)"},
        "cookies": {"ASP.NET_SessionId": r".*"},
        "confidence": 100,
    },
    "Express": {
        "category": "framework", "website": "https://expressjs.com",
        "headers": {"x-powered-by": r"Express"},
        "cookies": {"connect.sid": r".*"},
        "confidence": 100,
    },
    "Flask": {
        "category": "framework", "website": "https://flask.palletsprojects.com",
        "headers": {"server": r"Werkzeug/(?P<version>[\d\.]+)?"},
        "cookies": {"session": r"^\.ey"},
        "confidence": 70,
    },
    "FastAPI": {
        "category": "framework", "website": "https://fastapi.tiangolo.com",
        "html": [r"swagger-ui", r"redoc", r"/openapi\.json"],
        "headers": {"server": r"uvicorn"},
        "confidence": 60,
    },
    "Phoenix": {
        "category": "framework", "website": "https://www.phoenixframework.org",
        "html": [r"phoenix\.js", r"PhoenixSocket"],
        "cookies": {"_phoenix_": r".*"},
        "confidence": 90,
    },
    "Gatsby": {
        "category": "framework", "website": "https://www.gatsbyjs.com",
        "html": [r"___gatsby", r"/page-data/", r"gatsby-chunk"],
        "scripts": [r"gatsby"],
        "meta": {"generator": r"Gatsby\s*(?P<version>[\d\.]+)?"},
        "implies": ["React"], "confidence": 100,
    },
    "Next.js": {
        "category": "framework", "website": "https://nextjs.org",
        "html": [r"__NEXT_DATA__", r"/_next/static", r"/_next/image"],
        "scripts": [r"/_next/static/chunks/"],
        "version": r"\"buildId\":\"[^\"]+\".*?\"nextExport\"|/_next/static/(?P<version>[\w\-\.]+)/_",
        "implies": ["React"], "confidence": 100,
    },
    "Nuxt.js": {
        "category": "framework", "website": "https://nuxt.com",
        "html": [r"window\.__NUXT__", r"/_nuxt/", r"nuxt-link"],
        "scripts": [r"/_nuxt/"],
        "implies": ["Vue.js"], "confidence": 100,
    },
    "Vue.js": {
        "category": "framework", "website": "https://vuejs.org",
        "html": [r"v-cloak", r"v-bind:", r"v-on:", r"__vue__",
                 r"vue(?:\.esm)?\.(?:min\.)?js"],
        "scripts": [r"vue(?:\.esm)?[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js"],
        "confidence": 90,
    },
    "React": {
        "category": "framework", "website": "https://react.dev",
        "html": [r"react(?:-dom)?[\.-](?P<version>[\d\.]+)?(?:\.production)?(?:\.min)?\.js",
                 r"data-reactroot", r"data-reactid", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        "scripts": [r"react(?:-dom)?[\.-](?:[\d\.]+)?(?:\.production)?(?:\.min)?\.js"],
        "confidence": 90,
    },
    "Angular": {
        "category": "framework", "website": "https://angular.io",
        "html": [r"ng-version=\"(?P<version>[\d\.]+)\"", r"ng-app",
                 r"ng-controller", r"angular(?:\.min)?\.js"],
        "confidence": 95,
    },
    "Svelte": {
        "category": "framework", "website": "https://svelte.dev",
        "html": [r"svelte-\w+", r"/_app/immutable/", r"__SVELTE"],
        "confidence": 90,
    },
    "Astro": {
        "category": "framework", "website": "https://astro.build",
        "html": [r"/_astro/", r"astro-island", r"astro:scripts"],
        "meta": {"generator": r"Astro\s*(?P<version>[\d\.]+)?"},
        "confidence": 100,
    },
    "Remix": {
        "category": "framework", "website": "https://remix.run",
        "html": [r"window\.__remixContext", r"/build/_shared/", r"remix-run"],
        "implies": ["React"], "confidence": 100,
    },
    "SolidJS": {
        "category": "framework", "website": "https://www.solidjs.com",
        "html": [r"solid-js", r"_\$HY\s*="],
        "confidence": 85,
    },
    "Qwik": {
        "category": "framework", "website": "https://qwik.builder.io",
        "html": [r"q:container", r"q:base", r"q:instance"],
        "confidence": 100,
    },

    # ------------------------------ Servers -------------------------------
    "nginx": {
        "category": "server", "website": "https://nginx.org",
        "headers": {"server": r"nginx(?:/(?P<version>[\d\.]+))?"},
        "confidence": 100,
    },
    "Apache": {
        "category": "server", "website": "https://httpd.apache.org",
        "headers": {"server": r"Apache(?:/(?P<version>[\d\.]+))?"},
        "confidence": 100,
    },
    "IIS": {
        "category": "server", "website": "https://www.iis.net",
        "headers": {"server": r"Microsoft-IIS(?:/(?P<version>[\d\.]+))?"},
        "confidence": 100,
    },
    "Caddy": {
        "category": "server", "website": "https://caddyserver.com",
        "headers": {"server": r"Caddy"},
        "confidence": 100,
    },
    "LiteSpeed": {
        "category": "server", "website": "https://www.litespeedtech.com",
        "headers": {"server": r"LiteSpeed", "x-litespeed-cache": r".*"},
        "confidence": 100,
    },
    "OpenResty": {
        "category": "server", "website": "https://openresty.org",
        "headers": {"server": r"openresty(?:/(?P<version>[\d\.]+))?"},
        "implies": ["nginx"], "confidence": 100,
    },
    "Tomcat": {
        "category": "server", "website": "https://tomcat.apache.org",
        "headers": {"server": r"Apache-Coyote|Apache Tomcat",
                    "x-powered-by": r"Servlet.*Tomcat"},
        "confidence": 100,
    },
    "Jetty": {
        "category": "server", "website": "https://www.eclipse.org/jetty/",
        "headers": {"server": r"Jetty(?:\((?P<version>[\d\.]+)\))?"},
        "confidence": 100,
    },
    "Gunicorn": {
        "category": "server", "website": "https://gunicorn.org",
        "headers": {"server": r"gunicorn(?:/(?P<version>[\d\.]+))?"},
        "confidence": 100,
    },
    "uWSGI": {
        "category": "server", "website": "https://uwsgi-docs.readthedocs.io",
        "headers": {"x-powered-by": r"uWSGI", "server": r"uWSGI"},
        "confidence": 100,
    },

    # ----------------------------- CDN / WAF ------------------------------
    "Cloudflare": {
        "category": "cdn", "website": "https://www.cloudflare.com",
        "headers": {"server": r"cloudflare", "cf-ray": r".*",
                    "cf-cache-status": r".*"},
        "cookies": {"__cfduid": r".*", "__cf_bm": r".*", "cf_clearance": r".*"},
        "confidence": 100,
    },
    "Akamai": {
        "category": "cdn", "website": "https://www.akamai.com",
        "headers": {"server": r"AkamaiGHost|AkamaiNetStorage",
                    "x-akamai-request-id": r".*",
                    "x-akamai-transformed": r".*"},
        "confidence": 100,
    },
    "Fastly": {
        "category": "cdn", "website": "https://www.fastly.com",
        "headers": {"x-served-by": r"cache-\w+", "x-fastly-request-id": r".*",
                    "fastly-debug-digest": r".*"},
        "confidence": 100,
    },
    "AWS CloudFront": {
        "category": "cdn", "website": "https://aws.amazon.com/cloudfront/",
        "headers": {"x-amz-cf-id": r".*", "x-amz-cf-pop": r".*",
                    "via": r"CloudFront"},
        "confidence": 100,
    },
    "Google Cloud CDN": {
        "category": "cdn", "website": "https://cloud.google.com/cdn",
        "headers": {"via": r"\d\.\d\s+google",
                    "x-goog-generation": r".*",
                    "x-google-backends": r".*"},
        "confidence": 90,
    },
    "Imperva": {
        "category": "cdn", "website": "https://www.imperva.com",
        "headers": {"x-iinfo": r".*", "x-cdn": r"Incapsula"},
        "cookies": {"incap_ses_": r".*", "visid_incap_": r".*"},
        "confidence": 100,
    },
    "Sucuri": {
        "category": "cdn", "website": "https://sucuri.net",
        "headers": {"server": r"Sucuri", "x-sucuri-id": r".*",
                    "x-sucuri-cache": r".*"},
        "confidence": 100,
    },
    "Vercel": {
        "category": "cdn", "website": "https://vercel.com",
        "headers": {"x-vercel-id": r".*", "x-vercel-cache": r".*",
                    "server": r"Vercel"},
        "confidence": 100,
    },
    "Netlify": {
        "category": "cdn", "website": "https://www.netlify.com",
        "headers": {"x-nf-request-id": r".*", "server": r"Netlify"},
        "confidence": 100,
    },
    "Bunny.net": {
        "category": "cdn", "website": "https://bunny.net",
        "headers": {"server": r"BunnyCDN", "cdn-pullzone": r".*",
                    "cdn-requestcountrycode": r".*"},
        "confidence": 100,
    },

    # ------------------------------ Analytics -----------------------------
    "Google Analytics": {
        "category": "analytics", "website": "https://analytics.google.com",
        "html": [r"google-analytics\.com/(?:ga|analytics|collect)",
                 r"GoogleAnalyticsObject", r"gtag/js\?id=UA-",
                 r"gtag/js\?id=G-"],
        "scripts": [r"google-analytics\.com", r"googletagmanager\.com/gtag/js"],
        "confidence": 100,
    },
    "Google Tag Manager": {
        "category": "analytics", "website": "https://tagmanager.google.com",
        "html": [r"googletagmanager\.com/gtm\.js",
                 r"googletagmanager\.com/ns\.html"],
        "scripts": [r"googletagmanager\.com/gtm\.js"],
        "confidence": 100,
    },
    "Matomo": {
        "category": "analytics", "website": "https://matomo.org",
        "html": [r"matomo\.js", r"piwik\.js", r"_paq\.push",
                 r"var\s+_paq\s*="],
        "confidence": 100,
    },
    "Mixpanel": {
        "category": "analytics", "website": "https://mixpanel.com",
        "html": [r"cdn\.mxpnl\.com", r"mixpanel\.(?:init|track)",
                 r"api\.mixpanel\.com"],
        "scripts": [r"mxpnl\.com", r"mixpanel\.com"],
        "confidence": 100,
    },
    "Amplitude": {
        "category": "analytics", "website": "https://amplitude.com",
        "html": [r"cdn\.amplitude\.com", r"amplitude\.getInstance\(",
                 r"api\.amplitude\.com"],
        "confidence": 100,
    },
    "Hotjar": {
        "category": "analytics", "website": "https://www.hotjar.com",
        "html": [r"static\.hotjar\.com", r"hjSettings", r"hj\(\)"],
        "scripts": [r"static\.hotjar\.com"],
        "confidence": 100,
    },
    "Segment": {
        "category": "analytics", "website": "https://segment.com",
        "html": [r"cdn\.segment\.(?:com|io)", r"analytics\.load\(",
                 r"analytics\.track\("],
        "scripts": [r"cdn\.segment\."],
        "confidence": 100,
    },
    "Plausible": {
        "category": "analytics", "website": "https://plausible.io",
        "html": [r"plausible\.io/js/", r"data-domain=.*plausible"],
        "scripts": [r"plausible\.io"],
        "confidence": 100,
    },
    "Fathom": {
        "category": "analytics", "website": "https://usefathom.com",
        "html": [r"usefathom\.com", r"cdn\.usefathom\.com"],
        "scripts": [r"usefathom\.com"],
        "confidence": 100,
    },
    "Umami": {
        "category": "analytics", "website": "https://umami.is",
        "html": [r"umami\.js", r"data-website-id"],
        "scripts": [r"umami"],
        "confidence": 60,
    },
    "PostHog": {
        "category": "analytics", "website": "https://posthog.com",
        "html": [r"posthog\.com/static", r"posthog\.init\(",
                 r"app\.posthog\.com"],
        "scripts": [r"posthog"],
        "confidence": 100,
    },
    "HubSpot": {
        "category": "analytics", "website": "https://www.hubspot.com",
        "html": [r"js\.hs-scripts\.com", r"js\.hubspot\.com",
                 r"hs-analytics", r"_hsq\.push"],
        "scripts": [r"hs-scripts\.com", r"hubspot\.com"],
        "confidence": 100,
    },

    # ------------------------------- JS libs ------------------------------
    "jQuery": {
        "category": "js_lib", "website": "https://jquery.com",
        "html": [r"jquery[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"jQuery\s*\(\s*(?:function|document)"],
        "scripts": [r"jquery[\.-](?:[\d\.]+)?(?:\.min)?\.js"],
        "confidence": 100,
    },
    "Lodash": {
        "category": "js_lib", "website": "https://lodash.com",
        "html": [r"lodash[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"_\.VERSION\s*="],
        "scripts": [r"lodash"],
        "confidence": 90,
    },
    "Underscore.js": {
        "category": "js_lib", "website": "https://underscorejs.org",
        "html": [r"underscore[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js"],
        "scripts": [r"underscore"],
        "confidence": 90,
    },
    "Alpine.js": {
        "category": "js_lib", "website": "https://alpinejs.dev",
        "html": [r"alpinejs[\.-]?(?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"x-data=", r"window\.Alpine"],
        "scripts": [r"alpinejs"],
        "confidence": 95,
    },
    "HTMX": {
        "category": "js_lib", "website": "https://htmx.org",
        "html": [r"htmx(?:\.org)?[\.-]?(?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"hx-get=", r"hx-post=", r"hx-trigger="],
        "scripts": [r"htmx"],
        "confidence": 100,
    },
    "Modernizr": {
        "category": "js_lib", "website": "https://modernizr.com",
        "html": [r"modernizr[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"Modernizr\."],
        "scripts": [r"modernizr"],
        "confidence": 95,
    },
    "D3": {
        "category": "js_lib", "website": "https://d3js.org",
        "html": [r"d3[\.-]v?(?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"d3\.select\("],
        "scripts": [r"d3[\.\-]"],
        "confidence": 90,
    },
    "Chart.js": {
        "category": "js_lib", "website": "https://www.chartjs.org",
        "html": [r"[Cc]hart[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"new\s+Chart\(", r"Chart\.register\("],
        "scripts": [r"chart\.js"],
        "confidence": 85,
    },
    "Lit": {
        "category": "js_lib", "website": "https://lit.dev",
        "html": [r"lit-html", r"lit-element", r"@lit/"],
        "scripts": [r"lit-"],
        "confidence": 90,
    },
    "Redux": {
        "category": "js_lib", "website": "https://redux.js.org",
        "html": [r"__REDUX_DEVTOOLS_EXTENSION__",
                 r"redux[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js"],
        "scripts": [r"redux"],
        "confidence": 90,
    },
    "MobX": {
        "category": "js_lib", "website": "https://mobx.js.org",
        "html": [r"mobx[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"__mobxDidRunLazyInitializers"],
        "scripts": [r"mobx"],
        "confidence": 90,
    },

    # -------------------------- Payments / Ecommerce ----------------------
    "Stripe": {
        "category": "payment", "website": "https://stripe.com",
        "html": [r"js\.stripe\.com", r"Stripe\(\s*['\"]pk_"],
        "scripts": [r"js\.stripe\.com"],
        "confidence": 100,
    },
    "PayPal": {
        "category": "payment", "website": "https://www.paypal.com",
        "html": [r"paypal(?:objects|\.com)/[^'\"]*", r"paypal\.com/sdk/js",
                 r"data-paypal-"],
        "scripts": [r"paypal\.com", r"paypalobjects\.com"],
        "confidence": 100,
    },
    "Snipcart": {
        "category": "payment", "website": "https://snipcart.com",
        "html": [r"cdn\.snipcart\.com", r"snipcart\.(?:init|setup)",
                 r"data-item-id="],
        "scripts": [r"snipcart\.com"],
        "confidence": 100,
    },
    "Checkout.com": {
        "category": "payment", "website": "https://www.checkout.com",
        "html": [r"cko-\w+\.js", r"checkout\.com/sdk",
                 r"CKO\.frames\.Frames"],
        "scripts": [r"checkout\.com"],
        "confidence": 100,
    },
    "Klarna": {
        "category": "payment", "website": "https://www.klarna.com",
        "html": [r"klarnacdn\.net", r"js\.klarna\.com",
                 r"klarna-onsite-service"],
        "scripts": [r"klarna"],
        "confidence": 100,
    },

    # --------------------------- Headless CMS -----------------------------
    "Strapi": {
        "category": "headless_cms", "website": "https://strapi.io",
        "headers": {"x-powered-by": r"Strapi(?:\s*<[^>]+>)?"},
        "confidence": 100,
    },
    "Contentful": {
        "category": "headless_cms", "website": "https://www.contentful.com",
        "html": [r"ctfassets\.net", r"cdn\.contentful\.com",
                 r"images\.ctfassets\.net"],
        "scripts": [r"contentful"],
        "confidence": 100,
    },
    "Sanity": {
        "category": "headless_cms", "website": "https://www.sanity.io",
        "html": [r"cdn\.sanity\.io", r"@sanity/client"],
        "scripts": [r"cdn\.sanity\.io"],
        "confidence": 100,
    },
    "Prismic": {
        "category": "headless_cms", "website": "https://prismic.io",
        "html": [r"prismic\.io", r"@prismicio/client"],
        "scripts": [r"prismic\.io"],
        "confidence": 100,
    },
    "WordPress REST API": {
        "category": "headless_cms", "website": "https://developer.wordpress.org/rest-api/",
        "html": [r"/wp-json/wp/v2/", r"<link\s+rel=['\"]https?://api\.w\.org"],
        "headers": {"link": r"wp-json/wp/v2"},
        "implies": ["WordPress"], "confidence": 95,
    },

    # ------------------------- Auth / Identity ----------------------------
    "Auth0": {
        "category": "auth", "website": "https://auth0.com",
        "html": [r"cdn\.auth0\.com", r"@auth0/auth0", r"auth0-spa-js",
                 r"\.auth0\.com/authorize"],
        "scripts": [r"auth0"],
        "confidence": 100,
    },
    "Okta": {
        "category": "auth", "website": "https://www.okta.com",
        "html": [r"okta-signin-widget", r"\.okta\.com/", r"okta\.min\.js"],
        "scripts": [r"okta"],
        "confidence": 100,
    },
    "Firebase Auth": {
        "category": "auth", "website": "https://firebase.google.com",
        "html": [r"firebase-auth", r"gstatic\.com/firebasejs",
                 r"firebaseapp\.com", r"firebase\.auth\("],
        "scripts": [r"firebasejs"],
        "confidence": 100,
    },
    "Clerk": {
        "category": "auth", "website": "https://clerk.com",
        "html": [r"clerk\.(?:dev|com|accounts\.dev)", r"@clerk/clerk-"],
        "scripts": [r"clerk\."],
        "confidence": 100,
    },
    "Keycloak": {
        "category": "auth", "website": "https://www.keycloak.org",
        "html": [r"keycloak(?:-js)?[\.-](?P<version>[\d\.]+)?(?:\.min)?\.js",
                 r"/auth/realms/"],
        "scripts": [r"keycloak"],
        "confidence": 100,
    },

    # ---------------------------- Monitoring ------------------------------
    "Sentry": {
        "category": "monitoring", "website": "https://sentry.io",
        "html": [r"browser\.sentry-cdn\.com", r"Sentry\.init\(",
                 r"window\.__SENTRY__"],
        "scripts": [r"sentry-cdn\.com", r"sentry"],
        "confidence": 100,
    },
    "Datadog RUM": {
        "category": "monitoring", "website": "https://www.datadoghq.com",
        "html": [r"datadoghq\.com/rum", r"DD_RUM\.(?:init|onReady)",
                 r"browser-agent\.rum\.us"],
        "scripts": [r"datadog"],
        "confidence": 100,
    },
    "New Relic": {
        "category": "monitoring", "website": "https://newrelic.com",
        "html": [r"NREUM(?:\.info|=)", r"js-agent\.newrelic\.com"],
        "scripts": [r"newrelic"],
        "confidence": 100,
    },
    "Bugsnag": {
        "category": "monitoring", "website": "https://www.bugsnag.com",
        "html": [r"d2wy8f7a9ursnm\.cloudfront\.net/bugsnag",
                 r"Bugsnag\.(?:start|notify)"],
        "scripts": [r"bugsnag"],
        "confidence": 100,
    },
    "Rollbar": {
        "category": "monitoring", "website": "https://rollbar.com",
        "html": [r"cdn\.rollbar\.com", r"Rollbar\.(?:init|configure)"],
        "scripts": [r"rollbar"],
        "confidence": 100,
    },

    # ----------------------------- Builders -------------------------------
    "Weebly": {
        "category": "builder", "website": "https://www.weebly.com",
        "html": [r"cdn\d*\.editmysite\.com", r"weebly\.com",
                 r"var\s+_W\s*=\s*_W"],
        "meta": {"generator": r"Weebly"},
        "confidence": 100,
    },
    "Carrd": {
        "category": "builder", "website": "https://carrd.co",
        "html": [r"carrd\.co", r"var\s+carrd\s*="],
        "meta": {"generator": r"Carrd"},
        "confidence": 100,
    },
    "Zyro": {
        "category": "builder", "website": "https://zyro.com",
        "html": [r"zyro\.com", r"assets\.zyrosite\.com"],
        "meta": {"generator": r"Zyro"},
        "confidence": 100,
    },

    # ------------------------------ Live chat -----------------------------
    "Intercom": {
        "category": "live_chat", "website": "https://www.intercom.com",
        "html": [r"widget\.intercom\.io", r"intercomSettings",
                 r"Intercom\(['\"](?:boot|update|shutdown)"],
        "scripts": [r"intercom"],
        "confidence": 100,
    },
    "Drift": {
        "category": "live_chat", "website": "https://www.drift.com",
        "html": [r"js\.driftt\.com", r"drift\.load\(", r"driftt\.com"],
        "scripts": [r"driftt?\.com"],
        "confidence": 100,
    },
    "Zendesk Chat": {
        "category": "live_chat", "website": "https://www.zendesk.com",
        "html": [r"zopim\.com", r"zdassets\.com", r"\$zopim\(",
                 r"static\.zdassets\.com"],
        "scripts": [r"zdassets\.com", r"zopim\.com"],
        "confidence": 100,
    },
    "Crisp": {
        "category": "live_chat", "website": "https://crisp.chat",
        "html": [r"client\.crisp\.chat", r"CRISP_WEBSITE_ID",
                 r"\$crisp\.push"],
        "scripts": [r"crisp\.chat"],
        "confidence": 100,
    },
    "Tawk.to": {
        "category": "live_chat", "website": "https://www.tawk.to",
        "html": [r"embed\.tawk\.to", r"Tawk_API", r"tawk\.to/chat"],
        "scripts": [r"tawk\.to"],
        "confidence": 100,
    },
    "LiveChat": {
        "category": "live_chat", "website": "https://www.livechat.com",
        "html": [r"cdn\.livechatinc\.com", r"__lc\.license",
                 r"LC_API\."],
        "scripts": [r"livechatinc\.com"],
        "confidence": 100,
    },

    # ---------------------- Fonts / Asset providers -----------------------
    "Google Fonts": {
        "category": "font", "website": "https://fonts.google.com",
        "html": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"],
        "confidence": 100,
    },
    "Adobe Fonts": {
        "category": "font", "website": "https://fonts.adobe.com",
        "html": [r"use\.typekit\.net", r"use\.edgefonts\.net"],
        "confidence": 100,
    },
    "cdnjs": {
        "category": "cdn_asset", "website": "https://cdnjs.com",
        "html": [r"cdnjs\.cloudflare\.com"],
        "scripts": [r"cdnjs\.cloudflare\.com"],
        "confidence": 100,
    },
    "jsDelivr": {
        "category": "cdn_asset", "website": "https://www.jsdelivr.com",
        "html": [r"cdn\.jsdelivr\.net"],
        "scripts": [r"cdn\.jsdelivr\.net"],
        "confidence": 100,
    },
    "unpkg": {
        "category": "cdn_asset", "website": "https://unpkg.com",
        "html": [r"unpkg\.com"],
        "scripts": [r"unpkg\.com"],
        "confidence": 100,
    },
    "Font Awesome": {
        "category": "font", "website": "https://fontawesome.com",
        "html": [r"font-?awesome", r"use\.fontawesome\.com",
                 r"fa-(?:solid|regular|brands|light)"],
        "scripts": [r"fontawesome"],
        "confidence": 95,
    },

    # ------------------------------ Build tools ---------------------------
    "Vite": {
        "category": "build_tool", "website": "https://vitejs.dev",
        "html": [r"/@vite/client", r"type=\"module\"\s+src=[\"'][^\"']*vite"],
        "confidence": 100,
    },
}


# ---------------------------------------------------------------------------
# Module implementation
# ---------------------------------------------------------------------------
CATEGORY_LABELS = {
    "cms": "CMS",
    "framework": "Framework",
    "server": "Web Server",
    "cdn": "CDN / WAF",
    "analytics": "Analytics",
    "js_lib": "JavaScript Library",
    "ecommerce": "E-commerce",
    "headless_cms": "Headless CMS",
    "auth": "Auth / Identity",
    "monitoring": "Monitoring",
    "builder": "Site Builder",
    "live_chat": "Live Chat",
    "payment": "Payment",
    "font": "Font Provider",
    "cdn_asset": "CDN Assets",
    "build_tool": "Build Tool",
}


class WappalyzerFull(BaseModule):
    name = "web/wappalyzer_full"
    description = ("Deep passive tech fingerprinting - 100+ signatures across "
                   "CMS, frameworks, servers, CDN, analytics, JS libs, ecommerce, "
                   "headless CMS, auth, monitoring, builders, chat, fonts")
    category = "web"
    target_type = "domain/url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("FETCH_ROBOTS", "true", False,
                        "Also fetch /robots.txt and match robots signatures (true/false)")
        self.add_option("FETCH_SITEMAP", "false", False,
                        "Also fetch /sitemap.xml - can be slow on large sites (true/false)")
        self.add_option("IMPLIES_DEPTH", "2", False,
                        "Levels of implied-tech resolution")
        self.add_option("VERIFY_TLS", "true", False,
                        "Verify TLS certificates (true/false)")

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _bool_opt(value, default=False):
        if value is None:
            return default
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    @staticmethod
    def _match(pattern, haystack):
        """Case-insensitive re.search that never raises."""
        if not haystack:
            return None
        try:
            return re.search(pattern, haystack, re.IGNORECASE)
        except re.error:
            return None

    @staticmethod
    def _extract_version(match, extra_regex=None, extra_haystack=""):
        """Return a version string from a match's named group, or by running
        extra_regex over extra_haystack."""
        if match is not None:
            try:
                v = match.groupdict().get("version")
                if v:
                    return v
            except (IndexError, AttributeError):
                pass
        if extra_regex and extra_haystack:
            try:
                m = re.search(extra_regex, extra_haystack, re.IGNORECASE)
                if m:
                    return m.groupdict().get("version") or m.group(0)
            except (re.error, IndexError):
                pass
        return None

    def _collect_sources(self, resp, soup):
        """Pull out the various pieces that signatures look at."""
        html = resp.text or ""
        # Case-insensitive header dict
        headers_lc = {k.lower(): v for k, v in resp.headers.items()}
        # requests exposes a CookieJar; name -> value
        try:
            cookies = {c.name: (c.value or "") for c in resp.cookies}
        except Exception:
            cookies = {}
        # Script sources
        scripts = []
        try:
            for s in soup.find_all("script", src=True):
                scripts.append(s.get("src") or "")
        except Exception:
            pass
        # Meta tags: name/property -> content
        metas = {}
        try:
            for m in soup.find_all("meta"):
                key = (m.get("name") or m.get("property") or "").lower()
                content = m.get("content") or ""
                if key:
                    metas[key] = content
        except Exception:
            pass
        # Favicon href(s)
        icons = []
        try:
            for link in soup.find_all("link", rel=True):
                rel = " ".join(link.get("rel") or []).lower()
                if "icon" in rel:
                    href = link.get("href") or ""
                    if href:
                        icons.append(href)
        except Exception:
            pass
        return {
            "html": html,
            "headers": headers_lc,
            "cookies": cookies,
            "scripts": scripts,
            "metas": metas,
            "icons": icons,
        }

    def _detect_one(self, name, sigs, sources, robots_text):
        """Run every detector in a signature. Return (evidence, version) or None."""
        version = None
        evidence = None

        # html body
        for pattern in sigs.get("html") or []:
            m = self._match(pattern, sources["html"])
            if m:
                evidence = f"html:{pattern[:60]}"
                version = version or self._extract_version(m)
                break

        # <script src=...>
        if evidence is None:
            for pattern in sigs.get("scripts") or []:
                for src in sources["scripts"]:
                    m = self._match(pattern, src)
                    if m:
                        evidence = f"script:{src[:80]}"
                        version = version or self._extract_version(m)
                        break
                if evidence:
                    break

        # <meta name=...>
        if evidence is None:
            for key, pattern in (sigs.get("meta") or {}).items():
                content = sources["metas"].get(key.lower(), "")
                m = self._match(pattern, content)
                if m:
                    evidence = f"meta:{key}={content[:60]}"
                    version = version or self._extract_version(m)
                    break

        # headers (case-insensitive name)
        if evidence is None:
            for name_h, pattern in (sigs.get("headers") or {}).items():
                val = sources["headers"].get(name_h.lower(), "")
                m = self._match(pattern, val)
                if m:
                    evidence = f"header:{name_h}={val[:80]}"
                    version = version or self._extract_version(m)
                    break

        # cookies (case-insensitive name match: any cookie whose name starts
        # with or equals the key)
        if evidence is None:
            for cname, pattern in (sigs.get("cookies") or {}).items():
                key_lc = cname.lower()
                for ck_name, ck_val in sources["cookies"].items():
                    if key_lc in ck_name.lower():
                        m = self._match(pattern, ck_val or ck_name)
                        if m:
                            evidence = f"cookie:{ck_name}"
                            version = version or self._extract_version(m)
                            break
                if evidence:
                    break

        # favicon href
        if evidence is None and sigs.get("icon"):
            for href in sources["icons"]:
                m = self._match(sigs["icon"], href)
                if m:
                    evidence = f"icon:{href[:80]}"
                    version = version or self._extract_version(m)
                    break

        # robots.txt lines
        if evidence is None and robots_text:
            for pattern in sigs.get("robots") or []:
                m = self._match(pattern, robots_text)
                if m:
                    evidence = f"robots:{pattern[:60]}"
                    version = version or self._extract_version(m)
                    break

        if evidence is None:
            return None

        # Standalone version regex, run against html + joined headers
        if version is None and sigs.get("version"):
            hay = sources["html"] + "\n" + "\n".join(
                f"{k}: {v}" for k, v in sources["headers"].items()
            )
            version = self._extract_version(None, sigs["version"], hay)

        return evidence, version

    def _resolve_implies(self, detected, depth):
        """Expand implied techs breadth-first up to `depth` levels. Added techs
        inherit the implier's category/website and lose version info."""
        if depth <= 0:
            return
        frontier = list(detected.keys())
        for _ in range(depth):
            next_frontier = []
            for tech in frontier:
                for implied in SIGNATURES.get(tech, {}).get("implies") or []:
                    if implied in detected:
                        continue
                    base = SIGNATURES.get(implied, {})
                    detected[implied] = {
                        "name": implied,
                        "category": base.get("category", "unknown"),
                        "version": None,
                        "confidence": max(50, base.get("confidence", 70) - 20),
                        "evidence": f"implied-by:{tech}",
                        "website": base.get("website", ""),
                    }
                    next_frontier.append(implied)
            if not next_frontier:
                break
            frontier = next_frontier

    def _apply_excludes(self, detected):
        for tech, info in list(detected.items()):
            if tech not in detected:  # may have been removed by a peer
                continue
            for ex in SIGNATURES.get(tech, {}).get("excludes") or []:
                detected.pop(ex, None)

    # ------------------------------------------------------------------
    # Side-channel fetchers
    # ------------------------------------------------------------------
    def _fetch(self, url, verify_tls, timeout):
        try:
            return http.get(url, timeout=timeout, verify=verify_tls,
                            allow_redirects=True)
        except Exception as e:
            self._warn(f"GET {url} failed: {e}")
            return None

    def _warn(self, msg):
        self.results.setdefault("warnings", []).append(msg)
        print_status(msg, "warning")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        target = normalize_url(self.get_option("TARGET"))
        fetch_robots = self._bool_opt(self.get_option("FETCH_ROBOTS"), True)
        fetch_sitemap = self._bool_opt(self.get_option("FETCH_SITEMAP"), False)
        verify_tls = self._bool_opt(self.get_option("VERIFY_TLS"), True)
        try:
            implies_depth = max(0, int(self.get_option("IMPLIES_DEPTH") or 2))
        except (TypeError, ValueError):
            implies_depth = 2

        config = Config()
        timeout = config.get("timeout", 10)

        self.results = {
            "target": target,
            "page_info": {},
            "detected": [],
            "by_category": {},
            "stats": {},
            "warnings": [],
        }

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 64}")
        print(f"  Wappalyzer Full - {target}")
        print(f"{'=' * 64}{Colors.RESET}\n")

        t0 = time.time()
        print_status(f"Fetching {target}", "info")
        resp = self._fetch(target, verify_tls, timeout)
        if resp is None:
            print_status("Target fetch failed - nothing to fingerprint", "error")
            self.results["stats"]["duration_sec"] = round(time.time() - t0, 2)
            return False

        try:
            soup = BeautifulSoup(resp.text or "", "html.parser")
        except Exception as e:
            self._warn(f"HTML parse error: {e}")
            soup = BeautifulSoup("", "html.parser")

        sources = self._collect_sources(resp, soup)

        title = ""
        try:
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
        except Exception:
            pass

        self.results["page_info"] = {
            "status": resp.status_code,
            "server": sources["headers"].get("server", ""),
            "content_length": len(resp.content or b""),
            "title": title,
            "final_url": resp.url,
        }
        print_status(
            f"HTTP {resp.status_code} "
            f"({self.results['page_info']['content_length']} bytes) "
            f"'{title[:70]}'",
            "info",
        )

        # robots.txt (opt-in true/false — default true)
        robots_text = ""
        if fetch_robots:
            print_status("Fetching /robots.txt", "info")
            r = self._fetch(f"{target}/robots.txt", verify_tls, timeout)
            if r is not None and r.status_code == 200 and r.text:
                robots_text = r.text
                self.results["page_info"]["robots_bytes"] = len(r.content or b"")

        # sitemap.xml (opt-in true/false — default false)
        if fetch_sitemap:
            print_status("Fetching /sitemap.xml", "info")
            r = self._fetch(f"{target}/sitemap.xml", verify_tls, timeout)
            if r is not None and r.status_code == 200 and r.text:
                sources["html"] += "\n" + r.text  # add to haystack
                self.results["page_info"]["sitemap_bytes"] = len(r.content or b"")

        # Fingerprint
        print_status(f"Running {len(SIGNATURES)} signatures", "info")
        detected = {}
        for name, sigs in SIGNATURES.items():
            try:
                hit = self._detect_one(name, sigs, sources, robots_text)
            except Exception as e:
                self._warn(f"signature '{name}' crashed: {e}")
                continue
            if not hit:
                continue
            evidence, version = hit
            detected[name] = {
                "name": name,
                "category": sigs.get("category", "unknown"),
                "version": version,
                "confidence": int(sigs.get("confidence", 80)),
                "evidence": evidence,
                "website": sigs.get("website", ""),
            }
            v = f" {version}" if version else ""
            print_status(f"Detected: {Colors.BOLD}{name}{Colors.RESET}{v} "
                         f"[{detected[name]['category']}]", "success")

        # implies / excludes
        self._resolve_implies(detected, implies_depth)
        self._apply_excludes(detected)

        # Build final structures
        detected_list = sorted(
            detected.values(),
            key=lambda x: (x["category"], x["name"].lower()),
        )
        by_category = {}
        for info in detected_list:
            by_category.setdefault(info["category"], []).append(info)

        duration = round(time.time() - t0, 2)
        self.results["detected"] = detected_list
        self.results["by_category"] = by_category
        self.results["stats"] = {
            "total_detected": len(detected_list),
            "fetched_bytes": self.results["page_info"]["content_length"],
            "duration_sec": duration,
        }

        self._print_summary(by_category, duration)
        return True

    # ------------------------------------------------------------------
    # Pretty summary
    # ------------------------------------------------------------------
    def _print_summary(self, by_category, duration):
        print()
        print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 64}")
        print(f"  Detection summary ({sum(len(v) for v in by_category.values())} "
              f"techs in {duration}s)")
        print(f"{'=' * 64}{Colors.RESET}")
        if not by_category:
            print_status("No technologies detected.", "warning")
            return
        # Stable category order: known labels first, then unknowns
        known_order = list(CATEGORY_LABELS.keys())
        ordered = [c for c in known_order if c in by_category]
        ordered += [c for c in sorted(by_category.keys()) if c not in known_order]
        for cat in ordered:
            label = CATEGORY_LABELS.get(cat, cat.title())
            items = by_category[cat]
            print(f"\n  {Colors.BOLD}{Colors.CYAN}{label}{Colors.RESET} "
                  f"({len(items)})")
            for info in items:
                ver = f" {Colors.YELLOW}v{info['version']}{Colors.RESET}" \
                    if info["version"] else ""
                conf = info["confidence"]
                conf_col = Colors.GREEN if conf >= 90 else (
                    Colors.YELLOW if conf >= 70 else Colors.DIM)
                print(f"    {Colors.GREEN}+{Colors.RESET} "
                      f"{Colors.BOLD}{info['name']}{Colors.RESET}{ver}"
                      f"  {conf_col}[{conf}%]{Colors.RESET}"
                      f"  {Colors.DIM}{info['evidence']}{Colors.RESET}")
        print()
