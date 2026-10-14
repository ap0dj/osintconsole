import json
from core.base_module import BaseModule
from core.utils import print_status, Colors, normalize_url
from core import http


API_PATHS = [
    "swagger.json", "swagger/v1/swagger.json", "swagger-ui.html", "swagger",
    "openapi.json", "openapi.yaml", "api-docs", "v2/api-docs", "v3/api-docs",
    "api/swagger.json", "api/openapi.json", "api/api-docs", "api/docs",
    "docs", "redoc", "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
    "graphiql", "api/graphql", "v1/graphql", "query", "api/swagger-ui.html",
    ".well-known/openapi", "actuator", "actuator/mappings", "wp-json",
    "api/health", "healthz", "metrics",
]

GRAPHQL_PATHS = ["graphql", "api/graphql", "v1/graphql", "query", "graphiql"]

INTROSPECTION_QUERY = {"query": "{__schema{queryType{name} types{name kind}}}"}


class ApiDiscovery(BaseModule):
    name = "web/api_discovery"
    description = "Discover API endpoints - Swagger/OpenAPI specs, GraphQL (+ introspection), actuators"
    category = "web"
    target_type = "domain/url"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target URL or domain")
        self.add_option("VERIFY_TLS", "true", False, "Validate TLS certs; set to 'false' to probe hosts with broken/self-signed certs")

    def _classify(self, path, resp):
        ctype = resp.headers.get("Content-Type", "").lower()
        body = resp.text or ""
        snippet = body[:3000].lower()
        if "swagger" in snippet or '"openapi"' in snippet or "swagger-ui" in snippet:
            return "OpenAPI/Swagger"
        if '"paths"' in snippet and ('"swagger"' in snippet or '"openapi"' in snippet):
            return "OpenAPI spec"
        if "graphiql" in snippet or "graphql" in path:
            return "GraphQL"
        if "actuator" in path or "mappings" in snippet:
            return "Spring Actuator"
        if "wp-json" in path or '"routes"' in snippet:
            return "WordPress REST"
        if "json" in ctype:
            return "JSON API"
        return "endpoint"

    def _check_graphql_introspection(self, base):
        results = []
        for path in GRAPHQL_PATHS:
            url = f"{base}/{path}"
            try:
                resp = http.post(url, json=INTROSPECTION_QUERY, verify=self._verify_tls,
                                 allow_redirects=False, timeout=10)
                if resp.status_code == 200 and "__schema" in (resp.text or ""):
                    results.append({"url": url, "introspection": True})
                    print_status(f"GraphQL introspection ENABLED: {url}", "warning")
            except Exception:
                pass
        return results

    def run(self):
        if not self.validate():
            return False

        base = normalize_url(self.get_option("TARGET"))
        self._verify_tls = self.get_option("VERIFY_TLS").lower() != "false"

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  API Discovery: {base}")
        print(f"{'='*58}{Colors.RESET}\n")

        found = []
        for path in API_PATHS:
            url = f"{base}/{path}"
            try:
                resp = http.get(url, verify=self._verify_tls, allow_redirects=True, timeout=10)
                if resp.status_code in (200, 401, 403):
                    ctype = resp.headers.get("Content-Type", "")
                    is_html = "text/html" in ctype.lower()
                    kind = self._classify(path, resp)
                    # A 200 HTML response that matched no real API signature
                    # (kind falls back to "endpoint") is just a normal web page
                    # or soft-404 - not an API. Only keep HTML 200s that a
                    # signature positively identified (Swagger UI, GraphiQL,
                    # Actuator, WP REST, ...). Protected 401/403 are kept as a
                    # real "endpoint exists" signal.
                    if resp.status_code == 200 and is_html and kind == "endpoint":
                        continue
                    entry = {"url": url, "status": resp.status_code,
                             "type": kind, "content_type": ctype}
                    found.append(entry)
                    status = "warning" if resp.status_code == 200 else "info"
                    print_status(f"[{resp.status_code}] {kind}: {url}", status)
            except Exception:
                pass

        print_status("Testing GraphQL introspection...", "info")
        graphql = self._check_graphql_introspection(base)

        self.results = {
            "target": base,
            "endpoints_found": found,
            "endpoints_count": len(found),
            "graphql_introspection": graphql,
        }

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  {len(found)} API endpoint(s) discovered")
        if graphql:
            print(f"  {len(graphql)} GraphQL endpoint(s) with introspection enabled")
        print(f"{'='*58}{Colors.RESET}\n")

        return True
