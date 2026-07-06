"""
API surface discovery.
Probes for common API documentation and GraphQL endpoints exposed without authentication.
"""
from typing import Any
from urllib.parse import urljoin, urlparse
import requests

API_PATHS = [
    ("/api/docs",             "MEDIUM", "FastAPI/Swagger docs publicly accessible"),
    ("/api/swagger",          "MEDIUM", "Swagger UI accessible at /api/swagger"),
    ("/swagger.json",         "MEDIUM", "OpenAPI 2.0 spec exposed"),
    ("/swagger-ui.html",      "MEDIUM", "Swagger UI accessible"),
    ("/swagger-ui/",          "MEDIUM", "Swagger UI accessible"),
    ("/openapi.json",         "MEDIUM", "OpenAPI 3.0 spec exposed"),
    ("/openapi.yaml",         "MEDIUM", "OpenAPI 3.0 YAML spec exposed"),
    ("/v1/api-docs",          "MEDIUM", "API documentation at /v1/api-docs"),
    ("/v2/api-docs",          "MEDIUM", "API documentation at /v2/api-docs"),
    ("/v3/api-docs",          "MEDIUM", "API documentation at /v3/api-docs"),
    ("/api/v1/swagger",       "MEDIUM", "Swagger docs at API v1"),
    ("/api/v2/swagger",       "MEDIUM", "Swagger docs at API v2"),
    ("/graphql",              "MEDIUM", "GraphQL endpoint accessible — check if introspection is enabled"),
    ("/graphiql",             "HIGH",   "GraphiQL IDE publicly accessible — full schema introspectable"),
    ("/playground",           "MEDIUM", "GraphQL Playground publicly accessible"),
    ("/altair",               "MEDIUM", "Altair GraphQL client interface publicly accessible"),
    ("/api/graphql",          "MEDIUM", "GraphQL endpoint at /api/graphql"),
    ("/actuator",             "HIGH",   "Spring Boot Actuator exposed — may leak env vars, heap dumps, metrics"),
    ("/actuator/health",      "LOW",    "Spring Boot health endpoint exposed"),
    ("/actuator/env",         "CRITICAL","Spring Boot /actuator/env exposes all environment variables"),
    ("/actuator/mappings",    "MEDIUM", "Spring Boot endpoint mappings exposed"),
    ("/metrics",              "MEDIUM", "Metrics endpoint publicly accessible"),
    ("/health",               "LOW",    "Health check endpoint publicly accessible"),
    ("/.well-known/security.txt", "INFO", "security.txt present — review for disclosed security contacts"),
    ("/api",                  "INFO",   "API root accessible — review for disclosed endpoints"),
    ("/api/v1",               "INFO",   "API v1 root accessible"),
    ("/api/v2",               "INFO",   "API v2 root accessible"),
]

GRAPHQL_INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}}}"}'
GRAPHQL_INTROSPECTION_SIGNATURE = "__schema"

SWAGGER_SIGNATURES = [
    '"swagger"', '"openapi"', "swagger-ui", "SwaggerUI",
    '"paths"', '"definitions"', '"components"'
]


def _is_swagger_content(text: str) -> bool:
    text_lower = text.lower()
    return any(sig.lower() in text_lower for sig in SWAGGER_SIGNATURES)


def _is_graphql_introspectable(url: str) -> bool:
    try:
        resp = requests.post(
            url,
            json={"query": "{__schema{queryType{name}}}"},
            timeout=6,
            headers={"Content-Type": "application/json"},
        )
        return resp.status_code == 200 and GRAPHQL_INTROSPECTION_SIGNATURE in resp.text
    except Exception:
        return False


def check_api_surface(base_url: str) -> list[dict[str, Any]]:
    findings = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    session = requests.Session()
    session.max_redirects = 2

    for path, severity, description in API_PATHS:
        url = urljoin(root + "/", path.lstrip("/"))
        try:
            resp = session.get(url, timeout=6, allow_redirects=True)

            if resp.status_code not in (200, 206):
                continue

            # Extra confidence checks
            detail_suffix = ""

            if "graphql" in path.lower() or "graphiql" in path.lower():
                if _is_graphql_introspectable(url):
                    severity = "HIGH"
                    detail_suffix = " — introspection is ENABLED (full schema exposed)"
                else:
                    detail_suffix = " — introspection may be disabled"

            elif "swagger" in path.lower() or "openapi" in path.lower() or "api-docs" in path.lower():
                if not _is_swagger_content(resp.text):
                    continue  # 200 but not actually an API doc

            findings.append({
                "type": "Exposed API Surface",
                "severity": severity,
                "detail": f"{path} — {description}{detail_suffix}",
                "evidence": f"HTTP {resp.status_code} at {url} | Content-Type: {resp.headers.get('Content-Type', 'unknown')[:80]}",
                "remediation": (
                    f"Restrict access to {path} in production. "
                    "Add authentication/authorization to API documentation and admin interfaces. "
                    "Consider disabling GraphQL introspection in production."
                ),
            })

        except requests.RequestException:
            pass

    return findings
