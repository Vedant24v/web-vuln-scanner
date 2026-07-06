"""
Exposed sensitive files checker.
Probes for publicly accessible sensitive paths.
"""
from typing import Any
from urllib.parse import urljoin
import requests


SENSITIVE_PATHS = [
    # Version control & secrets
    ("/.git/config",            "HIGH",   "Git config exposed — may reveal repository URL, credentials"),
    ("/.git/HEAD",              "HIGH",   "Git HEAD file exposed — confirms .git directory is accessible"),
    ("/.env",                   "CRITICAL","Environment file exposed — likely contains API keys, DB credentials"),
    ("/.env.local",             "CRITICAL","Local environment file exposed"),
    ("/.env.production",        "CRITICAL","Production environment file exposed"),
    ("/config.json",            "HIGH",   "Config file exposed — may contain credentials or infrastructure details"),
    ("/configuration.json",     "HIGH",   "Configuration file exposed"),
    ("/secrets.json",           "CRITICAL","Secrets file exposed"),
    ("/credentials.json",       "CRITICAL","Credentials file exposed"),

    # API docs (flag as INFO — useful for attack surface mapping)
    ("/swagger.json",           "MEDIUM", "Swagger/OpenAPI spec exposed — full API surface visible without auth"),
    ("/swagger-ui.html",        "MEDIUM", "Swagger UI exposed publicly"),
    ("/openapi.json",           "MEDIUM", "OpenAPI spec exposed publicly"),
    ("/api/docs",               "MEDIUM", "API documentation publicly accessible"),
    ("/api/swagger",            "MEDIUM", "Swagger UI accessible at /api/swagger"),
    ("/graphql",                "MEDIUM", "GraphQL endpoint publicly accessible — check introspection"),

    # Admin panels
    ("/admin",                  "MEDIUM", "Admin panel path exists — verify authentication is required"),
    ("/admin/login",            "LOW",    "Admin login page accessible"),
    ("/wp-admin",               "MEDIUM", "WordPress admin panel detected"),
    ("/wp-login.php",           "LOW",    "WordPress login page accessible"),
    ("/phpmyadmin",             "HIGH",   "phpMyAdmin panel potentially exposed"),
    ("/administrator",          "MEDIUM", "Joomla administrator panel detected"),

    # Backup files (check common extensions on common names)
    ("/backup.sql",             "CRITICAL","Database backup potentially exposed"),
    ("/db.sql",                 "CRITICAL","Database dump potentially exposed"),
    ("/backup.zip",             "HIGH",   "Site backup archive potentially exposed"),
    ("/site.zip",               "HIGH",   "Site backup archive potentially exposed"),
    ("/config.php.bak",         "HIGH",   "PHP config backup exposed"),
    ("/index.php.old",          "MEDIUM", "Old PHP file backup exposed"),
    ("/web.config.bak",         "HIGH",   "IIS web.config backup exposed"),

    # Server info
    ("/server-status",          "MEDIUM", "Apache server-status may be exposed"),
    ("/server-info",            "MEDIUM", "Apache server-info may be exposed"),
    ("/.DS_Store",              "LOW",    ".DS_Store file exposed — reveals directory structure on macOS-hosted server"),
    ("/robots.txt",             "INFO",   "robots.txt accessible — review for sensitive path disclosures"),
    ("/sitemap.xml",            "INFO",   "sitemap.xml accessible — review for path enumeration"),
]

SENSITIVE_CONTENT_SIGNATURES = [
    "DB_PASSWORD", "DB_HOST", "SECRET_KEY", "API_KEY", "AWS_ACCESS",
    "[core]", "repositoryformatversion",  # git config
    "-----BEGIN", "private key",
]


def check_exposed_files(base_url: str) -> list[dict[str, Any]]:
    findings = []
    # Normalize base_url to root
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    session = requests.Session()
    session.max_redirects = 3

    for path, severity, description in SENSITIVE_PATHS:
        target_url = urljoin(root + "/", path.lstrip("/"))
        try:
            resp = session.get(target_url, timeout=6, allow_redirects=False)

            # Only flag if we get a real 200 (not a redirect to login page)
            if resp.status_code == 200:
                snippet = resp.text[:500]

                # For INFO severity (robots.txt, sitemap), always flag
                # For others, check content length > 0 and optionally signature
                is_sensitive_content = any(
                    sig.lower() in snippet.lower() for sig in SENSITIVE_CONTENT_SIGNATURES
                )

                # Bump severity if content confirms it
                effective_severity = severity
                if is_sensitive_content and severity in ("MEDIUM", "HIGH"):
                    effective_severity = "CRITICAL"

                findings.append({
                    "type": "Exposed Sensitive File",
                    "severity": effective_severity,
                    "detail": f"{path} — {description}",
                    "evidence": f"HTTP 200 at {target_url} | Content preview: {snippet[:200]}",
                    "remediation": (
                        f"Immediately restrict access to {path} via web server configuration. "
                        "Remove or relocate the file outside the webroot, or add authentication."
                    ),
                })

            elif resp.status_code == 403:
                # 403 means it exists but is blocked — worth noting for HIGH+
                if severity in ("CRITICAL", "HIGH"):
                    findings.append({
                        "type": "Sensitive Path Exists (Access Restricted)",
                        "severity": "LOW",
                        "detail": f"{path} returns HTTP 403 — file/directory exists but access is restricted",
                        "evidence": f"HTTP 403 at {target_url}",
                        "remediation": (
                            "Confirm the restriction is enforced at all access paths. "
                            "Consider removing the file entirely rather than relying on 403."
                        ),
                    })

        except requests.RequestException:
            pass

    return findings
