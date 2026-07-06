"""
Directory listing exposure checker.
Checks common paths for Apache/Nginx autoindex-style directory listings.
"""
import re
from typing import Any
from urllib.parse import urljoin, urlparse
import requests

DIRECTORY_LISTING_SIGNATURES = [
    r"Index of /",
    r"<title>Index of",
    r"Directory listing for",
    r"Parent Directory</a>",
    r"\[To Parent Directory\]",
    r"<h1>Directory Listing",
]

COMMON_DIRECTORIES = [
    "/",
    "/images/",
    "/img/",
    "/assets/",
    "/static/",
    "/files/",
    "/uploads/",
    "/media/",
    "/docs/",
    "/backup/",
    "/temp/",
    "/tmp/",
    "/logs/",
    "/data/",
    "/public/",
    "/downloads/",
    "/js/",
    "/css/",
    "/fonts/",
    "/includes/",
    "/lib/",
    "/vendor/",
    "/node_modules/",
]


def _is_directory_listing(html: str) -> bool:
    for pattern in DIRECTORY_LISTING_SIGNATURES:
        if re.search(pattern, html, re.IGNORECASE):
            return True
    return False


def check_directory_listing(base_url: str) -> list[dict[str, Any]]:
    findings = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    session = requests.Session()
    session.max_redirects = 2
    checked = set()

    for dir_path in COMMON_DIRECTORIES:
        url = urljoin(root + "/", dir_path.lstrip("/"))
        if url in checked:
            continue
        checked.add(url)

        try:
            resp = session.get(url, timeout=6, allow_redirects=False)
            if resp.status_code == 200 and _is_directory_listing(resp.text):
                # Extract a few listed files as evidence
                listed_files = re.findall(r'href="([^"?#]+)"', resp.text)
                listed_files = [f for f in listed_files if not f.startswith(("http", "/", "?", "#"))][:5]

                findings.append({
                    "type": "Directory Listing Exposed",
                    "severity": "MEDIUM",
                    "detail": f"Directory listing enabled at {url}",
                    "evidence": (
                        f"HTTP 200 with directory listing at {url}. "
                        f"Sample files: {', '.join(listed_files) or 'N/A'}"
                    ),
                    "remediation": (
                        f"Disable directory indexing for {dir_path}. "
                        "Apache: add 'Options -Indexes' to .htaccess or httpd.conf. "
                        "Nginx: remove 'autoindex on' directive."
                    ),
                })
        except requests.RequestException:
            pass

    return findings
