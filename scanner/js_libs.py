"""
JavaScript library version checker.
Parses <script src> tags, extracts version strings, flags known-outdated
versions of jQuery, Bootstrap, Angular, React, Vue, and Lodash.

IMPORTANT: This does NOT fetch a live CVE database.
           It flags versions older than the known-safe thresholds and
           instructs the user to verify manually via https://security.snyk.io
"""
import re
from typing import Any
from bs4 import BeautifulSoup


# Library name → (regex to extract version from src URL, minimum safe version, CVE notes)
KNOWN_LIBS = {
    "jquery": {
        "pattern": r"jquery[.-](\d+\.\d+\.?\d*)(\.min)?\.js",
        "safe_from": (3, 7, 0),
        "flagged_ranges": [
            ((0, 0, 0), (1, 99, 99), "jQuery <2.x is EOL with many known XSS/CSRF CVEs (CVE-2019-11358, CVE-2020-11022/23)"),
            ((2, 0, 0), (2, 99, 99), "jQuery 2.x is EOL — upgrade to 3.7+"),
            ((3, 0, 0), (3, 6, 99), "jQuery 3.0–3.6 has known CVEs (CVE-2020-11022, CVE-2020-11023) — upgrade to 3.7+"),
        ],
    },
    "bootstrap": {
        "pattern": r"bootstrap[.-](\d+\.\d+\.?\d*)(\.min)?\.(?:js|css)",
        "safe_from": (5, 3, 0),
        "flagged_ranges": [
            ((0, 0, 0), (3, 99, 99), "Bootstrap <4 is EOL with known XSS vulnerabilities"),
            ((4, 0, 0), (4, 6, 1), "Bootstrap 4.0–4.6.0 has XSS vulnerabilities in tooltip/popover (CVE-2021-23368)"),
            ((5, 0, 0), (5, 2, 99), "Bootstrap 5.0–5.2 has known vulnerabilities — upgrade to 5.3+"),
        ],
    },
    "angular": {
        "pattern": r"angular[^/]*[.-](\d+\.\d+\.?\d*)(\.min)?\.js",
        "safe_from": (18, 0, 0),
        "flagged_ranges": [
            ((0, 0, 0), (1, 99, 99), "AngularJS 1.x is EOL since Dec 2021 with multiple XSS/sandbox-escape CVEs"),
            ((2, 0, 0), (17, 99, 99), "Angular <18 may have known vulnerabilities — check https://angular.dev/reference/releases"),
        ],
    },
    "react": {
        "pattern": r"react[.-](\d+\.\d+\.?\d*)(\.min)?\.js",
        "safe_from": (18, 0, 0),
        "flagged_ranges": [
            ((0, 0, 0), (16, 8, 5), "React <16.8.6 has a known XSS vulnerability (CVE-2018-6341)"),
        ],
    },
    "vue": {
        "pattern": r"vue[.-](\d+\.\d+\.?\d*)(\.min)?\.js",
        "safe_from": (3, 4, 0),
        "flagged_ranges": [
            ((0, 0, 0), (2, 99, 99), "Vue 2.x is EOL since Dec 2023 — upgrade to Vue 3"),
            ((3, 0, 0), (3, 3, 99), "Vue 3.0–3.3 has known vulnerabilities — upgrade to 3.4+"),
        ],
    },
    "lodash": {
        "pattern": r"lodash[.-](\d+\.\d+\.?\d*)(\.min)?\.js",
        "safe_from": (4, 17, 21),
        "flagged_ranges": [
            ((0, 0, 0), (4, 17, 20), "Lodash <4.17.21 has prototype pollution CVEs (CVE-2021-23337, CVE-2020-28500)"),
        ],
    },
    "moment": {
        "pattern": r"moment[.-](\d+\.\d+\.?\d*)(\.min)?\.js",
        "safe_from": (99, 0, 0),  # Moment.js is fully deprecated
        "flagged_ranges": [
            ((0, 0, 0), (99, 99, 99), "Moment.js is deprecated — no longer maintained. Migrate to date-fns or Day.js"),
        ],
    },
}


def _parse_version(version_str: str) -> tuple[int, int, int]:
    parts = version_str.strip().split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return (0, 0, 0)


def check_js_libraries(response) -> list[dict[str, Any]]:
    findings = []

    try:
        soup = BeautifulSoup(response.text, "html.parser")
        script_tags = soup.find_all("script", src=True)
    except Exception:
        return findings

    detected: set[str] = set()

    for tag in script_tags:
        src = tag.get("src", "")
        src_lower = src.lower()

        for lib_name, config in KNOWN_LIBS.items():
            match = re.search(config["pattern"], src_lower, re.IGNORECASE)
            if not match:
                continue

            version_str = match.group(1)
            version = _parse_version(version_str)
            key = f"{lib_name}-{version_str}"
            if key in detected:
                continue
            detected.add(key)

            for range_min, range_max, cve_note in config["flagged_ranges"]:
                if range_min <= version <= range_max:
                    findings.append({
                        "type": "Outdated JavaScript Library",
                        "severity": "MEDIUM",
                        "detail": (
                            f"{lib_name.title()} v{version_str} detected via: {src[:120]}"
                        ),
                        "evidence": f"{lib_name} {version_str} — {cve_note}",
                        "remediation": (
                            f"Upgrade {lib_name.title()} to a supported version. "
                            f"Verify current CVEs at https://security.snyk.io/package/npm/{lib_name} — "
                            "do not rely solely on this automated detection."
                        ),
                    })
                    break

    return findings
