"""
Cookie security flag checker.
Flags cookies missing Secure, HttpOnly, or SameSite attributes.
"""
from typing import Any


def check_cookies(response) -> list[dict[str, Any]]:
    findings = []

    for cookie in response.cookies:
        issues = []

        # requests.cookies.RequestsCookieJar doesn't expose flags directly
        # We parse the Set-Cookie header from the raw response
        pass

    # Parse Set-Cookie headers from raw response headers
    set_cookie_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "getlist") else []

    # Fallback: parse from response.headers (may be comma-joined)
    if not set_cookie_headers:
        raw_cookies = response.headers.get("Set-Cookie", "")
        if raw_cookies:
            set_cookie_headers = [raw_cookies]

    for cookie_str in set_cookie_headers:
        parts = [p.strip().lower() for p in cookie_str.split(";")]
        cookie_name = cookie_str.split(";")[0].split("=")[0].strip()

        issues = []
        if "secure" not in parts:
            issues.append("Secure flag missing")
        if "httponly" not in parts:
            issues.append("HttpOnly flag missing")
        if not any(p.startswith("samesite") for p in parts):
            issues.append("SameSite attribute missing")

        if issues:
            findings.append({
                "type": "Insecure Cookie Flags",
                "severity": "MEDIUM",
                "detail": f"Cookie '{cookie_name}' has: {', '.join(issues)}",
                "evidence": cookie_str[:200],
                "remediation": (
                    f"Set the {', '.join(issues)} on the '{cookie_name}' cookie. "
                    "Example: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict"
                ),
            })

    return findings
