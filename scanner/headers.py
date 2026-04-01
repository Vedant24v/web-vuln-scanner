SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS by controlling allowed content sources",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "Referrer-Policy": "Controls referrer information in requests",
    "Permissions-Policy": "Controls browser feature access",
}

def check_headers(response):
    findings = []
    present = []

    for header, description in SECURITY_HEADERS.items():
        if header not in response.headers:
            findings.append({
                "type": "Missing Security Header",
                "severity": "MEDIUM",
                "detail": f"{header} is missing — {description}"
            })
        else:
            present.append(header)

    return findings, present