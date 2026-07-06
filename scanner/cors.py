"""
CORS misconfiguration checker.
Flags wildcard Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials: true.
"""
from typing import Any
import requests as req_lib


def check_cors(response) -> list[dict[str, Any]]:
    findings = []

    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "").lower()

    # Wildcard ACAO with credentials is a critical misconfiguration
    if acao == "*" and acac == "true":
        findings.append({
            "type": "CORS Misconfiguration",
            "severity": "HIGH",
            "detail": (
                "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. "
                "Browsers ignore ACAC when ACAO is wildcard, but some frameworks/proxies may not — "
                "this configuration indicates a misconfigured CORS policy."
            ),
            "evidence": f"ACAO: {acao} | ACAC: {acac}",
            "remediation": (
                "Never combine wildcard ACAO with credentials. "
                "Reflect the specific allowed origin from a whitelist, or remove ACAC: true."
            ),
        })

    # Also check if ACAO reflects an arbitrary Origin (by sending a test request)
    try:
        url = response.url
        test_origin = "https://evil.example.com"
        probe = req_lib.get(url, headers={"Origin": test_origin}, timeout=8, allow_redirects=True)
        reflected_origin = probe.headers.get("Access-Control-Allow-Origin", "")
        reflected_creds = probe.headers.get("Access-Control-Allow-Credentials", "").lower()

        if reflected_origin == test_origin and reflected_creds == "true":
            findings.append({
                "type": "CORS Misconfiguration — Origin Reflection",
                "severity": "CRITICAL",
                "detail": (
                    "Server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true. "
                    "This allows any website to make authenticated cross-origin requests on behalf of users."
                ),
                "evidence": f"Sent Origin: {test_origin} → Got ACAO: {reflected_origin}, ACAC: {reflected_creds}",
                "remediation": (
                    "Maintain a strict whitelist of allowed origins. "
                    "Never reflect the incoming Origin value without validation."
                ),
            })
    except Exception:
        pass

    return findings
