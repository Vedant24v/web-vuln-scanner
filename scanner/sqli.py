import requests

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-",
    "syntax error",
    "pg_query",
]

def check_sqli(url):
    findings = []

    if "?" not in url:
        return findings

    base, params = url.split("?", 1)
    param_pairs = params.split("&")

    for payload in SQLI_PAYLOADS:
        for i, pair in enumerate(param_pairs):
            if "=" not in pair:
                continue

            key, _ = pair.split("=", 1)
            tampered = param_pairs.copy()
            tampered[i] = f"{key}={requests.utils.quote(payload)}"
            test_url = base + "?" + "&".join(tampered)

            try:
                response = requests.get(test_url, timeout=5)
                body = response.text.lower()

                for error in SQLI_ERRORS:
                    if error in body:
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "CRITICAL",
                            "detail": f"DB error detected with payload: {payload}",
                            "url": test_url
                        })
                        return findings  # Stop after first confirmed finding
            except requests.RequestException:
                pass

    return findings