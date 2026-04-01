import requests

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

def check_xss(url):
    findings = []

    # Only test if URL has query parameters
    if "?" not in url:
        return findings

    base, params = url.split("?", 1)
    param_pairs = params.split("&")

    for payload in XSS_PAYLOADS:
        for i, pair in enumerate(param_pairs):
            if "=" not in pair:
                continue

            key, _ = pair.split("=", 1)
            tampered = param_pairs.copy()
            tampered[i] = f"{key}={requests.utils.quote(payload)}"
            test_url = base + "?" + "&".join(tampered)

            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "HIGH",
                        "detail": f"Payload reflected in response: {payload}",
                        "url": test_url
                    })
                    break  # One confirmed finding per param is enough
            except requests.RequestException:
                pass

    return findings