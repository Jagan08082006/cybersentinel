"""
security_header.py
--------------------
Checks a website's HTTP response headers and reports which
important security headers are present or missing.
"""

import requests

# Important security headers and why each one matters
IMPORTANT_HEADERS = {
    "Content-Security-Policy": "Prevents XSS / code injection attacks",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "Strict-Transport-Security": "Forces secure HTTPS connections",
    "X-Content-Type-Options": "Prevents MIME-type sniffing attacks",
    "Referrer-Policy": "Controls how much referrer info is leaked",
    "Permissions-Policy": "Restricts use of browser features (camera, mic, etc.)",
}


def check_security_headers(url: str) -> dict:
    """
    Takes a website URL, returns which security headers are
    present and which are missing.
    """
    result = {
        "url": url,
        "reachable": False,
        "present": [],
        "missing": [],
        "error": None,
    }

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=8)
        result["reachable"] = True
        headers = response.headers

        for header_name, description in IMPORTANT_HEADERS.items():
            if header_name in headers:
                result["present"].append({
                    "header": header_name,
                    "value": headers[header_name],
                    "why_it_matters": description,
                })
            else:
                result["missing"].append({
                    "header": header_name,
                    "why_it_matters": description,
                })

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result
