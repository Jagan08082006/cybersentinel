"""
ssl_checker.py
----------------
Checks a website's SSL/TLS certificate:
  - Is HTTPS supported at all?
  - Is the certificate currently valid (not expired)?
  - How many days until it expires?
  - Who issued the certificate?
"""

import ssl
import socket
from datetime import datetime


def check_ssl_certificate(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """
    Connects to a host over HTTPS and inspects its SSL certificate.
    Returns details about validity and expiry.
    """
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0]

    result = {
        "host": clean_host,
        "has_ssl": False,
        "valid": False,
        "issuer": None,
        "expires_on": None,
        "days_until_expiry": None,
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                result["has_ssl"] = True

                # Parse issuer organization name
                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer_parts.get("organizationName", "Unknown")

                # Parse expiry date (format: 'Jun 30 23:59:59 2026 GMT')
                expiry_str = cert.get("notAfter")
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                result["expires_on"] = expiry_date.strftime("%Y-%m-%d")

                days_left = (expiry_date - datetime.utcnow()).days
                result["days_until_expiry"] = days_left
                result["valid"] = days_left > 0

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e.verify_message}"
    except socket.timeout:
        result["error"] = "Connection timed out (host may not support HTTPS)"
    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Could not connect on port 443: {str(e)}"

    return result
