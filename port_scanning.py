"""
port_scanning.py
-------------------
Scans a target host to check which common network ports are
OPEN. Open ports can be risky if running unnecessary/outdated
services.

NOTE: Only scan systems you own or have permission to test.
"""

import socket

# Common ports + the service usually running on them
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet (insecure - should usually be closed)",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP-alt",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Tries to connect to one port. Returns True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except socket.error:
        return False


def scan_host(host: str, ports: dict = COMMON_PORTS) -> dict:
    """Scans a host across the given dictionary of ports."""
    clean_host = host.replace("https://", "").replace("http://", "").split("/")[0]

    report = {
        "host": clean_host,
        "open_ports": [],
        "closed_ports_count": 0,
        "error": None,
    }

    try:
        socket.gethostbyname(clean_host)
    except socket.gaierror:
        report["error"] = f"Could not resolve host: {clean_host}"
        return report

    for port, service in ports.items():
        if scan_port(clean_host, port):
            report["open_ports"].append({"port": port, "service": service})
        else:
            report["closed_ports_count"] += 1

    return report
