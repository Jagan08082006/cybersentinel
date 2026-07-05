"""
risk_score.py
----------------
Takes the results from all other modules (header check, port
scan, password analysis, broken links) and combines them into
ONE overall risk score + severity rating.

Scoring logic (you can adjust these numbers later):
- Each missing security header   = +8 points
- Each open risky port            = +12 points (extra for telnet/RDP)
- Weak/Very Weak password         = +20 points
- Moderate password                = +10 points
- Each broken link                = +2 points (max +20 total)
"""

RISKY_PORTS = {21, 23, 3389}  # FTP, Telnet, RDP - extra risky if open


def calculate_risk_score(header_report: dict, port_report: dict,
                          password_report: dict, link_report: dict) -> dict:
    """
    Combines all four module reports into a single risk score
    (0-100+) and a severity label.
    """
    score = 0
    reasons = []

    # --- 1. Security headers ---
    missing_headers = header_report.get("missing", []) if header_report else []
    for item in missing_headers:
        score += 8
        reasons.append(f"Missing header: {item['header']}")

    # --- 2. Open ports ---
    open_ports = port_report.get("open_ports", []) if port_report else []
    for item in open_ports:
        if item["port"] in RISKY_PORTS:
            score += 20
            reasons.append(f"High-risk open port: {item['port']} ({item['service']})")
        else:
            score += 12
            reasons.append(f"Open port: {item['port']} ({item['service']})")

    # --- 3. Password strength ---
    if password_report:
        strength = password_report.get("strength")
        if strength == "Very Weak":
            score += 25
            reasons.append("Password strength: Very Weak")
        elif strength == "Weak":
            score += 20
            reasons.append("Password strength: Weak")
        elif strength == "Moderate":
            score += 10
            reasons.append("Password strength: Moderate")
        # Strong passwords add 0

    # --- 4. Broken links ---
    broken_links = link_report.get("broken_links", []) if link_report else []
    broken_link_score = min(len(broken_links) * 2, 20)  # cap at 20
    if broken_link_score:
        score += broken_link_score
        reasons.append(f"{len(broken_links)} broken link(s) found")

    # --- Decide severity label ---
    if score >= 80:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    elif score > 0:
        severity = "Low"
    else:
        severity = "Very Low"

    return {
        "total_score": score,
        "capped_score": min(score, 100),  # used for the progress bar width (max 100%)
        "severity": severity,
        "reasons": reasons,
    }
