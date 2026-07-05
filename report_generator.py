"""
report_generator.py
----------------------
Takes the scan results (same data shown on the results page)
and generates a downloadable PDF report using reportlab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_pdf_report(results: dict) -> io.BytesIO:
    """
    Builds a PDF report from the scan results dictionary and
    returns it as an in-memory file (BytesIO) ready to send to
    the browser for download.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                             topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#1A1A1A")
    )
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"],
        textColor=colors.HexColor("#B85C00"), spaceBefore=14, spaceAfter=6
    )
    normal_style = styles["Normal"]

    elements = []

    # --- Title ---
    elements.append(Paragraph("CyberSentinel Security Scan Report", title_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Target: {results['target_url']}", normal_style))
    elements.append(Paragraph(
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        normal_style
    ))
    elements.append(Spacer(1, 16))

    # --- Risk Score ---
    risk = results["risk_report"]
    elements.append(Paragraph("Overall Risk Score", heading_style))
    elements.append(Paragraph(
        f"<b>{risk['total_score']} — {risk['severity']} Risk</b>", normal_style
    ))
    elements.append(Spacer(1, 10))

    # --- Security Headers Table ---
    header_report = results["header_report"]
    elements.append(Paragraph("Security Headers", heading_style))
    if header_report.get("error"):
        elements.append(Paragraph(f"Error: {header_report['error']}", normal_style))
    else:
        header_rows = [["Header", "Status"]]
        for item in header_report["present"]:
            header_rows.append([item["header"], "Present"])
        for item in header_report["missing"]:
            header_rows.append([item["header"], "Missing"])
        elements.append(_make_table(header_rows))
    elements.append(Spacer(1, 10))

    # --- Port Scan Table ---
    port_report = results["port_report"]
    elements.append(Paragraph("Port Scan", heading_style))
    if port_report.get("error"):
        elements.append(Paragraph(f"Error: {port_report['error']}", normal_style))
    elif port_report["open_ports"]:
        port_rows = [["Port", "Service"]]
        for item in port_report["open_ports"]:
            port_rows.append([str(item["port"]), item["service"]])
        elements.append(_make_table(port_rows))
    else:
        elements.append(Paragraph("No common ports open.", normal_style))
    elements.append(Spacer(1, 10))

    # --- Password Analysis (only if checked) ---
    password_report = results.get("password_report")
    if password_report:
        elements.append(Paragraph("Password Strength", heading_style))
        elements.append(Paragraph(
            f"Strength: <b>{password_report['strength']}</b> "
            f"({password_report['score']}/100)", normal_style
        ))
        for issue in password_report["issues"]:
            elements.append(Paragraph(f"- {issue}", normal_style))
        elements.append(Spacer(1, 10))

    # --- Broken Links Table ---
    link_report = results["link_report"]
    elements.append(Paragraph("Broken Links", heading_style))
    if link_report.get("error"):
        elements.append(Paragraph(f"Error: {link_report['error']}", normal_style))
    elif link_report["broken_links"]:
        link_rows = [["URL", "Status Code"]]
        for item in link_report["broken_links"]:
            link_rows.append([item["url"], str(item.get("status_code") or "ERROR")])
        elements.append(_make_table(link_rows))
    else:
        elements.append(Paragraph("No broken links found.", normal_style))
    elements.append(Spacer(1, 10))

    # --- Why this score ---
    elements.append(Paragraph("Why This Score?", heading_style))
    for reason in risk["reasons"]:
        elements.append(Paragraph(f"- {reason}", normal_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer


def _make_table(rows):
    """Helper: builds a simple styled table for the PDF."""
    table = Table(rows, hAlign="LEFT", colWidths=[10*cm, 5*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B2B2B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table
