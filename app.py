"""
app.py
--------
Main Flask application. This is the file you RUN.

Features:
  1. User login/registration (accounts stored in a local SQLite database)
  2. Security header check
  3. Port scan
  4. Broken link check
  5. SSL/HTTPS certificate check
  6. Password strength analysis (+ AI-suggested strong password if weak)
  7. Combined risk score
  8. Scan history (saved per logged-in user)
  9. PDF report download
"""

import json
from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash

from security_header import check_security_headers
from port_scanning import scan_host
from password_analysis import analyze_password
from broken_link import check_broken_links
from ssl_checker import check_ssl_certificate
from risk_score import calculate_risk_score
from report_generator import generate_pdf_report
from ai_password_suggester import suggest_strong_password
import database as db
from auth import hash_password, verify_password, login_required

app = Flask(__name__)
app.secret_key = "change-this-to-something-random-and-secret"  # needed for login sessions

db.init_db()

# Keeps the most recently VIEWED scan results in memory so the
# "Download PDF Report" button can use them without re-scanning.
last_scan_results = None


# --------------------------------------------------------------
# AUTH ROUTES
# --------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", error=None)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if len(username) < 3:
        return render_template("register.html", error="Username must be at least 3 characters.")
    if len(password) < 8:
        return render_template("register.html", error="Password must be at least 8 characters.")

    success = db.create_user(username, hash_password(password))
    if not success:
        return render_template("register.html", error="That username is already taken.")

    flash("Account created! Please log in.")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    user = db.get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        return render_template("login.html", error="Invalid username or password.")

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------
# MAIN SCANNER ROUTES (login required)
# --------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "GET":
        return render_template("index.html", results=None, error=None)

    target_url = request.form.get("target_url", "").strip()
    password = request.form.get("password", "").strip()

    if not target_url:
        return render_template("index.html", results=None, error="Please enter a website URL to scan.")

    # Run each scanning module
    header_report = check_security_headers(target_url)
    port_report = scan_host(target_url)
    link_report = check_broken_links(target_url)
    ssl_report = check_ssl_certificate(target_url)

    password_report = None
    ai_suggestion = None
    if password:
        password_report = analyze_password(password)
        # If the password is anything other than "Strong", ask AI for a better one
        if password_report["strength"] != "Strong":
            ai_suggestion = suggest_strong_password(password, password_report["strength"])

    risk_report = calculate_risk_score(header_report, port_report, password_report, link_report)

    results = {
        "target_url": target_url,
        "header_report": header_report,
        "port_report": port_report,
        "password_report": password_report,
        "ai_suggestion": ai_suggestion,
        "link_report": link_report,
        "ssl_report": ssl_report,
        "risk_report": risk_report,
    }

    global last_scan_results
    last_scan_results = results

    # Save this scan into the logged-in user's history
    db.save_scan(
        user_id=session["user_id"],
        target_url=target_url,
        risk_score=risk_report["total_score"],
        severity=risk_report["severity"],
        results=results,
    )

    return render_template("index.html", results=results, error=None)


@app.route("/download-report")
@login_required
def download_report():
    """Generates a PDF from the most recent scan and sends it to the browser."""
    if last_scan_results is None:
        return "No scan results available yet. Please run a scan first.", 400

    try:
        pdf_buffer = generate_pdf_report(last_scan_results)
    except Exception as e:
        return f"Could not generate PDF: {str(e)}", 500

    safe_name = last_scan_results["target_url"].replace("://", "_").replace("/", "_").replace(":", "_")
    filename = f"security_report_{safe_name}.pdf"

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


@app.route("/history")
@login_required
def history():
    scans = db.get_scan_history(session["user_id"])
    return render_template("history.html", scans=scans)


@app.route("/history/<int:scan_id>")
@login_required
def history_detail(scan_id):
    scan = db.get_scan_by_id(scan_id, session["user_id"])
    if not scan:
        return "Scan not found.", 404

    global last_scan_results
    last_scan_results = scan["results"]

    return render_template("index.html", results=scan["results"], error=None, viewing_history=True)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
