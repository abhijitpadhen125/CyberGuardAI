from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    session,
    flash,
    send_file
)

from functools import wraps
import os
import secrets
from html import escape

import database
import auth

from scanner import get_device_info
from security_checker import check_security
from risk_engine import calculate_risk
from ai_agent import analyze
from vulnerability_database import enrich_findings

# =========================================================
# SOFTWARE VULNERABILITY MODULE
# =========================================================

from vulnerability_scanner import scan_installed_software


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "CyberGuardAI-2026-Change-This-To-A-Long-Random-Secret-Key"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# =========================================================
# CSRF TOKEN SUPPORT
# =========================================================

@app.context_processor
def inject_csrf_token():

    def csrf_token():

        token = session.get("_csrf_token")

        if not token:

            token = secrets.token_hex(32)

            session["_csrf_token"] = token

        return token

    return {
        "csrf_token": csrf_token
    }


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

try:

    database.init_db()
    database.init_remediation_table()
    database.init_alerts_table()
    auth.init_users_db()

    print("Database initialization successful.")

except Exception as error:

    print(
        "DATABASE INITIALIZATION ERROR:",
        error
    )


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    try:

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        return redirect(
            url_for("dashboard")
        )

    except Exception as error:

        return error_page(
            "HOME PAGE ERROR",
            error
        )


# =========================================================
# SIGNUP
# =========================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    try:

        if request.method == "POST":

            username = request.form.get(
                "username",
                ""
            ).strip()

            password = request.form.get(
                "password",
                ""
            )

            success, message = auth.create_user(
                username,
                password
            )

            if success:

                flash(
                    "Account created successfully. Please login.",
                    "success"
                )

                return redirect(
                    url_for("login")
                )

            flash(
                message,
                "error"
            )

        return render_template(
            "signup.html"
        )

    except Exception as error:

        print(
            "SIGNUP ERROR:",
            error
        )

        return error_page(
            "SIGNUP PAGE ERROR",
            error
        )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    try:

        if request.method == "POST":

            username = request.form.get(
                "username",
                ""
            ).strip()

            password = request.form.get(
                "password",
                ""
            )

            user = auth.verify_user(
                username,
                password
            )

            if user:

                session.clear()

                session["user_id"] = user[0]

                session["username"] = user[1]

                return redirect(
                    url_for("dashboard")
                )

            flash(
                "Invalid username or password.",
                "error"
            )

        return render_template(
            "login.html"
        )

    except Exception as error:

        print(
            "LOGIN ERROR:",
            error
        )

        return error_page(
            "LOGIN PAGE ERROR",
            error
        )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout",
    methods=["GET", "POST"]
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    try:

        user_id = session.get(
            "user_id"
        )

        scans = database.get_scan_history(
            user_id
        )

        severity_counts = database.get_severity_counts(
            user_id
        )

        risk_trend = database.get_risk_trend(
            user_id
        )

        remediation_summary = database.get_remediation_summary(
            user_id
        )

        remediation_progress = database.get_remediation_progress(
            user_id
        )

        alerts = database.get_alerts(
            user_id
        )

        unread_alert_count = database.get_unread_alert_count(
            user_id
        )

        total_scans = len(scans)

        total_findings = sum(
            severity_counts.values()
        )

        recent_scans = scans[:5]

        return render_template(
            "dashboard.html",

            username=session.get(
                "username",
                "User"
            ),

            scans=scans,

            recent_scans=recent_scans,

            total_scans=total_scans,

            total_findings=total_findings,

            severity_counts=severity_counts,

            risk_trend=risk_trend,

            remediation_summary=remediation_summary,

            remediation_progress=remediation_progress,

            alerts=alerts,

            unread_alert_count=unread_alert_count
        )

    except Exception as error:

        print(
            "DASHBOARD ERROR:",
            error
        )

        return error_page(
            "DASHBOARD ERROR",
            error
        )


# =========================================================
# SECURITY SCAN
# =========================================================

@app.route(
    "/scan",
    methods=["GET", "POST"]
)
@login_required
def scan():

    if request.method == "GET":

        try:

            return render_template(
                "scan.html"
            )

        except Exception as error:

            return error_page(
                "SCAN PAGE ERROR",
                error
            )

    try:

        user_id = session.get(
            "user_id"
        )

        print("=" * 70)

        print(
            "CYBERGUARD AI SECURITY SCAN STARTED"
        )

        print("=" * 70)

        # =================================================
        # 1. DEVICE INFORMATION
        # =================================================

        device = get_device_info()

        print(
            "Device information collected."
        )

        # =================================================
        # 2. NORMAL SECURITY CHECKS
        # =================================================

        findings = check_security()

        print(
            "Security findings:",
            len(findings)
        )

        # =================================================
        # 3. CVE ENRICHMENT FOR NORMAL FINDINGS
        # =================================================

        try:

            findings = enrich_findings(
                findings
            )

            print(
                "CVE enrichment completed."
            )

        except Exception as error:

            print(
                "CVE enrichment error:",
                error
            )

        # =================================================
        # 4. INSTALLED SOFTWARE VULNERABILITY SCAN
        # =================================================

        software_findings = []

        software_results = []

        software_risk_score = 0

        software_risk_level = "LOW"

        try:

            print()
            print(
                "=" * 70
            )

            print(
                "STARTING INSTALLED SOFTWARE VULNERABILITY SCAN"
            )

            print(
                "=" * 70
            )

            (
                software_results,
                software_risk_score,
                software_risk_level
            ) = scan_installed_software()

            print(
                "Software vulnerability scan completed."
            )

            print(
                "Possible software CVE matches:",
                len(software_results)
            )

            print(
                "Software Risk Score:",
                software_risk_score
            )

            print(
                "Software Risk Level:",
                software_risk_level
            )

            # =================================================
            # 5. CONVERT SOFTWARE RESULTS INTO FINDINGS
            # =================================================

            for result in software_results:

                software_name = result.get(
                    "software_name",
                    "Unknown Software"
                )

                software_version = result.get(
                    "software_version",
                    "Unknown Version"
                )

                publisher = result.get(
                    "publisher",
                    "Unknown"
                )

                cve_id = result.get(
                    "cve_id"
                )

                cvss_score = result.get(
                    "cvss_score"
                )

                cvss_severity = result.get(
                    "cvss_severity"
                )

                description = result.get(
                    "description",
                    "No vulnerability description available."
                )

                version_match = result.get(
                    "version_match",
                    "Needs verification"
                )

                # ---------------------------------------------
                # IMPORTANT:
                # NVD keyword matching alone does not confirm
                # that the installed version is vulnerable.
                #
                # Therefore, possible matches remain
                # Informational until version verification.
                # ---------------------------------------------

                severity = "Informational"

                if str(version_match).strip().lower() == "confirmed":

                    if cvss_severity:

                        severity_upper = str(
                            cvss_severity
                        ).upper()

                        if severity_upper == "CRITICAL":

                            severity = "Critical"

                        elif severity_upper == "HIGH":

                            severity = "High"

                        elif severity_upper == "MEDIUM":

                            severity = "Medium"

                        elif severity_upper == "LOW":

                            severity = "Low"

                # ---------------------------------------------
                # Finding title
                # ---------------------------------------------

                if cve_id:

                    finding_title = (
                        f"{software_name} "
                        f"{software_version} - "
                        f"{cve_id}"
                    )

                else:

                    finding_title = (
                        f"{software_name} "
                        f"{software_version} "
                        f"- Possible Vulnerability"
                    )

                # ---------------------------------------------
                # Detection message
                # ---------------------------------------------

                detection_message = (
                    f"Possible CVE match found for "
                    f"{software_name} "
                    f"version {software_version}."
                )

                # ---------------------------------------------
                # Recommendation
                # ---------------------------------------------

                recommendation = (
                    "Verify the exact installed software version "
                    "against the official vendor advisory and "
                    "NVD affected-version information before "
                    "treating this as a confirmed vulnerability."
                )

                if severity == "Critical":

                    recommendation = (
                        "Immediately verify whether the installed "
                        "software version is affected. If confirmed, "
                        "apply the vendor security update."
                    )

                elif severity == "High":

                    recommendation = (
                        "Verify the affected version and apply "
                        "the latest vendor security update if "
                        "the installed version is affected."
                    )

                elif severity == "Medium":

                    recommendation = (
                        "Verify the CVE against the installed "
                        "software version and apply the recommended "
                        "security update if applicable."
                    )

                elif severity == "Low":

                    recommendation = (
                        "Review the CVE information and update "
                        "the software if the installed version "
                        "is confirmed to be affected."
                    )

                # ---------------------------------------------
                # Create CyberGuard finding
                # ---------------------------------------------

                software_finding = {

                    "title":
                        finding_title,

                    "severity":
                        severity,

                    "component":
                        software_name,

                    "software_name":
                        software_name,

                    "software_version":
                        software_version,

                    "publisher":
                        publisher,

                    "cve":
                        cve_id,

                    "cve_id":
                        cve_id,

                    "cvss_score":
                        cvss_score,

                    "cvss_severity":
                        cvss_severity,

                    "version_match":
                        version_match,

                    "detection":
                        detection_message,

                    "description":
                        description,

                    "impact":
                        (
                            "The NVD database returned a possible "
                            "software vulnerability match. The "
                            "installed version must be verified "
                            "against the affected version before "
                            "considering the vulnerability confirmed."
                        ),

                    "recommendation":
                        recommendation
                }

                software_findings.append(
                    software_finding
                )

            # =================================================
            # 6. ADD SOFTWARE FINDINGS TO MAIN FINDINGS
            # =================================================

            if software_findings:

                findings.extend(
                    software_findings
                )

                print(
                    "Software findings added:",
                    len(software_findings)
                )

            else:

                print(
                    "No software vulnerability matches found."
                )

        except Exception as error:

            print(
                "SOFTWARE VULNERABILITY SCAN ERROR:",
                error
            )

        # =================================================
        # 7. FINAL CYBERGUARD RISK CALCULATION
        # =================================================

        risk_score, risk_level = calculate_risk(
            findings
        )

        print()

        print(
            "=" * 70
        )

        print(
            "FINAL CYBERGUARD RISK"
        )

        print(
            "=" * 70
        )

        print(
            "Final Risk Score:",
            risk_score
        )

        print(
            "Final Risk Level:",
            risk_level
        )

        print(
            "Total Findings:",
            len(findings)
        )

        print(
            "=" * 70
        )

        # =================================================
        # 8. AI ANALYSIS OF ALL FINDINGS
        # =================================================

        try:

            ai_results = analyze(
                device,
                findings,
                risk_score,
                risk_level
            )

        except Exception as error:

            print(
                "AI analysis error:",
                error
            )

            ai_results = []

        # =================================================
        # 9. SAVE COMPLETE SCAN
        # =================================================

        scan_id = database.save_scan(
            user_id,
            device,
            findings,
            risk_score,
            risk_level,
            ai_results
        )

        print(
            "Scan saved:",
            scan_id
        )

        # =================================================
        # 10. CREATE REMEDIATION ITEMS
        # =================================================

        try:

            database.create_remediation_items(
                user_id,
                scan_id,
                findings
            )

            print(
                "Remediation items created."
            )

        except Exception as error:

            print(
                "Remediation error:",
                error
            )

        # =================================================
        # 11. CREATE SECURITY ALERTS
        # =================================================

        try:

            database.create_security_alerts(
                user_id,
                scan_id,
                findings
            )

            print(
                "Security alerts created."
            )

        except Exception as error:

            print(
                "Alert creation error:",
                error
            )

        # =================================================
        # 12. SCAN COMPLETE
        # =================================================

        print()

        print(
            "=" * 70
        )

        print(
            "SECURITY SCAN COMPLETED"
        )

        print(
            "Total Findings:",
            len(findings)
        )

        print(
            "Final Risk:",
            risk_level
        )

        print(
            "=" * 70
        )

        return redirect(
            url_for(
                "scan_details",
                scan_id=scan_id
            )
        )

    except Exception as error:

        print(
            "SCAN ERROR:",
            error
        )

        return error_page(
            "SECURITY SCAN ERROR",
            error
        )


# =========================================================
# SCAN DETAILS
# =========================================================

@app.route(
    "/scan/<int:scan_id>"
)
@login_required
def scan_details(scan_id):

    try:

        user_id = session.get(
            "user_id"
        )

        scan_data = database.get_scan_details(
            scan_id,
            user_id
        )

        if scan_data is None:

            flash(
                "Scan was not found.",
                "error"
            )

            return redirect(
                url_for("history")
            )

        return render_template(
            "scan_details.html",
            scan=scan_data
        )

    except Exception as error:

        print(
            "SCAN DETAILS ERROR:",
            error
        )

        return error_page(
            "SCAN DETAILS ERROR",
            error
        )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
@login_required
def history():

    try:

        user_id = session.get(
            "user_id"
        )

        scans = database.get_scan_history(
            user_id
        )

        return render_template(
            "history.html",
            scans=scans
        )

    except Exception as error:

        print(
            "HISTORY ERROR:",
            error
        )

        return error_page(
            "SCAN HISTORY ERROR",
            error
        )


# =========================================================
# REMEDIATION
# =========================================================

@app.route("/remediation")
@login_required
def remediation():

    try:

        user_id = session.get(
            "user_id"
        )

        remediation_items = database.get_remediation_items(
            user_id
        )

        remediation_summary = database.get_remediation_summary(
            user_id
        )

        remediation_progress = database.get_remediation_progress(
            user_id
        )

        return render_template(
            "remediation.html",
            remediation_items=remediation_items,
            remediation_summary=remediation_summary,
            remediation_progress=remediation_progress
        )

    except Exception as error:

        print(
            "REMEDIATION ERROR:",
            error
        )

        return error_page(
            "REMEDIATION ERROR",
            error
        )


# =========================================================
# REMEDIATION DETAIL
# =========================================================

@app.route(
    "/remediation/<int:remediation_id>"
)
@login_required
def remediation_detail(remediation_id):

    try:

        user_id = session.get(
            "user_id"
        )

        item = database.get_remediation_detail(
            remediation_id,
            user_id
        )

        if item is None:

            flash(
                "Remediation item was not found.",
                "error"
            )

            return redirect(
                url_for("remediation")
            )

        return render_template(
            "remediation_detail.html",
            item=item
        )

    except Exception as error:

        print(
            "REMEDIATION DETAIL ERROR:",
            error
        )

        return error_page(
            "REMEDIATION DETAIL ERROR",
            error
        )


# =========================================================
# UPDATE REMEDIATION
# =========================================================

@app.route(
    "/remediation/<int:remediation_id>/update",
    methods=["POST"]
)
@login_required
def update_remediation(remediation_id):

    user_id = session.get(
        "user_id"
    )

    status = request.form.get(
        "status",
        ""
    )

    try:

        updated = database.update_remediation_status(
            remediation_id,
            user_id,
            status
        )

        if updated:

            flash(
                "Remediation status updated.",
                "success"
            )

        else:

            flash(
                "Unable to update remediation status.",
                "error"
            )

    except Exception as error:

        print(
            "REMEDIATION UPDATE ERROR:",
            error
        )

        flash(
            "Remediation update failed.",
            "error"
        )

    return redirect(
        url_for(
            "remediation_detail",
            remediation_id=remediation_id
        )
    )


# =========================================================
# SECURITY ALERTS
# =========================================================

@app.route("/alerts")
@login_required
def alerts():

    try:

        user_id = session.get(
            "user_id"
        )

        alert_list = database.get_alerts(
            user_id
        )

        unread_alert_count = database.get_unread_alert_count(
            user_id
        )

        return render_template(
            "alerts.html",
            alerts=alert_list,
            unread_alert_count=unread_alert_count
        )

    except Exception as error:

        print(
            "ALERTS ERROR:",
            error
        )

        return error_page(
            "SECURITY ALERTS ERROR",
            error
        )


# =========================================================
# ALERT DETAIL
# =========================================================

@app.route(
    "/alert/<int:alert_id>"
)
@login_required
def alert_detail(alert_id):

    try:

        user_id = session.get(
            "user_id"
        )

        print()
        print("=" * 70)
        print("OPENING SECURITY ALERT")
        print("Alert ID:", alert_id)
        print("User ID:", user_id)
        print("=" * 70)

        alert = database.get_alert_detail(
            alert_id,
            user_id
        )

        if alert is None:

            print(
                "ALERT NOT FOUND:",
                alert_id
            )

            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Alert Not Found - CyberGuard AI</title>
                <style>
                    body {{
                        margin: 0;
                        padding: 40px;
                        font-family: Arial, sans-serif;
                        background: #f5f7fb;
                    }}

                    .box {{
                        max-width: 700px;
                        margin: 60px auto;
                        background: white;
                        padding: 35px;
                        border-radius: 16px;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.08);
                    }}

                    h1 {{
                        color: #dc2626;
                    }}

                    a {{
                        display: inline-block;
                        margin-top: 20px;
                        padding: 12px 18px;
                        background: #2563eb;
                        color: white;
                        text-decoration: none;
                        border-radius: 8px;
                    }}
                </style>
            </head>

            <body>

                <div class="box">

                    <h1>
                        ⚠️ Security Alert Not Found
                    </h1>

                    <p>
                        Alert ID #{alert_id} could not be found
                        for the currently logged-in user.
                    </p>

                    <a href="/alerts">
                        ← Back to Security Alerts
                    </a>

                </div>

            </body>
            </html>
            """, 404

        alert = dict(alert)

        alert_id_value = escape(
            str(alert.get("id", ""))
        )

        scan_id_value = escape(
            str(alert.get("scan_id", ""))
        )

        title = escape(
            str(
                alert.get(
                    "title",
                    "Security Alert"
                )
            )
        )

        severity = escape(
            str(
                alert.get(
                    "severity",
                    "Informational"
                )
            )
        )

        message = escape(
            str(
                alert.get(
                    "message",
                    "No alert message available."
                )
            )
        )

        status = escape(
            str(
                alert.get(
                    "status",
                    "Unread"
                )
            )
        )

        created_at = escape(
            str(
                alert.get(
                    "created_at",
                    "Not available"
                )
            )
        )

        severity_lower = severity.lower()

        if severity_lower == "critical":

            severity_class = "critical"

        elif severity_lower == "high":

            severity_class = "high"

        elif severity_lower == "medium":

            severity_class = "medium"

        elif severity_lower == "low":

            severity_class = "low"

        else:

            severity_class = "info"

        if status.lower() == "unread":

            read_button = f"""
            <a
                href="/alert/{alert_id_value}/read"
                class="button blue"
            >
                ✓ Mark as Read
            </a>
            """

        else:

            read_button = """
            <span class="read-badge">
                ✓ Alert Already Read
            </span>
            """

        print(
            "ALERT LOADED SUCCESSFULLY:",
            alert_id_value
        )

        return f"""
        <!DOCTYPE html>

        <html lang="en">

        <head>

            <meta charset="UTF-8">

            <meta
                name="viewport"
                content="width=device-width, initial-scale=1.0"
            >

            <title>
                Security Alert - CyberGuard AI
            </title>

            <style>

                * {{
                    box-sizing: border-box;
                }}

                body {{
                    margin: 0;
                    font-family: Arial, Helvetica, sans-serif;
                    background: #f5f7fb;
                    color: #111827;
                }}

                .page {{
                    min-height: 100vh;
                    padding: 30px;
                }}

                .container {{
                    max-width: 1100px;
                    margin: 0 auto;
                }}

                .header {{
                    background: linear-gradient(135deg,#111827,#1e3a8a);
                    color: white;
                    padding: 30px;
                    border-radius: 18px;
                    margin-bottom: 25px;
                    box-shadow: 0 10px 30px rgba(15,23,42,0.15);
                }}

                .header h1 {{
                    margin: 0 0 10px 0;
                    font-size: 28px;
                }}

                .header p {{
                    margin: 0;
                    color: #dbeafe;
                    line-height: 1.6;
                }}

                .card {{
                    background: white;
                    border: 1px solid #e5e7eb;
                    border-radius: 16px;
                    padding: 30px;
                    box-shadow: 0 5px 18px rgba(15,23,42,0.06);
                    margin-bottom: 20px;
                }}

                .title-row {{
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    gap: 20px;
                    margin-bottom: 25px;
                }}

                .title {{
                    margin: 0;
                    font-size: 25px;
                    color: #111827;
                    line-height: 1.4;
                }}

                .severity {{
                    display: inline-block;
                    padding: 7px 14px;
                    border-radius: 20px;
                    font-size: 13px;
                    font-weight: bold;
                    white-space: nowrap;
                }}

                .critical {{
                    background: #fee2e2;
                    color: #991b1b;
                }}

                .high {{
                    background: #fee2e2;
                    color: #b91c1c;
                }}

                .medium {{
                    background: #fef3c7;
                    color: #92400e;
                }}

                .low {{
                    background: #dcfce7;
                    color: #166534;
                }}

                .info {{
                    background: #dbeafe;
                    color: #1e40af;
                }}

                .grid {{
                    display: grid;
                    grid-template-columns: repeat(2,1fr);
                    gap: 18px;
                    margin-bottom: 25px;
                }}

                .info-box {{
                    background: #f8fafc;
                    border: 1px solid #e5e7eb;
                    border-radius: 12px;
                    padding: 18px;
                }}

                .label {{
                    color: #6b7280;
                    font-size: 13px;
                    font-weight: 600;
                    margin-bottom: 8px;
                }}

                .value {{
                    color: #111827;
                    font-size: 15px;
                    font-weight: 600;
                    word-break: break-word;
                }}

                .message {{
                    background: #f8fafc;
                    border: 1px solid #e5e7eb;
                    border-radius: 12px;
                    padding: 22px;
                    margin-top: 10px;
                }}

                .message h2 {{
                    margin: 0 0 12px 0;
                    font-size: 19px;
                    color: #111827;
                }}

                .message p {{
                    margin: 0;
                    color: #4b5563;
                    line-height: 1.7;
                    white-space: pre-wrap;
                    word-break: break-word;
                }}

                .actions {{
                    display: flex;
                    flex-wrap: wrap;
                    gap: 12px;
                    margin-top: 25px;
                }}

                .button {{
                    display: inline-block;
                    padding: 12px 18px;
                    border-radius: 9px;
                    text-decoration: none;
                    font-size: 14px;
                    font-weight: 600;
                }}

                .blue {{
                    background: #2563eb;
                    color: white;
                }}

                .blue:hover {{
                    background: #1d4ed8;
                }}

                .dark {{
                    background: #111827;
                    color: white;
                }}

                .dark:hover {{
                    background: #1f2937;
                }}

                .light {{
                    background: #f3f4f6;
                    color: #111827;
                    border: 1px solid #e5e7eb;
                }}

                .light:hover {{
                    background: #e5e7eb;
                }}

                .read-badge {{
                    display: inline-block;
                    padding: 12px 18px;
                    background: #dcfce7;
                    color: #166534;
                    border-radius: 9px;
                    font-size: 14px;
                    font-weight: 600;
                }}

                .footer {{
                    text-align: center;
                    color: #6b7280;
                    font-size: 13px;
                    margin-top: 25px;
                }}

                @media (max-width: 700px) {{

                    .page {{
                        padding: 15px;
                    }}

                    .header {{
                        padding: 22px;
                    }}

                    .header h1 {{
                        font-size: 23px;
                    }}

                    .card {{
                        padding: 22px;
                    }}

                    .title-row {{
                        flex-direction: column;
                    }}

                    .grid {{
                        grid-template-columns: 1fr;
                    }}

                }}

            </style>

        </head>

        <body>

            <div class="page">

                <div class="container">

                    <div class="header">

                        <h1>
                            🚨 CyberGuard AI
                        </h1>

                        <p>
                            Security Alert Details
                        </p>

                    </div>

                    <div class="card">

                        <div class="title-row">

                            <h2 class="title">
                                {title}
                            </h2>

                            <span class="severity {severity_class}">
                                {severity}
                            </span>

                        </div>

                        <div class="grid">

                            <div class="info-box">

                                <div class="label">
                                    Alert ID
                                </div>

                                <div class="value">
                                    #{alert_id_value}
                                </div>

                            </div>

                            <div class="info-box">

                                <div class="label">
                                    Scan ID
                                </div>

                                <div class="value">
                                    #{scan_id_value}
                                </div>

                            </div>

                            <div class="info-box">

                                <div class="label">
                                    Severity
                                </div>

                                <div class="value">
                                    {severity}
                                </div>

                            </div>

                            <div class="info-box">

                                <div class="label">
                                    Status
                                </div>

                                <div class="value">
                                    {status}
                                </div>

                            </div>

                            <div class="info-box">

                                <div class="label">
                                    Created At
                                </div>

                                <div class="value">
                                    {created_at}
                                </div>

                            </div>

                        </div>

                        <div class="message">

                            <h2>
                                Alert Message
                            </h2>

                            <p>
                                {message}
                            </p>

                        </div>

                        <div class="actions">

                            {read_button}

                            <a
                                href="/scan/{scan_id_value}"
                                class="button dark"
                            >
                                🔍 View Scan
                            </a>

                            <a
                                href="/alerts"
                                class="button light"
                            >
                                ← Back to Security Alerts
                            </a>

                        </div>

                    </div>

                    <div class="footer">

                        CyberGuard AI
                        •
                        Security Monitoring System

                    </div>

                </div>

            </div>

        </body>

        </html>
        """

    except Exception as error:

        print()
        print("=" * 70)
        print("ALERT DETAIL ERROR")
        print("Alert ID:", alert_id)
        print("Error:", error)
        print("=" * 70)

        return error_page(
            "SECURITY ALERT DETAIL ERROR",
            error
        )


# =========================================================
# MARK ALERT AS READ
# =========================================================

@app.route(
    "/alert/<int:alert_id>/read",
    methods=["GET", "POST"]
)
@login_required
def mark_alert_as_read(alert_id):

    user_id = session.get(
        "user_id"
    )

    try:

        updated = database.mark_alert_read(
            alert_id,
            user_id
        )

        print(
            "Alert marked as read:",
            alert_id,
            "Updated:",
            updated
        )

    except Exception as error:

        print(
            "MARK ALERT READ ERROR:",
            error
        )

    return redirect(
        url_for("alerts")
    )


# =========================================================
# SECURITY OVERVIEW
# =========================================================

@app.route(
    "/security-overview"
)
@login_required
def security_overview():

    try:

        user_id = session.get(
            "user_id"
        )

        severity_counts = database.get_severity_counts(
            user_id
        )

        risk_trend = database.get_risk_trend(
            user_id
        )

        scans = database.get_scan_history(
            user_id
        )

        total_scans = len(
            scans
        )

        total_findings = sum(
            severity_counts.values()
        )

        remediation_summary = database.get_remediation_summary(
            user_id
        )

        if remediation_summary is None:

            remediation_summary = {
                "Total": 0,
                "Open": 0,
                "In Progress": 0,
                "Resolved": 0
            }

        remediation_progress = database.get_remediation_progress(
            user_id
        )

        if remediation_progress is None:

            remediation_progress = 0

        risk_score = 0

        risk_level = "LOW"

        if scans:

            latest_scan = scans[0]

            try:

                risk_score = latest_scan["risk_score"]

            except Exception:

                try:

                    risk_score = latest_scan.get(
                        "risk_score",
                        0
                    )

                except Exception:

                    risk_score = 0

            try:

                risk_level = latest_scan["risk_level"]

            except Exception:

                try:

                    risk_level = latest_scan.get(
                        "risk_level",
                        "LOW"
                    )

                except Exception:

                    risk_level = "LOW"

        return render_template(
            "security_overview.html",

            severity_counts=severity_counts,

            risk_trend=risk_trend,

            total_scans=total_scans,

            total_findings=total_findings,

            remediation_summary=remediation_summary,

            remediation_progress=remediation_progress,

            risk_score=risk_score,

            risk_level=risk_level
        )

    except Exception as error:

        print(
            "SECURITY OVERVIEW ERROR:",
            error
        )

        return error_page(
            "SECURITY OVERVIEW ERROR",
            error
        )


# =========================================================
# PDF REPORT
# =========================================================

@app.route(
    "/report/<int:scan_id>"
)
@login_required
def report(scan_id):

    try:

        user_id = session.get(
            "user_id"
        )

        scan_data = database.get_scan_details(
            scan_id,
            user_id
        )

        if scan_data is None:

            flash(
                "Scan was not found.",
                "error"
            )

            return redirect(
                url_for("history")
            )

        from report_generator import generate_report

        pdf_path = generate_report(
            scan_data
        )

        if pdf_path and os.path.exists(
            pdf_path
        ):

            return send_file(
                pdf_path,
                as_attachment=True,
                download_name=(
                    f"CyberGuard_AI_Report_{scan_id}.pdf"
                )
            )

        return error_page(
            "PDF REPORT ERROR",
            "PDF report could not be generated."
        )

    except Exception as error:

        print(
            "PDF ERROR:",
            error
        )

        return error_page(
            "PDF REPORT ERROR",
            error
        )


# =========================================================
# TEST
# =========================================================

@app.route("/test")
def test():

    return """
    <!DOCTYPE html>

    <html>

    <head>

        <title>CyberGuard AI Test</title>

    </head>

    <body>

        <h1>🛡️ CyberGuard AI</h1>

        <h2>Flask Server is Working</h2>

        <p>
            Application server is running correctly.
        </p>

        <p>
            CSRF Token Support: Enabled
        </p>

        <br>

        <a href="/login">
            Login
        </a>

        <br><br>

        <a href="/signup">
            Signup
        </a>

    </body>

    </html>
    """


# =========================================================
# ERROR PAGE
# =========================================================

def error_page(title, error):

    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <meta charset="UTF-8">

        <title>
            CyberGuard AI - Error
        </title>

        <style>

            body {{
                margin: 0;
                padding: 40px;
                font-family: Arial, sans-serif;
                background: #f5f7fb;
                color: #111827;
            }}

            .error-box {{
                max-width: 900px;
                margin: 40px auto;
                background: white;
                border-radius: 15px;
                padding: 30px;
                border: 1px solid #e5e7eb;
                box-shadow:
                    0 10px 30px
                    rgba(0,0,0,0.08);
            }}

            h1 {{
                color: #dc2626;
            }}

            .error {{
                background: #fef2f2;
                border: 1px solid #fecaca;
                color: #991b1b;
                padding: 20px;
                border-radius: 10px;
                white-space: pre-wrap;
                word-break: break-word;
                font-family: Consolas, monospace;
            }}

            a {{
                display: inline-block;
                margin-top: 20px;
                margin-right: 10px;
                padding: 11px 18px;
                background: #111827;
                color: white;
                text-decoration: none;
                border-radius: 8px;
            }}

        </style>

    </head>

    <body>

        <div class="error-box">

            <h1>
                ⚠️ {title}
            </h1>

            <p>
                CyberGuard AI found an application error.
            </p>

            <div class="error">
{escape(str(error))}
            </div>

            <a href="/test">
                Test Page
            </a>

            <a href="/alerts">
                Security Alerts
            </a>

        </div>

    </body>

    </html>
    """


# =========================================================
# 404
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return error_page(
        "PAGE NOT FOUND",
        "The requested page does not exist."
    ), 404


# =========================================================
# 500
# =========================================================

@app.errorhandler(500)
def internal_server_error(error):

    return error_page(
        "INTERNAL SERVER ERROR",
        error
    ), 500


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    print()

    print("=" * 70)

    print(
        "CYBERGUARD AI"
    )

    print("=" * 70)

    print(
        "Starting Flask server..."
    )

    print()

    print(
        "Open: http://127.0.0.1:5000"
    )

    print(
        "Test: http://127.0.0.1:5000/test"
    )

    print(
        "Alerts: http://127.0.0.1:5000/alerts"
    )

    print("=" * 70)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )