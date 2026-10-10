import sqlite3
import json
import os
from datetime import datetime


DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cyberguard.db"
)


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():

    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            hostname TEXT,
            operating_system TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            findings TEXT,
            ai_results TEXT
        )
    """)

    columns = conn.execute(
        "PRAGMA table_info(scans)"
    ).fetchall()

    column_names = [
        column[1]
        for column in columns
    ]

    if "user_id" not in column_names:

        conn.execute("""
            ALTER TABLE scans
            ADD COLUMN user_id INTEGER
        """)

    conn.commit()
    conn.close()


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(
    user_id,
    device,
    findings,
    risk_score,
    risk_level,
    ai_results
):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.execute("""
        INSERT INTO scans (
            user_id,
            scanned_at,
            hostname,
            operating_system,
            risk_score,
            risk_level,
            findings,
            ai_results
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        user_id,

        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        device.get(
            "hostname",
            "Unknown"
        ),

        device.get(
            "os",
            "Unknown"
        ),

        risk_score,

        risk_level,

        json.dumps(findings),

        json.dumps(ai_results)
    ))

    scan_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return scan_id


# =========================================================
# GET SCAN HISTORY
# =========================================================

def get_scan_history(user_id):

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    scans = conn.execute("""
        SELECT
            id,
            scanned_at,
            hostname,
            operating_system,
            risk_score,
            risk_level
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        user_id,
    )).fetchall()

    conn.close()

    return scans


# =========================================================
# GET SCAN DETAILS
# =========================================================

def get_scan_details(
    scan_id,
    user_id
):

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    scan = conn.execute("""
        SELECT
            id,
            scanned_at,
            hostname,
            operating_system,
            risk_score,
            risk_level,
            findings,
            ai_results
        FROM scans
        WHERE id = ?
        AND user_id = ?
    """, (
        scan_id,
        user_id
    )).fetchone()

    conn.close()

    if scan is None:
        return None

    scan = dict(scan)

    try:

        scan["findings"] = json.loads(
            scan["findings"]
        )

    except Exception:

        scan["findings"] = []

    try:

        scan["ai_results"] = json.loads(
            scan["ai_results"]
        )

    except Exception:

        scan["ai_results"] = []

    return scan


# =========================================================
# SEVERITY COUNTS
# =========================================================

def get_severity_counts(user_id):

    conn = sqlite3.connect(DB_PATH)

    scans = conn.execute("""
        SELECT findings
        FROM scans
        WHERE user_id = ?
    """, (
        user_id,
    )).fetchall()

    conn.close()

    counts = {

        "Critical": 0,

        "High": 0,

        "Medium": 0,

        "Low": 0,

        "Informational": 0
    }

    for scan in scans:

        try:

            findings = json.loads(
                scan[0]
            )

        except Exception:

            findings = []

        for finding in findings:

            severity = finding.get(
                "severity",
                "Informational"
            )

            if severity in counts:

                counts[severity] += 1

    return counts


# =========================================================
# RISK TREND
# =========================================================

def get_risk_trend(user_id):

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    scans = conn.execute("""
        SELECT
            scanned_at,
            risk_score
        FROM scans
        WHERE user_id = ?
        ORDER BY id ASC
    """, (
        user_id,
    )).fetchall()

    conn.close()

    return scans


# =========================================================
# REMEDIATION TABLE
# =========================================================

def init_remediation_table():

    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS remediation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            finding_title TEXT NOT NULL,
            severity TEXT,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# =========================================================
# CREATE REMEDIATION ITEMS
# =========================================================

def create_remediation_items(
    user_id,
    scan_id,
    findings
):

    conn = sqlite3.connect(DB_PATH)

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    for finding in findings:

        title = finding.get(
            "title",
            "Unknown Finding"
        )

        severity = finding.get(
            "severity",
            "Informational"
        )

        existing = conn.execute("""
            SELECT id
            FROM remediation
            WHERE user_id = ?
            AND finding_title = ?
            AND status != 'Resolved'
        """, (
            user_id,
            title
        )).fetchone()

        if existing is None:

            conn.execute("""
                INSERT INTO remediation (
                    user_id,
                    scan_id,
                    finding_title,
                    severity,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (

                user_id,

                scan_id,

                title,

                severity,

                "Open",

                now,

                now
            ))

    conn.commit()
    conn.close()


# =========================================================
# GET REMEDIATION ITEMS
# =========================================================

def get_remediation_items(user_id):

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    items = conn.execute("""
        SELECT
            id,
            scan_id,
            finding_title,
            severity,
            status,
            created_at,
            updated_at
        FROM remediation
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        user_id,
    )).fetchall()

    conn.close()

    return items


# =========================================================
# UPDATE REMEDIATION STATUS
# =========================================================

def update_remediation_status(
    remediation_id,
    user_id,
    status
):

    allowed_statuses = [
        "Open",
        "In Progress",
        "Resolved"
    ]

    if status not in allowed_statuses:

        return False

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.execute("""
        UPDATE remediation
        SET
            status = ?,
            updated_at = ?
        WHERE id = ?
        AND user_id = ?
    """, (

        status,

        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        remediation_id,

        user_id
    ))

    conn.commit()

    updated = cursor.rowcount > 0

    conn.close()

    return updated


# =========================================================
# REMEDIATION SUMMARY
# =========================================================

def get_remediation_summary(user_id):

    conn = sqlite3.connect(DB_PATH)

    summary = conn.execute("""
        SELECT
            status,
            COUNT(*) AS count
        FROM remediation
        WHERE user_id = ?
        GROUP BY status
    """, (
        user_id,
    )).fetchall()

    conn.close()

    result = {

        "Open": 0,

        "In Progress": 0,

        "Resolved": 0,

        "Total": 0
    }

    for status, count in summary:

        if status in result:

            result[status] = count

    result["Total"] = (

        result["Open"]

        + result["In Progress"]

        + result["Resolved"]
    )

    return result


# =========================================================
# REMEDIATION PROGRESS
# =========================================================

def get_remediation_progress(user_id):

    summary = get_remediation_summary(
        user_id
    )

    total = summary["Total"]

    resolved = summary["Resolved"]

    if total == 0:

        return 0

    return int(
        (resolved / total) * 100
    )


# =========================================================
# REMEDIATION DETAIL
# =========================================================

def get_remediation_detail(
    remediation_id,
    user_id
):

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    item = conn.execute("""
        SELECT
            id,
            scan_id,
            finding_title,
            severity,
            status,
            created_at,
            updated_at
        FROM remediation
        WHERE id = ?
        AND user_id = ?
    """, (
        remediation_id,
        user_id
    )).fetchone()

    conn.close()

    return item


# =========================================================
# ALERT TABLE
# =========================================================

def init_alerts_table():

    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Unread',
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# =========================================================
# CREATE SECURITY ALERTS
# =========================================================

def create_security_alerts(
    user_id,
    scan_id,
    findings
):

    conn = sqlite3.connect(DB_PATH)

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    for finding in findings:

        severity = finding.get(
            "severity",
            "Informational"
        )

        # -------------------------------------------------
        # ALERT LEVELS
        # -------------------------------------------------
        #
        # Critical and High = immediate alert
        # Medium = security warning
        # Low / Informational = no alert
        #

        if severity not in [
            "Critical",
            "High",
            "Medium"
        ]:

            continue

        title = finding.get(
            "title",
            "Security Finding"
        )

        recommendation = finding.get(
            "recommendation",
            "Review this security finding."
        )

        cve_id = finding.get(
            "cve_id",
            finding.get("cve")
        )

        software_name = finding.get(
            "software_name"
        )

        if cve_id:

            if software_name:

                message = (
                    f"Potential vulnerability "
                    f"{cve_id} was associated with "
                    f"{software_name}. "
                    f"{recommendation}"
                )

            else:

                message = (
                    f"CVE {cve_id} was detected. "
                    f"{recommendation}"
                )

        else:

            message = recommendation

        conn.execute("""
            INSERT INTO alerts (
                user_id,
                scan_id,
                title,
                severity,
                message,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (

            user_id,

            scan_id,

            title,

            severity,

            message,

            "Unread",

            now
        ))

    conn.commit()
    conn.close()


# =========================================================
# GET ALERTS
# =========================================================

def get_alerts(user_id):

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    alerts = conn.execute("""
        SELECT
            id,
            scan_id,
            title,
            severity,
            message,
            status,
            created_at
        FROM alerts
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        user_id,
    )).fetchall()

    conn.close()

    return alerts


# =========================================================
# GET UNREAD ALERT COUNT
# =========================================================

def get_unread_alert_count(user_id):

    conn = sqlite3.connect(DB_PATH)

    result = conn.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE user_id = ?
        AND status = 'Unread'
    """, (
        user_id,
    )).fetchone()

    conn.close()

    return result[0]


# =========================================================
# MARK ALERT AS READ
# =========================================================

def mark_alert_read(
    alert_id,
    user_id
):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.execute("""
        UPDATE alerts
        SET status = 'Read'
        WHERE id = ?
        AND user_id = ?
    """, (
        alert_id,
        user_id
    ))

    conn.commit()

    updated = cursor.rowcount > 0

    conn.close()

    return updated


# =========================================================
# ALERT DETAIL
# =========================================================

def get_alert_detail(
    alert_id,
    user_id
):

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    alert = conn.execute("""
        SELECT
            id,
            scan_id,
            title,
            severity,
            message,
            status,
            created_at
        FROM alerts
        WHERE id = ?
        AND user_id = ?
    """, (
        alert_id,
        user_id
    )).fetchone()

    conn.close()

    return alert