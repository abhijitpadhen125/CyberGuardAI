from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

import os
from datetime import datetime


def generate_report(scan_data):

    # ---------------------------------------------------------
    # CREATE REPORTS FOLDER
    # ---------------------------------------------------------

    base_folder = os.path.dirname(
        os.path.abspath(__file__)
    )

    reports_folder = os.path.join(
        base_folder,
        "reports"
    )

    os.makedirs(
        reports_folder,
        exist_ok=True
    )

    # ---------------------------------------------------------
    # GET SCAN ID
    # ---------------------------------------------------------

    scan_id = scan_data.get(
        "id",
        "unknown"
    )

    # ---------------------------------------------------------
    # PDF FILE PATH
    # ---------------------------------------------------------

    file_name = (
        f"CyberGuardAI_Report_{scan_id}.pdf"
    )

    file_path = os.path.join(
        reports_folder,
        file_name
    )

    # ---------------------------------------------------------
    # PDF DOCUMENT
    # ---------------------------------------------------------

    document = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    # ---------------------------------------------------------
    # STYLES
    # ---------------------------------------------------------

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontSize=15,
        spaceBefore=15,
        spaceAfter=10
    )

    normal_style = ParagraphStyle(
        "NormalStyle",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        spaceAfter=6
    )

    # ---------------------------------------------------------
    # STORY
    # ---------------------------------------------------------

    story = []

    # ---------------------------------------------------------
    # TITLE
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "CYBERGUARD AI",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Cybersecurity Scan Report",
            heading_style
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            normal_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    # ---------------------------------------------------------
    # DEVICE INFORMATION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "1. Device Information",
            heading_style
        )
    )

    hostname = scan_data.get(
        "hostname",
        "Unknown"
    )

    operating_system = scan_data.get(
        "operating_system",
        "Unknown"
    )

    device_table_data = [
        ["Information", "Value"],
        ["Scan ID", str(scan_id)],
        ["Hostname", str(hostname)],
        ["Operating System", str(operating_system)],
        [
            "Risk Score",
            str(
                scan_data.get(
                    "risk_score",
                    0
                )
            )
        ],
        [
            "Risk Level",
            str(
                scan_data.get(
                    "risk_level",
                    "Unknown"
                )
            )
        ]
    ]

    device_table = Table(
        device_table_data,
        colWidths=[160, 330]
    )

    device_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1f2937")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(
        device_table
    )

    story.append(
        Spacer(1, 20)
    )

    # ---------------------------------------------------------
    # SECURITY FINDINGS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "2. Security Findings",
            heading_style
        )
    )

    findings = scan_data.get(
        "findings",
        []
    )

    if not findings:

        story.append(
            Paragraph(
                "No security findings were detected.",
                normal_style
            )
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            title = finding.get(
                "title",
                "Security Finding"
            )

            severity = finding.get(
                "severity",
                "Informational"
            )

            component = finding.get(
                "component",
                "Unknown"
            )

            detection = finding.get(
                "detection",
                "Not available"
            )

            description = finding.get(
                "description",
                "Not available"
            )

            impact = finding.get(
                "impact",
                "Not available"
            )

            recommendation = finding.get(
                "recommendation",
                "Not available"
            )

            story.append(
                Paragraph(
                    f"<b>{index}. {title}</b>",
                    normal_style
                )
            )

            finding_table_data = [
                ["Severity", str(severity)],
                ["Component", str(component)],
                ["Detection", str(detection)],
                ["Description", str(description)],
                ["Impact", str(impact)],
                [
                    "Recommendation",
                    str(recommendation)
                ]
            ]

            finding_table = Table(
                finding_table_data,
                colWidths=[120, 370]
            )

            finding_table.setStyle(
                TableStyle([
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey
                    ),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.HexColor("#f3f4f6")
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (0, -1),
                        "Helvetica-Bold"
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        7
                    )
                ])
            )

            story.append(
                finding_table
            )

            story.append(
                Spacer(1, 15)
            )

    # ---------------------------------------------------------
    # AI ANALYSIS
    # ---------------------------------------------------------

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "3. AI Security Analysis",
            heading_style
        )
    )

    ai_results = scan_data.get(
        "ai_results",
        []
    )

    if not ai_results:

        story.append(
            Paragraph(
                "No AI analysis is available.",
                normal_style
            )
        )

    else:

        for index, result in enumerate(
            ai_results,
            start=1
        ):

            title = result.get(
                "title",
                "Security Analysis"
            )

            severity = result.get(
                "severity",
                "Informational"
            )

            analysis = result.get(
                "analysis",
                "Not available"
            )

            recommendation = result.get(
                "recommendation",
                "Not available"
            )

            story.append(
                Paragraph(
                    f"<b>{index}. {title}</b>",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Severity:</b> {severity}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Analysis:</b> {analysis}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> {recommendation}",
                    normal_style
                )
            )

            story.append(
                Spacer(1, 10)
            )

    # ---------------------------------------------------------
    # CVE INFORMATION
    # ---------------------------------------------------------

    cve_findings = []

    for finding in findings:

        if finding.get("cve_id"):

            cve_findings.append(
                finding
            )

    if cve_findings:

        story.append(
            PageBreak()
        )

        story.append(
            Paragraph(
                "4. Vulnerability / CVE Information",
                heading_style
            )
        )

        for finding in cve_findings:

            cve_id = finding.get(
                "cve_id",
                "Unknown"
            )

            cve_description = finding.get(
                "cve_description",
                "Not available"
            )

            cvss_score = finding.get(
                "cvss_score",
                "Not available"
            )

            cvss_severity = finding.get(
                "cvss_severity",
                "Not available"
            )

            cwe = finding.get(
                "cwe",
                "Not available"
            )

            story.append(
                Paragraph(
                    f"<b>{cve_id}</b>",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>CVSS Score:</b> {cvss_score}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>CVSS Severity:</b> {cvss_severity}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>CWE:</b> {cwe}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Description:</b> {cve_description}",
                    normal_style
                )

            )

            story.append(
                Spacer(1, 12)
            )

    # ---------------------------------------------------------
    # FINAL MESSAGE
    # ---------------------------------------------------------

    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "CyberGuard AI - Automated Cybersecurity Assessment",
            normal_style
        )
    )

    # ---------------------------------------------------------
    # BUILD PDF
    # ---------------------------------------------------------

    document.build(
        story
    )

    # ---------------------------------------------------------
    # VERIFY FILE
    # ---------------------------------------------------------

    if not os.path.exists(file_path):

        raise FileNotFoundError(
            "PDF file was not created."
        )

    return file_path