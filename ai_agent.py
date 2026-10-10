def analyze(
    device,
    findings,
    risk_score,
    risk_level
):
    """
    Analyze normal security findings.
    """

    results = []

    if not findings:

        return [{
            "title":
                "No Major Vulnerabilities Detected",

            "severity":
                "Informational",

            "analysis":
                "The security scan did not detect any major security findings.",

            "recommendation":
                "Continue performing regular security scans and keep the operating system and software updated."
        }]

    for finding in findings:

        title = finding.get(
            "title",
            "Security Finding"
        )

        severity = finding.get(
            "severity",
            "Informational"
        )

        recommendation = finding.get(
            "recommendation",
            "Review this security finding and apply the recommended security fix."
        )

        if severity == "Critical":

            analysis = (
                "This is a critical security finding. "
                "It may represent a significant security "
                "risk and should be reviewed immediately."
            )

        elif severity == "High":

            analysis = (
                "This is a high-severity security finding. "
                "It could significantly increase the "
                "security risk of the device."
            )

        elif severity == "Medium":

            analysis = (
                "This is a medium-severity security finding. "
                "It should be reviewed and fixed as part "
                "of normal security maintenance."
            )

        elif severity == "Low":

            analysis = (
                "This is a low-severity security finding. "
                "It represents a smaller security concern "
                "but should still be reviewed."
            )

        else:

            analysis = (
                "This finding provides useful security "
                "information about the scanned device."
            )

        result = {

            "title":
                title,

            "severity":
                severity,

            "analysis":
                analysis,

            "recommendation":
                recommendation
        }

        if finding.get("cve_id"):

            result["cve_id"] = (
                finding.get("cve_id")
            )

            result["cvss_score"] = (
                finding.get("cvss_score")
            )

            result["cvss_severity"] = (
                finding.get("cvss_severity")
            )

            result["cwe"] = (
                finding.get("cwe")
            )

        results.append(
            result
        )

    return results


def analyze_software_vulnerabilities(
    software_results
):
    """
    Analyze possible software vulnerabilities.

    Important:
    NVD keyword matches are treated as possible
    vulnerabilities until exact product/version
    applicability is verified.
    """

    results = []

    for vulnerability in software_results:

        software_name = vulnerability.get(
            "software_name",
            "Unknown Software"
        )

        software_version = vulnerability.get(
            "software_version",
            "Unknown Version"
        )

        cve_id = vulnerability.get(
            "cve_id",
            "Unknown CVE"
        )

        severity = vulnerability.get(
            "cvss_severity",
            "Unknown"
        )

        cvss_score = vulnerability.get(
            "cvss_score"
        )

        description = vulnerability.get(
            "description",
            "No vulnerability description available."
        )

        version_match = vulnerability.get(
            "version_match",
            "Needs verification"
        )

        if severity:

            severity_text = str(
                severity
            ).upper()

        else:

            severity_text = "UNKNOWN"

        if severity_text == "CRITICAL":

            analysis = (
                f"{software_name} version "
                f"{software_version} has a possible "
                f"Critical CVE match ({cve_id}). "
                "This finding should be verified against "
                "the exact installed product and version."
            )

            recommendation = (
                "Verify the affected version and apply "
                "the vendor security update if the installed "
                "version is affected."
            )

        elif severity_text == "HIGH":

            analysis = (
                f"{software_name} version "
                f"{software_version} has a possible "
                f"High-severity CVE match ({cve_id}). "
                "The exact product/version applicability "
                "should be verified."
            )

            recommendation = (
                "Check the vendor advisory and update the "
                "software to a secure version if affected."
            )

        elif severity_text == "MEDIUM":

            analysis = (
                f"{software_name} version "
                f"{software_version} has a possible "
                f"Medium-severity CVE match ({cve_id}). "
                "Further version verification is required."
            )

            recommendation = (
                "Verify the CVE against the installed version "
                "and apply the recommended update if applicable."
            )

        elif severity_text == "LOW":

            analysis = (
                f"{software_name} version "
                f"{software_version} has a possible "
                f"Low-severity CVE match ({cve_id}). "
                "The result should be verified."
            )

            recommendation = (
                "Review the vulnerability information and "
                "update the software when appropriate."
            )

        else:

            analysis = (
                f"A possible CVE match was found for "
                f"{software_name} version "
                f"{software_version}. "
                "The vulnerability severity or exact "
                "version applicability could not be confirmed."
            )

            recommendation = (
                "Verify the CVE using the official vendor "
                "advisory and NVD affected-version information."
            )

        results.append({

            "title":
                f"{software_name} - {cve_id}",

            "software_name":
                software_name,

            "software_version":
                software_version,

            "cve_id":
                cve_id,

            "severity":
                severity_text,

            "cvss_score":
                cvss_score,

            "version_match":
                version_match,

            "analysis":
                analysis,

            "description":
                description,

            "recommendation":
                recommendation
        })

    return results


def analyze_security(
    device,
    findings,
    risk_score,
    risk_level
):
    """
    Compatibility function used by the existing app.
    """

    return analyze(
        device,
        findings,
        risk_score,
        risk_level
    )


if __name__ == "__main__":

    print("=" * 60)
    print("CYBERGUARD AI - AI AGENT TEST")
    print("=" * 60)

    test_vulnerabilities = [

        {
            "software_name":
                "Example Software",

            "software_version":
                "1.0",

            "cve_id":
                "CVE-TEST",

            "cvss_score":
                7.5,

            "cvss_severity":
                "HIGH",

            "version_match":
                "Needs verification",

            "description":
                "Example vulnerability for testing."
        }
    ]

    results = analyze_software_vulnerabilities(
        test_vulnerabilities
    )

    for result in results:

        print()
        print(
            "Title:",
            result["title"]
        )

        print(
            "Severity:",
            result["severity"]
        )

        print(
            "Analysis:",
            result["analysis"]
        )

        print(
            "Recommendation:",
            result["recommendation"]
        )

        print("-" * 60)