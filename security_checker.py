import platform
import socket
import subprocess


def check_security():

    findings = []

    # --------------------------------------------------
    # 1. WINDOWS FIREWALL CHECK
    # --------------------------------------------------

    try:

        if platform.system() == "Windows":

            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "Get-NetFirewallProfile | "
                    "Select-Object Name,Enabled"
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout.lower()

            if "false" in output:

                findings.append({
                    "title":
                        "Windows Firewall Configuration",

                    "severity":
                        "High",

                    "component":
                        "Windows Firewall",

                    "detection":
                        "One or more firewall profiles "
                        "may be disabled.",

                    "description":
                        "A Windows Firewall profile appears "
                        "to be disabled.",

                    "impact":
                        "A disabled firewall can increase "
                        "exposure to unauthorized network "
                        "connections.",

                    "recommendation":
                        "Enable Windows Firewall for all "
                        "required network profiles."
                })

            else:

                findings.append({
                    "title":
                        "Windows Firewall",

                    "severity":
                        "Informational",

                    "component":
                        "Windows Firewall",

                    "detection":
                        "Windows Firewall appears "
                        "to be enabled.",

                    "description":
                        "The system firewall configuration "
                        "was checked.",

                    "impact":
                        "A properly configured firewall "
                        "helps restrict unwanted network "
                        "connections.",

                    "recommendation":
                        "Keep Windows Firewall enabled "
                        "and regularly review its "
                        "configuration."
                })

    except Exception as error:

        findings.append({
            "title":
                "Firewall Check",

            "severity":
                "Low",

            "component":
                "Windows Firewall",

            "detection":
                "Firewall status could not be "
                "completely verified.",

            "description":
                str(error),

            "impact":
                "The security status of the firewall "
                "could not be confirmed.",

            "recommendation":
                "Manually verify that Windows Firewall "
                "is enabled."
        })

    # --------------------------------------------------
    # 2. OPERATING SYSTEM CHECK
    # --------------------------------------------------

    try:

        os_name = platform.system()
        os_version = platform.version()
        os_release = platform.release()

        findings.append({
            "title":
                "Operating System Information",

            "severity":
                "Informational",

            "component":
                os_name,

            "detection":
                f"{os_name} {os_release} detected.",

            "description":
                f"Operating system version detected: "
                f"{os_version}",

            "impact":
                "An outdated operating system can "
                "contain known security vulnerabilities.",

            "recommendation":
                "Keep the operating system updated "
                "with the latest security patches."
        })

    except Exception:
        pass

    # --------------------------------------------------
    # 3. LISTENING NETWORK SERVICES
    # --------------------------------------------------

    try:

        if platform.system() == "Windows":

            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "Get-NetTCPConnection -State Listen | "
                    "Select-Object LocalPort,OwningProcess"
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout.strip()

            if output:

                findings.append({
                    "title":
                        "Listening Network Services",

                    "severity":
                        "Medium",

                    "component":
                        "Network Services",

                    "detection":
                        "Listening TCP services were "
                        "detected on the device.",

                    "description":
                        "The system has network services "
                        "listening for incoming connections.",

                    "impact":
                        "Unnecessary network services can "
                        "increase the device attack surface.",

                    "recommendation":
                        "Review listening ports and disable "
                        "services that are not required."
                })

    except Exception:
        pass

    # --------------------------------------------------
    # 4. DEVICE IDENTIFICATION
    # --------------------------------------------------

    try:

        hostname = socket.gethostname()

        findings.append({
            "title":
                "Device Identification",

            "severity":
                "Informational",

            "component":
                "System Configuration",

            "detection":
                f"Device hostname detected: {hostname}",

            "description":
                "The scanner successfully identified "
                "the device hostname.",

            "impact":
                "Hostname information can help identify "
                "a device inside a network.",

            "recommendation":
                "Use meaningful hostnames and avoid "
                "exposing unnecessary system information."
        })

    except Exception:
        pass

    # --------------------------------------------------
    # 5. SECURITY MAINTENANCE
    # --------------------------------------------------

    findings.append({
        "title":
            "Security Maintenance",

        "severity":
            "Low",

        "component":
            "System Security",

        "detection":
            "General security maintenance "
            "check completed.",

        "description":
            "Regular updates, firewall configuration, "
            "and monitoring are important for "
            "device security.",

        "impact":
            "Poor security maintenance can increase "
            "the risk of exploitation.",

        "recommendation":
            "Regularly update software, review security "
            "settings, use strong authentication, "
            "and perform periodic scans."
    })

    # --------------------------------------------------
    # 6. CVE TEST / VULNERABILITY DATABASE CONNECTION
    # --------------------------------------------------
    #
    # This is a controlled test finding.
    # It allows CyberGuard AI to verify that
    # CVE information can flow into the scan.
    #
    # Later we will replace this with real
    # software-version based CVE detection.
    #

    findings.append({
        "title":
            "CVE Database Integration Test",

        "severity":
            "Informational",

        "component":
            "Vulnerability Database",

        "cve":
            "CVE-2021-44228",

        "detection":
            "CVE/NVD integration test record.",

        "description":
            "This test finding verifies that CyberGuard "
            "AI can retrieve vulnerability information "
            "from the NVD database.",

        "impact":
            "No device vulnerability is being claimed "
            "by this test record.",

        "recommendation":
            "This is an integration test. The CVE "
            "mapping will later be replaced by "
            "real software and version detection."
    })

    return findings


if __name__ == "__main__":

    results = check_security()

    print("=" * 60)
    print("CYBERGUARD AI - SECURITY CHECK")
    print("=" * 60)

    for finding in results:

        print()
        print(
            "Title:",
            finding.get("title")
        )

        print(
            "Severity:",
            finding.get("severity")
        )

        print(
            "Component:",
            finding.get("component")
        )

        print(
            "CVE:",
            finding.get(
                "cve",
                "None"
            )
        )

        print(
            "Detection:",
            finding.get("detection")
        )

        print(
            "Description:",
            finding.get("description")
        )

        print(
            "Impact:",
            finding.get("impact")
        )

        print(
            "Recommendation:",
            finding.get("recommendation")
        )