import platform
import subprocess
import json


def get_installed_software():
    """
    Detect installed Windows software using PowerShell.
    """

    software = []

    if platform.system() != "Windows":
        return software

    try:
        command = """
        Get-ItemProperty `
        HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,
        HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,
        HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |
        Where-Object {
            $_.DisplayName -and $_.DisplayVersion
        } |
        Select-Object DisplayName, DisplayVersion, Publisher |
        ConvertTo-Json -Compress
        """

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        if result.returncode != 0:
            print(
                "Software detection failed:",
                result.stderr
            )
            return software

        output = result.stdout.strip()

        if not output:
            return software

        data = json.loads(output)

        if isinstance(data, dict):
            data = [data]

        for item in data:

            name = item.get(
                "DisplayName"
            )

            version = item.get(
                "DisplayVersion"
            )

            publisher = item.get(
                "Publisher",
                "Unknown"
            )

            if not name or not version:
                continue

            software.append({
                "name": name,
                "version": version,
                "publisher": publisher
            })

    except subprocess.TimeoutExpired:

        print(
            "Software detection timed out."
        )

    except json.JSONDecodeError:

        print(
            "Could not read software information."
        )

    except Exception as error:

        print(
            "Software scanner error:",
            error
        )

    return software


def get_software_summary():

    software = get_installed_software()

    return {
        "total": len(software),
        "software": software
    }


if __name__ == "__main__":

    print("=" * 60)
    print("CYBERGUARD AI - INSTALLED SOFTWARE SCANNER")
    print("=" * 60)

    software = get_installed_software()

    print()
    print(
        "Total software detected:",
        len(software)
    )

    print()

    for item in software[:30]:

        print(
            f"Name: {item['name']}"
        )

        print(
            f"Version: {item['version']}"
        )

        print(
            f"Publisher: {item['publisher']}"
        )

        print("-" * 50)