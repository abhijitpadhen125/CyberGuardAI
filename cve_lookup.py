import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cve(keyword):

    try:

        response = requests.get(
            NVD_API_URL,
            params={
                "keywordSearch": keyword,
                "resultsPerPage": 5
            },
            timeout=10
        )

        if response.status_code != 200:
            return []

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        results = []

        for item in vulnerabilities:

            cve = item.get(
                "cve",
                {}
            )

            cve_id = cve.get(
                "id",
                "Unknown"
            )

            descriptions = cve.get(
                "descriptions",
                []
            )

            description = "No description available."

            for desc in descriptions:

                if desc.get("lang") == "en":

                    description = desc.get(
                        "value",
                        description
                    )

                    break

            results.append({
                "cve_id": cve_id,
                "description": description
            })

        return results

    except requests.RequestException:

        return []

    except Exception:

        return []


def get_cve_information(keyword):

    results = search_cve(
        keyword
    )

    if not results:

        return {
            "found": False,
            "results": []
        }

    return {
        "found": True,
        "results": results
    }