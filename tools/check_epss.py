import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def check_epss(cve_id: str) -> str:
    epss_result = _fetch_epss(cve_id)
    kev_result = _check_cisa_kev(cve_id)
    return f"{epss_result}\n\n{kev_result}"


def _fetch_epss(cve_id: str) -> str:
    try:
        response = requests.get(
            EPSS_URL,
            params={"cve": cve_id},
            headers={"User-Agent": "CVE-Triage-Agent/1.0"},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        entries = data.get("data", [])
        if entries:
            entry = entries[0]
            score = float(entry["epss"])
            percentile = float(entry["percentile"])
            return (
                f"EPSS Score: {score:.4f} ({score * 100:.2f}% probability of exploitation in next 30 days)\n"
                f"EPSS Percentile: {percentile:.4f} (scores higher than {percentile * 100:.1f}% of all CVEs)"
            )
        return "EPSS Score: Not available for this CVE."
    except requests.exceptions.RequestException as e:
        return f"EPSS lookup failed: {str(e)}"


def _check_cisa_kev(cve_id: str) -> str:
    try:
        response = requests.get(
            CISA_KEV_URL,
            headers={"User-Agent": "CVE-Triage-Agent/1.0"},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

        for vuln in data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return (
                    f"CISA KEV Status: LISTED — confirmed active exploitation in the wild\n"
                    f"Product: {vuln.get('vendorProject', 'N/A')} {vuln.get('product', 'N/A')}\n"
                    f"Date Added to KEV: {vuln.get('dateAdded', 'N/A')}\n"
                    f"Required Action: {vuln.get('requiredAction', 'N/A')}\n"
                    f"Due Date: {vuln.get('dueDate', 'N/A')}"
                )

        return "CISA KEV Status: Not listed (no confirmed active exploitation reported to CISA)."
    except requests.exceptions.RequestException as e:
        return f"CISA KEV lookup failed: {str(e)}"
