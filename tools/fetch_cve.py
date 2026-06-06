import time
import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str) -> str:
    url = f"{NVD_BASE_URL}?cveId={cve_id}"
    headers = {"User-Agent": "CVE-Triage-Agent/1.0"}

    for attempt in range(3):
        try:
            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 404:
                return f"CVE {cve_id} not found in NVD database."

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 6))
                time.sleep(retry_after)
                continue

            if response.status_code == 503:
                time.sleep(6)
                continue

            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return f"No data found for {cve_id}."

            cve_item = vulnerabilities[0].get("cve", {})
            return _parse_cve(cve_id, cve_item)

        except requests.exceptions.Timeout:
            if attempt == 2:
                return f"Timeout fetching {cve_id} after 3 attempts."
            time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            if attempt == 2:
                return f"Network error fetching {cve_id}: {str(e)}"
            time.sleep(2 ** attempt)

    return f"Failed to fetch {cve_id} after 3 attempts."


def _parse_cve(cve_id: str, cve_item: dict) -> str:
    descriptions = cve_item.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available."
    )

    cvss_score = "N/A"
    cvss_severity = "N/A"
    cvss_vector = "N/A"
    metrics = cve_item.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            primary = next(
                (m for m in metric_list if m.get("type") == "Primary"),
                metric_list[0]
            )
            cvss_data = primary.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", "N/A")
            cvss_severity = cvss_data.get("baseSeverity", "N/A")
            cvss_vector = cvss_data.get("vectorString", "N/A")
            break

    weaknesses = cve_item.get("weaknesses", [])
    cwe_ids = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    cwe_str = ", ".join(cwe_ids) if cwe_ids else "None identified"

    configurations = cve_item.get("configurations", [])
    affected_products = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    cpe_name = cpe_match.get("criteria", "")
                    parts = cpe_name.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        version_info = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else ""
                        version_start = cpe_match.get("versionStartIncluding", "")
                        version_end = cpe_match.get("versionEndIncluding", "")
                        version_end_excl = cpe_match.get("versionEndExcluding", "")

                        entry = f"{vendor}/{product}"
                        if version_info:
                            entry += f" v{version_info}"
                        elif version_start or version_end or version_end_excl:
                            if version_start:
                                entry += f" >={version_start}"
                            if version_end:
                                entry += f" <={version_end}"
                            if version_end_excl:
                                entry += f" <{version_end_excl}"
                        affected_products.append(entry)

    if len(affected_products) > 10:
        affected_products = affected_products[:10]
        affected_products.append("... (truncated)")

    products_str = "\n  - ".join(affected_products) if affected_products else "Not specified"
    published = cve_item.get("published", "Unknown")[:10]

    return f"""CVE ID: {cve_id}
Published: {published}
Description: {description}

CVSS v3 Score: {cvss_score}
CVSS Severity: {cvss_severity}
CVSS Vector: {cvss_vector}

CWE IDs: {cwe_str}

Affected Products (CPE):
  - {products_str}"""
