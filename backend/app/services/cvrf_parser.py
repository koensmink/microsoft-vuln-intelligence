def first_text(value):
    if isinstance(value, dict):
        return value.get("Value") or value.get("value") or next((v for v in value.values() if isinstance(v, str)), None)
    if isinstance(value, list):
        return first_text(value[0]) if value else None
    return value if isinstance(value, str) else None

def parse_cvrf(document: dict, release_name: str) -> dict:
    tracking = document.get("DocumentTracking", {})
    title = first_text(document.get("DocumentTitle"))
    release = {"release_name": release_name, "document_title": title, "release_date": tracking.get("InitialReleaseDate"), "revision_date": tracking.get("CurrentReleaseDate")}
    product_tree = document.get("ProductTree", {})
    products = {}
    for branch in product_tree.get("FullProductName", []) or []:
        if isinstance(branch, dict):
            products[branch.get("ProductID")] = branch.get("Value") or branch.get("Name")
    cves = []
    for vuln in document.get("Vulnerability", []) or []:
        cve_id = vuln.get("CVE")
        if not cve_id:
            continue
        notes = vuln.get("Notes", []) or []
        description = next((first_text(n) for n in notes if isinstance(n, dict) and n.get("Type") == "Description"), None)
        threats = vuln.get("Threats", []) or []
        impact = next((first_text(t.get("Description")) for t in threats if isinstance(t, dict) and t.get("Type") == "Impact"), None)
        scores = vuln.get("CVSSScoreSets", []) or []
        score = scores[0].get("BaseScore") if scores and isinstance(scores[0], dict) else None
        cves.append({"cve_id": cve_id, "title": first_text(vuln.get("Title")), "description": description, "severity": vuln.get("Severity"), "cvss_score": score, "impact": impact, "publicly_disclosed": bool(vuln.get("PubliclyDisclosed")), "exploited": bool(vuln.get("Exploited")), "products": products, "remediations": vuln.get("Remediations", []) or []})
    return {"release": release, "cves": cves}
