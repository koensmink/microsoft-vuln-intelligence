from collections.abc import Iterable


def first_text(value):
    if isinstance(value, dict):
        return value.get("Value") or value.get("value") or value.get("Name") or next((v for v in value.values() if isinstance(v, str)), None)
    if isinstance(value, list):
        return first_text(value[0]) if value else None
    return value if isinstance(value, str) else None


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def product_catalog(product_tree: dict) -> dict[str, dict[str, str | None]]:
    catalog: dict[str, dict[str, str | None]] = {}
    for product in as_list(product_tree.get("FullProductName")):
        if isinstance(product, dict) and product.get("ProductID"):
            catalog[product["ProductID"]] = {"name": first_text(product), "family": product.get("ProductFamilyName"), "vendor": "Microsoft"}
    for branch in as_list(product_tree.get("Branch")):
        if not isinstance(branch, dict):
            continue
        family = branch.get("Name")
        for product in as_list(branch.get("FullProductName")):
            if isinstance(product, dict) and product.get("ProductID"):
                catalog[product["ProductID"]] = {"name": first_text(product), "family": family, "vendor": "Microsoft"}
    return catalog


def affected_products(vulnerability: dict, catalog: dict[str, dict[str, str | None]]) -> list[dict]:
    affected: dict[str, dict] = {}
    for status in as_list(vulnerability.get("ProductStatuses")):
        if not isinstance(status, dict):
            continue
        for product_id in as_list(status.get("ProductID")):
            if product_id in catalog:
                affected[product_id] = {"product_id": product_id, "product": catalog[product_id], "fixed_build": None, "kb_article": None, "download_url": None}
    for remediation in as_list(vulnerability.get("Remediations")):
        if not isinstance(remediation, dict):
            continue
        for product_id in as_list(remediation.get("ProductID")):
            if product_id in catalog:
                item = affected.setdefault(product_id, {"product_id": product_id, "product": catalog[product_id], "fixed_build": None, "kb_article": None, "download_url": None})
                item["kb_article"] = remediation.get("Description") or item.get("kb_article")
                item["download_url"] = remediation.get("URL") or item.get("download_url")
                item["fixed_build"] = remediation.get("FixedBuild") or item.get("fixed_build")
    return list(affected.values())


def parse_remediations(vulnerability: dict) -> list[dict[str, str | None]]:
    remediations = []
    for remediation in as_list(vulnerability.get("Remediations")):
        if isinstance(remediation, dict):
            remediations.append({"remediation_type": remediation.get("Type"), "description": remediation.get("Description"), "url": remediation.get("URL")})
    return remediations


def parse_cvrf(document: dict, release_name: str) -> dict:
    tracking = document.get("DocumentTracking", {})
    release = {"release_name": release_name, "document_title": first_text(document.get("DocumentTitle")), "release_date": tracking.get("InitialReleaseDate"), "revision_date": tracking.get("CurrentReleaseDate")}
    catalog = product_catalog(document.get("ProductTree", {}) or {})
    cves = []
    for vuln in as_list(document.get("Vulnerability")):
        if not isinstance(vuln, dict) or not vuln.get("CVE"):
            continue
        notes = as_list(vuln.get("Notes"))
        description = next((first_text(n) for n in notes if isinstance(n, dict) and n.get("Type") == "Description"), None)
        threats = as_list(vuln.get("Threats"))
        impact = next((first_text(t.get("Description")) for t in threats if isinstance(t, dict) and t.get("Type") == "Impact"), None)
        scores = as_list(vuln.get("CVSSScoreSets"))
        score = scores[0].get("BaseScore") if scores and isinstance(scores[0], dict) else None
        cves.append({"cve_id": vuln["CVE"], "title": first_text(vuln.get("Title")), "description": description, "severity": vuln.get("Severity"), "cvss_score": score, "impact": impact, "publicly_disclosed": bool(vuln.get("PubliclyDisclosed")), "exploited": bool(vuln.get("Exploited")), "affected_products": affected_products(vuln, catalog), "remediations": parse_remediations(vuln)})
    return {"release": release, "cves": cves}
