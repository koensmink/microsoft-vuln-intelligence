def text_value(value):
    if isinstance(value, dict):
        return value.get("Value") or value.get("value") or value.get("Title") or value.get("Name")
    if isinstance(value, list):
        return text_value(value[0]) if value else None
    return value if isinstance(value, str) else None


first_text = text_value


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}
    return bool(value)


def build_product_map(product_tree: dict) -> dict[str, dict]:
    products = {}

    def add_product(item: dict, family: str | None = None):
        product_id = item.get("ProductID") or item.get("ProductId")
        if product_id:
            products[product_id] = {
                "product_id": product_id,
                "name": text_value(item) or item.get("Name") or product_id,
                "cpe": item.get("CPE"),
                "family": family,
            }

    for item in as_list(product_tree.get("FullProductName")):
        if isinstance(item, dict):
            add_product(item)

    def walk_branch(branch: dict, family: str | None = None):
        name = branch.get("Name") or family
        for item in as_list(branch.get("FullProductName")):
            if isinstance(item, dict):
                add_product(item, name)
        for child in as_list(branch.get("Branch")):
            if isinstance(child, dict):
                walk_branch(child, name)

    for branch in as_list(product_tree.get("Branch")):
        if isinstance(branch, dict):
            walk_branch(branch)

    return products


def product_ids(value) -> list[str]:
    ids = []
    for item in as_list(value):
        if isinstance(item, str):
            ids.append(item)
        elif isinstance(item, dict):
            ids.extend(product_ids(item.get("ProductID") or item.get("ProductId")))
    return ids


def parse_cvrf(document: dict, release_name: str) -> dict:
    tracking = document.get("DocumentTracking", {}) or {}
    product_map = build_product_map(document.get("ProductTree", {}) or {})
    cves = []

    for vulnerability in as_list(document.get("Vulnerability")):
        if not isinstance(vulnerability, dict):
            continue
        cve_id = vulnerability.get("CVE")
        if not cve_id:
            continue

        notes = as_list(vulnerability.get("Notes"))
        description = next(
            (text_value(note) for note in notes if isinstance(note, dict) and note.get("Type") == "Description"),
            None,
        )
        statuses = {}
        for status in as_list(vulnerability.get("ProductStatuses")):
            if isinstance(status, dict):
                for pid in product_ids(status.get("ProductID")):
                    statuses[pid] = status.get("Type")

        products = {pid: {**product_map.get(pid, {"product_id": pid, "name": pid}), "status": status} for pid, status in statuses.items()}
        product_data = {pid: {"status": data.get("status")} for pid, data in products.items()}

        for threat in as_list(vulnerability.get("Threats")):
            if not isinstance(threat, dict):
                continue
            key = "impact" if threat.get("Type") in (0, "0", "Impact") else "severity" if threat.get("Type") in (3, "3", "Severity", "Maximum Severity") else None
            if not key:
                continue
            for pid in product_ids(threat.get("ProductID")) or list(product_data):
                product_data.setdefault(pid, {})[key] = text_value(threat.get("Description"))

        for score in as_list(vulnerability.get("CVSSScoreSets")):
            if not isinstance(score, dict):
                continue
            for pid in product_ids(score.get("ProductID")) or list(product_data):
                product_data.setdefault(pid, {}).update(
                    cvss_base_score=score.get("BaseScore"),
                    cvss_temporal_score=score.get("TemporalScore"),
                    cvss_vector=score.get("Vector"),
                )

        remediations = []
        for remediation in as_list(vulnerability.get("Remediations")):
            if isinstance(remediation, dict):
                pids = product_ids(remediation.get("ProductID")) or [None]
                for pid in pids:
                    remediations.append(
                        {
                            "product_id": pid,
                            "remediation_type": str(remediation.get("Type")) if remediation.get("Type") is not None else None,
                            "subtype": remediation.get("SubType"),
                            "description": text_value(remediation.get("Description")),
                            "url": remediation.get("URL"),
                        }
                    )

        cves.append(
            {
                "cve_id": cve_id,
                "title": text_value(vulnerability.get("Title")),
                "description": description,
                "release_date": vulnerability.get("ReleaseDate"),
                "revision_history": vulnerability.get("RevisionHistory"),
                "publicly_disclosed": parse_bool(vulnerability.get("PubliclyDisclosed")),
                "exploited": parse_bool(vulnerability.get("Exploited")),
                "products": products,
                "product_data": product_data,
                "remediations": remediations,
                "severity": next((d.get("severity") for d in product_data.values() if d.get("severity")), None),
                "cvss_score": max((d.get("cvss_base_score") for d in product_data.values() if d.get("cvss_base_score") is not None), default=None),
            }
        )

    return {
        "release": {
            "release_name": release_name,
            "document_title": text_value(document.get("DocumentTitle")),
            "release_date": tracking.get("InitialReleaseDate"),
            "revision_date": tracking.get("CurrentReleaseDate"),
        },
        "products": product_map,
        "cves": cves,
    }
