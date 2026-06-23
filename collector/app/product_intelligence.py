from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import text


RAW_PRODUCT_NAME_COLUMN = "name"


@dataclass(frozen=True)
class ProductMappingResult:
    product_family: str
    product_category: str
    confidence: float = 1.0
    source: str = "rule"


def map_product_name(raw_name: str | None) -> ProductMappingResult:
    """Map the canonical raw product name from products.name to rollup labels."""
    name = (raw_name or "").strip()
    if not name:
        return ProductMappingResult("Unknown", "Unknown", 1.0)

    value = name.lower()

    rules: list[tuple[tuple[str, ...], str, str, float]] = [
        (("azure stack",), "Azure Stack", "Cloud Platform", 0.98),
        (("azure kubernetes service", "aks"), "Azure Kubernetes Service", "Cloud Platform", 0.98),
        (("azure devops",), "Azure DevOps", "Developer Tools", 0.98),
        (("microsoft .net framework", ".net framework", "asp.net", ".net"), ".NET", "Runtime / Framework", 0.96),
        (("windows server",), "Windows Server", "Operating System", 0.98),
        (("windows 11 version",), "Windows 11", "Operating System", 0.97),
        (("windows 11",), "Windows 11", "Operating System", 0.97),
        (("windows 10 version",), "Windows 10", "Operating System", 0.97),
        (("windows 10",), "Windows 10", "Operating System", 0.97),
        (("microsoft 365 apps",), "Microsoft 365 Apps", "Productivity", 0.98),
        (("microsoft 365",), "Microsoft 365", "Productivity", 0.96),
        (("azure active directory", "entra"), "Entra ID", "Identity", 0.96),
        (("power platform", "power apps", "power automate", "power bi"), "Power Platform", "Business Applications", 0.95),
        (("sql server",), "SQL Server", "Database", 0.98),
        (("windows print spooler", "print spooler"), "Windows Print Spooler", "Operating System Component", 0.96),
        (("remote desktop", "rdp"), "Remote Desktop Services", "Operating System Component", 0.95),
        (("exchange",), "Exchange Server", "Messaging", 0.96),
        (("sharepoint",), "SharePoint Server", "Collaboration", 0.96),
        (("visual studio",), "Visual Studio", "Developer Tools", 0.96),
        (("github",), "GitHub", "Developer Tools", 0.96),
        (("defender",), "Microsoft Defender", "Security", 0.95),
        (("teams",), "Microsoft Teams", "Collaboration", 0.95),
        (("onedrive",), "OneDrive", "Collaboration", 0.95),
        (("dynamics",), "Dynamics 365", "Business Applications", 0.95),
        (("copilot",), "Microsoft Copilot", "AI", 0.92),
        (("hyper-v", "hyper v"), "Hyper-V", "Virtualization", 0.96),
        (("edge", "chromium"), "Microsoft Edge", "Browser", 0.90),
        (("office", "word", "excel", "powerpoint", "outlook", "access", "visio", "publisher"), "Microsoft Office", "Productivity", 0.92),
        (("windows", "win32k", "nt os", "kernel", "http.sys", "netlogon", "remote desktop"), "Windows", "Operating System", 0.90),
        (("apache", "linux", "gnutls", "openssl", "git", "curl", "qt"), "Third-Party / Open Source", "Third-Party Component", 0.90),
        (("azure",), "Azure", "Cloud Platform", 0.90),
    ]

    for needles, family, category, confidence in rules:
        if any(needle in value for needle in needles):
            return ProductMappingResult(family, category, confidence)

    return ProductMappingResult("Other Microsoft Product", "Unknown", 0.50)


def upsert_product_mapping(conn, raw_name: str | None) -> ProductMappingResult:
    """Classify and persist a raw product name in product_mappings.

    The canonical raw product name is products.name. Keeping this helper beside
    map_product_name makes collector sync and backfills use the same idempotent
    upsert semantics.
    """
    name = (raw_name or "").strip()
    mapping = map_product_name(name)
    now = datetime.now(timezone.utc)
    conn.execute(
        text(
            """
            INSERT INTO product_mappings (raw_name, product_family, product_category, confidence, source, created_at, updated_at)
            VALUES (:raw_name, :product_family, :product_category, :confidence, :source, :created_at, :updated_at)
            ON CONFLICT (raw_name) DO UPDATE SET
                product_family = EXCLUDED.product_family,
                product_category = EXCLUDED.product_category,
                confidence = EXCLUDED.confidence,
                source = EXCLUDED.source,
                updated_at = EXCLUDED.updated_at
            """
        ),
        {
            "raw_name": name,
            "product_family": mapping.product_family,
            "product_category": mapping.product_category,
            "confidence": mapping.confidence,
            "source": mapping.source,
            "created_at": now,
            "updated_at": now,
        },
    )
    return mapping
