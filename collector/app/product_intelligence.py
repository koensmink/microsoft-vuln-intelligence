from __future__ import annotations

from dataclasses import dataclass
import re
from datetime import datetime, timezone

from sqlalchemy import text


RAW_PRODUCT_NAME_COLUMN = "name"


@dataclass(frozen=True)
class ProductMappingResult:
    product_family: str
    product_category: str
    confidence: float = 1.0
    source: str = "rule"


def _has_token(value: str, token: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", value) is not None


def _has_prefix_phrase(value: str, phrase: str) -> bool:
    """Match a product-name prefix without accepting a longer word."""
    return re.match(rf"^{re.escape(phrase)}(?![a-z0-9])", value) is not None


def _is_azure_linux_or_cbl(value: str) -> bool:
    return (
        value.startswith("azl3 ")
        or value.startswith("cbl2 ")
        or " on azure linux " in value
        or " on cbl mariner " in value
    )


def _map_azure_linux_or_cbl(value: str) -> ProductMappingResult | None:
    if not _is_azure_linux_or_cbl(value):
        return None
    if _has_token(value, "kernel"):
        return ProductMappingResult("Azure Linux", "Operating System", 0.98)
    return ProductMappingResult("Azure Linux", "Third-Party Component", 0.95)


def _is_office_product(value: str) -> bool:
    return any(
        _has_token(value, token)
        for token in ("office", "word", "excel", "powerpoint", "outlook", "access", "visio", "publisher")
    )


def map_product_name(raw_name: str | None) -> ProductMappingResult:
    """Map the canonical raw product name from products.name to rollup labels."""
    name = (raw_name or "").strip()
    if not name:
        return ProductMappingResult("Unknown", "Unknown", 1.0)

    value = name.lower()

    azure_linux_mapping = _map_azure_linux_or_cbl(value)
    if azure_linux_mapping is not None:
        return azure_linux_mapping

    # High-confidence product names must be resolved before broad family rules.
    explicit_rules: list[tuple[tuple[str, ...], str, str, float]] = [
        (
            (
                "microsoft purview ediscovery",
                "microsoft purview data governance",
                "microsoft purview",
            ),
            "Microsoft Purview",
            "Compliance",
            0.98,
        ),
        (
            ("microsoft partner center",),
            "Microsoft Partner Center",
            "Business Applications",
            0.98,
        ),
        (
            ("system center operations manager", "microsoft configuration manager"),
            "Microsoft System Center",
            "IT Management",
            0.98,
        ),
        (("microsoft account",), "Microsoft Account", "Identity", 0.98),
        (("microsoft authenticator",), "Microsoft Authenticator", "Identity", 0.98),
        (
            ("microsoft confluence saml sso plugin", "microsoft jira saml sso plugin"),
            "Entra ID",
            "Identity",
            0.95,
        ),
        (
            ("microsoft aci confidential containers",),
            "Azure Container Instances",
            "Cloud Platform",
            0.98,
        ),
        (("microsoft power pages",), "Power Platform", "Business Applications", 0.98),
        (("microsoft powerbi",), "Power Platform", "Business Applications", 0.96),
        (
            (
                "microsoft bing images",
                "microsoft bing search for android",
                "microsoft bing search for ios",
                "microsoft bing",
            ),
            "Microsoft Bing",
            "Online Services",
            0.98,
        ),
        (
            ("microsoft malware protection engine",),
            "Microsoft Defender",
            "Security",
            0.99,
        ),
        (("microsoft loop",), "Microsoft 365 Apps", "Productivity", 0.96),
        (("microsoft onenote",), "Microsoft 365 Apps", "Productivity", 0.98),
        (("microsoft graph",), "Microsoft Graph", "Developer Tools", 0.98),
        (("microsoft pc manager",), "Windows", "Operating System Component", 0.96),
        (("microsoft powertoys",), "Windows", "Operating System Component", 0.98),
        (
            ("microsoft fabric", "fabric data warehouse"),
            "Microsoft Fabric",
            "Data Platform",
            0.98,
        ),
        (
            ("nuance powerscribe", "powerscribe one"),
            "Nuance PowerScribe",
            "Healthcare",
            0.99,
        ),
        (("minecraft", "age of empires"), "Xbox / Gaming", "Gaming", 0.98),
        (("microsoft hpc pack",), "Microsoft HPC Pack", "Compute Platform", 0.98),
    ]
    for phrases, family, category, confidence in explicit_rules:
        if any(_has_prefix_phrase(value, phrase) for phrase in phrases):
            return ProductMappingResult(family, category, confidence)

    if re.match(r"^powershell\s+v?\d+(?:\.\d+)*\b", value):
        return ProductMappingResult("PowerShell", "Runtime / Framework", 0.99)

    if any(
        re.match(pattern, value)
        for pattern in (
            r"^microsoft\.bcl\.(?=[a-z0-9])",
            r"^microsoft\.aspnet\.odata(?:\b|\.)",
            r"^microsoft\.aspnetcore\.odata(?:\b|\.)",
        )
    ):
        return ProductMappingResult(".NET", "Runtime / Framework", 0.98)

    if any(
        re.match(pattern, value)
        for pattern in (
            r"^microsoft surface(?:\b|\s)",
            r"^surface laptop(?:\b|\s)",
            r"^surface management services(?:\b|\s)",
        )
    ):
        return ProductMappingResult("Microsoft Surface", "Hardware", 0.98)

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
        (("windows", "win32k", "nt os", "kernel", "http.sys", "netlogon", "remote desktop"), "Windows", "Operating System", 0.90),
        (("apache", "linux", "gnutls", "openssl", "git", "curl", "qt"), "Third-Party / Open Source", "Third-Party Component", 0.90),
        (("azure",), "Azure", "Cloud Platform", 0.90),
    ]

    for needles, family, category, confidence in rules:
        if family == "Windows" and _is_office_product(value):
            return ProductMappingResult("Microsoft Office", "Productivity", 0.92)
        if any(needle in value for needle in needles):
            return ProductMappingResult(family, category, confidence)

    if _is_office_product(value):
        return ProductMappingResult("Microsoft Office", "Productivity", 0.92)

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
