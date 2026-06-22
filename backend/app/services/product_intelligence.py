from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProductMappingResult:
    product_family: str
    product_category: str
    confidence: float = 1.0
    source: str = "rule"


def map_product_name(raw_name: str | None) -> ProductMappingResult:
    name = (raw_name or "").strip()
    if not name:
        return ProductMappingResult("Unknown", "Unknown", 1.0)

    value = name.lower()

    rules: list[tuple[tuple[str, ...], str, str, float]] = [
        (("azure stack",), "Azure Stack", "Cloud Platform", 0.98),
        (("windows server",), "Windows Server", "Operating System", 0.98),
        (("microsoft 365 apps",), "Microsoft 365 Apps", "Productivity", 0.98),
        (("azure active directory", "entra"), "Entra ID", "Identity", 0.96),
        (("power platform", "power apps", "power automate", "power bi"), "Power Platform", "Business Applications", 0.95),
        (("sql server",), "SQL Server", "Database", 0.98),
        (("exchange",), "Exchange Server", "Messaging", 0.96),
        (("sharepoint",), "SharePoint Server", "Collaboration", 0.96),
        (("visual studio",), "Visual Studio", "Developer Tools", 0.96),
        (("asp.net", ".net"), ".NET", "Runtime / Framework", 0.96),
        (("defender",), "Microsoft Defender", "Security", 0.95),
        (("teams",), "Microsoft Teams", "Collaboration", 0.95),
        (("onedrive",), "OneDrive", "Collaboration", 0.95),
        (("dynamics",), "Dynamics 365", "Business Applications", 0.95),
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
