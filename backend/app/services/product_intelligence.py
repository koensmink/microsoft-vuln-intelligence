from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ProductMappingResult:
    product_family: str
    product_category: str
    confidence: float = 1.0
    source: str = "rule"


def _has_token(value: str, token: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", value) is not None


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
    name = (raw_name or "").strip()
    if not name:
        return ProductMappingResult("Unknown", "Unknown", 1.0)

    value = name.lower()

    azure_linux_mapping = _map_azure_linux_or_cbl(value)
    if azure_linux_mapping is not None:
        return azure_linux_mapping

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
