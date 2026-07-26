from collector.app.product_intelligence import map_product_name
from backend.app.services.product_intelligence import map_product_name as backend_map_product_name


EXAMPLES = {
    "azl3 kernel 6.6.112.1-2 on Azure Linux 3.0": ("Azure Linux", "Operating System"),
    "cbl2 kernel 5.15.164.1-1 on CBL Mariner 2.0": ("Azure Linux", "Operating System"),
    "azl3 qemu 8.2.10-8 on Azure Linux 3.0": ("Azure Linux", "Third-Party Component"),
    "cbl2 glibc 2.35-17 on CBL Mariner 2.0": ("Azure Linux", "Third-Party Component"),
    "cbl2 local-path-provisioner 0.0.21-20 on CBL Mariner 2.0": ("Azure Linux", "Third-Party Component"),
    "Microsoft Visio": ("Microsoft Office", "Productivity"),
    "Visio 2024": ("Microsoft Office", "Productivity"),
    "Microsoft Office LTSC": ("Microsoft Office", "Productivity"),
    "Windows Graphics Kernel": ("Windows", "Operating System"),
    "Windows Kernel": ("Windows", "Operating System"),
}

HIGH_CONFIDENCE_EXAMPLES = {
    "Microsoft Purview eDiscovery": ("Microsoft Purview", "Compliance", 0.98),
    "Microsoft Partner Center": (
        "Microsoft Partner Center",
        "Business Applications",
        0.98,
    ),
    "System Center Operations Manager": (
        "Microsoft System Center",
        "IT Management",
        0.98,
    ),
    "Microsoft Account": ("Microsoft Account", "Identity", 0.98),
    "Microsoft Authenticator for Android": (
        "Microsoft Authenticator",
        "Identity",
        0.98,
    ),
    "Microsoft JIRA SAML SSO plugin": ("Entra ID", "Identity", 0.95),
    "Microsoft ACI Confidential Containers": (
        "Azure Container Instances",
        "Cloud Platform",
        0.98,
    ),
    "Microsoft Power Pages": ("Power Platform", "Business Applications", 0.98),
    "Microsoft PowerBI": ("Power Platform", "Business Applications", 0.96),
    "Microsoft Bing Search for iOS": ("Microsoft Bing", "Online Services", 0.98),
    "Microsoft Malware Protection Engine": ("Microsoft Defender", "Security", 0.99),
    "PowerShell 7.5": ("PowerShell", "Runtime / Framework", 0.99),
    "Microsoft.Bcl.Memory 10.0": (".NET", "Runtime / Framework", 0.98),
    "Microsoft Loop": ("Microsoft 365 Apps", "Productivity", 0.96),
    "Microsoft Graph": ("Microsoft Graph", "Developer Tools", 0.98),
    "Microsoft Surface Pro 8": ("Microsoft Surface", "Hardware", 0.98),
    "Microsoft PowerToys": ("Windows", "Operating System Component", 0.98),
    "Fabric Data Warehouse": ("Microsoft Fabric", "Data Platform", 0.98),
    "Nuance PowerScribe 360 4.0": ("Nuance PowerScribe", "Healthcare", 0.99),
    "Age of Empires": ("Xbox / Gaming", "Gaming", 0.98),
    "Microsoft HPC Pack": ("Microsoft HPC Pack", "Compute Platform", 0.98),
    "Microsoft PC Manager": ("Windows", "Operating System Component", 0.96),
}


def as_tuple(mapping):
    return (mapping.product_family, mapping.product_category, mapping.confidence, mapping.source)


def test_collector_product_classifier_handles_azure_linux_cbl_and_office_boundaries() -> None:
    for raw_name, (expected_family, expected_category) in EXAMPLES.items():
        mapping = map_product_name(raw_name)
        assert mapping.product_family == expected_family
        assert mapping.product_category == expected_category


def test_collector_product_classifier_does_not_match_office_terms_inside_unrelated_words() -> None:
    mapping = map_product_name("local-path-provisioner")
    assert mapping.product_family != "Microsoft Office"


def test_collector_product_classifier_handles_high_confidence_products() -> None:
    for raw_name, expected in HIGH_CONFIDENCE_EXAMPLES.items():
        mapping = map_product_name(raw_name)
        assert (mapping.product_family, mapping.product_category, mapping.confidence) == expected


def test_collector_product_classifier_avoids_new_rule_substring_collisions() -> None:
    for raw_name in (
        "NotMicrosoft Bingeworthy",
        "Minecrafting Tools",
        "PowerShell Preview",
        "Contoso Microsoft Purview Connector",
    ):
        assert map_product_name(raw_name).confidence < 0.98

def test_collector_and_backend_product_classifiers_match_for_edge_examples() -> None:
    for raw_name in EXAMPLES | HIGH_CONFIDENCE_EXAMPLES:
        assert as_tuple(map_product_name(raw_name)) == as_tuple(backend_map_product_name(raw_name))
    assert as_tuple(map_product_name("local-path-provisioner")) == as_tuple(backend_map_product_name("local-path-provisioner"))
