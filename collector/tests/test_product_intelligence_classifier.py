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


def test_collector_and_backend_product_classifiers_match_for_edge_examples() -> None:
    for raw_name in EXAMPLES:
        assert as_tuple(map_product_name(raw_name)) == as_tuple(backend_map_product_name(raw_name))
    assert as_tuple(map_product_name("local-path-provisioner")) == as_tuple(backend_map_product_name("local-path-provisioner"))
