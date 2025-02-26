from typing import Any

from ostorlab.assets import domain_name as domain_name_asset
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
import pytest

from agent import helpers


def testComputeDna_whenSameDomainDifferentPaths_returnsDifferentDna() -> None:
    """Ensure that when the same domain/asset with different metadata, ComputeDna returns different DNA."""
    vulnerability_title = "Vulnerability Title Unordered Dict"

    metadata_1 = []
    metadata_1.append(
        vuln_mixin.VulnerabilityLocationMetadata(
            metadata_type=vuln_mixin.MetadataType.PORT,
            value="8080",
        )
    )
    metadata_1.append(
        vuln_mixin.VulnerabilityLocationMetadata(
            metadata_type=vuln_mixin.MetadataType.PORT,
            value="8081",
        )
    )
    metadata_2 = []
    metadata_2.append(
        vuln_mixin.VulnerabilityLocationMetadata(
            metadata_type=vuln_mixin.MetadataType.PORT,
            value="9080",
        )
    )
    metadata_2.append(
        vuln_mixin.VulnerabilityLocationMetadata(
            metadata_type=vuln_mixin.MetadataType.PORT,
            value="8081",
        )
    )
    asset = domain_name_asset.DomainName(name="www.google.com")
    vuln_location_1 = vuln_mixin.VulnerabilityLocation(
        metadata=metadata_1,
        asset=asset,
    )
    vuln_location_2 = vuln_mixin.VulnerabilityLocation(
        metadata=metadata_2,
        asset=asset,
    )

    dna_1 = helpers.compute_dna(
        vulnerability_title, vuln_location_1, "technical_detail"
    )
    dna_2 = helpers.compute_dna(
        vulnerability_title, vuln_location_2, "technical_detail"
    )

    assert dna_1 is not None
    assert dna_2 is not None
    assert dna_1 != dna_2
    assert (
        dna_1
        == '{"location": {"domain_name": {"name": "www.google.com"}, "metadata": [{"type": "PORT", "value": "8080"}, {"type": "PORT", "value": "8081"}]}, "technical_detail": "technical_detail", "title": "Vulnerability Title Unordered Dict"}'
    )
    assert (
        dna_2
        == '{"location": {"domain_name": {"name": "www.google.com"}, "metadata": [{"type": "PORT", "value": "8081"}, {"type": "PORT", "value": "9080"}]}, "technical_detail": "technical_detail", "title": "Vulnerability Title Unordered Dict"}'
    )


def testComputeDna_whenUnorderedDict_returnsConsistentDna() -> None:
    """Ensure that ComputeDna returns a consistent DNA when vuln_location dictionary keys are unordered."""

    vulnerability_title = "Vulnerability Title Unordered Dict"

    metadata = []
    metadata.append(
        vuln_mixin.VulnerabilityLocationMetadata(
            metadata_type=vuln_mixin.MetadataType.PORT,
            value="8080",
        )
    )
    metadata.append(
        vuln_mixin.VulnerabilityLocationMetadata(
            metadata_type=vuln_mixin.MetadataType.PORT,
            value="8081",
        )
    )
    asset = domain_name_asset.DomainName(name="www.google.com")
    vuln_location_1 = vuln_mixin.VulnerabilityLocation(
        metadata=metadata,
        asset=asset,
    )
    vuln_location_2 = vuln_mixin.VulnerabilityLocation(
        metadata=metadata,
        asset=asset,
    )

    assert vuln_location_1 is not None
    assert vuln_location_2 is not None

    vuln_location_2.metadata = vuln_location_2.metadata[::-1]

    dna_1 = helpers.compute_dna(
        vulnerability_title, vuln_location_1, "technical_detail"
    )
    dna_2 = helpers.compute_dna(
        vulnerability_title, vuln_location_2, "technical_detail"
    )

    assert dna_1 is not None
    assert dna_2 is not None
    assert dna_1 == dna_2


@pytest.mark.parametrize(
    "unordered_dict, expected",
    [
        # Case: Dictionary keys are unordered
        ({"b": 2, "a": 1, "c": 3}, {"a": 1, "b": 2, "c": 3}),
        # Case: Nested dictionaries are also sorted
        ({"z": {"b": 2, "a": 1}, "y": 3}, {"y": 3, "z": {"a": 1, "b": 2}}),
        # Case: Lists inside dictionaries remain unchanged
        ({"list": [3, 1, 2], "key": "value"}, {"key": "value", "list": [1, 2, 3]}),
        # Case: Lists containing dictionaries get sorted by keys
        (
            {"list": [{"b": 2, "a": 1}, {"d": 4, "c": 3}]},
            {"list": [{"a": 1, "b": 2}, {"c": 3, "d": 4}]},
        ),
        # Case: Empty dictionary remains unchanged
        ({}, {}),
        # Case: Dictionary with single key remains unchanged
        ({"a": 1}, {"a": 1}),
    ],
)
def testSortDict_always_returnsSortedDict(
    unordered_dict: dict[str, Any], expected: dict[str, Any]
) -> None:
    """Ensure sort_dict correctly sorts dictionary keys recursively."""
    assert helpers.sort_dict(unordered_dict) == expected
