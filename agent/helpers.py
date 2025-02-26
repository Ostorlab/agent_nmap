import json
from typing import Any

from ostorlab.agent.mixins import agent_report_vulnerability_mixin


def compute_dna(
    vulnerability_title: str,
    vuln_location: agent_report_vulnerability_mixin.VulnerabilityLocation | None,
    technical_detail: str,
) -> str:
    """Compute a deterministic, debuggable DNA representation for a vulnerability.

    Args:
        vulnerability_title: The title of the vulnerability.
        vuln_location: The location of the vulnerability.
        technical_detail:

    Returns:
        A deterministic JSON representation of the vulnerability DNA.
    """
    dna_data: dict[str, Any] = {
        "title": vulnerability_title,
        "technical_detail": technical_detail,
    }

    if vuln_location is not None:
        location_dict: dict[str, Any] = vuln_location.to_dict()
        sorted_location_dict = sort_dict(location_dict)
        dna_data["location"] = sorted_location_dict

    return json.dumps(dna_data, sort_keys=True)


def sort_dict(d: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Recursively sort dictionary keys and lists within.

    Args:
        d: The dictionary or list to sort.

    Returns:
        A sorted dictionary or list.
    """
    if isinstance(d, dict):
        return {k: sort_dict(v) for k, v in sorted(d.items())}
    if isinstance(d, list):
        return sorted(
            d,
            key=lambda x: json.dumps(x, sort_keys=True)
            if isinstance(x, dict)
            else str(x),
        )
    return d
