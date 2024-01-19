"""Processing scans returned by the nmap agent."""
from typing import Dict, List

from agent import markdown


def get_technical_details(
    scans: Dict[
        str, Dict[str, List[Dict[str, Dict[str, str]]] | Dict[str, Dict[str, str]]]
    ],
) -> str:
    """Returns a markdown table of the technical report of the scan.
    Each row presents a service with the host, port, version, protocol, state, and service name.
    Args:
        scans : Dictionary of the scans.
    Returns:
        technical_detail : Markdown table of the scans results.
    """
    prepared_scans = markdown.prepare_data_for_markdown_formatting(scans)
    technical_detail = markdown.table_markdown(prepared_scans)
    return technical_detail
