"""Processing scans returned by the nmap agent."""
from typing import Dict

from agent import markdown

def get_technical_details(scans: Dict) -> str:
    """Returns a markdown table of the technical report of the scan.
    Each row presents a service with the host, port, version, protocol, state, and service name.
    Args:
        scans : Dictionary of the scans.
    Returns:
        technical_detail : Markdown table of the scans results.
    """
    scans = markdown.prepare_data_for_markdown_formatting(scans)
    technical_detail = markdown.table_markdown(scans)
    return technical_detail
