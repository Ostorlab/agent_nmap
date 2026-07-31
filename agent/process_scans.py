"""Processing scans returned by the nmap agent."""

from agent import markdown


def get_technical_details(
    scans: dict[
        str, dict[str, list[dict[str, dict[str, str]]] | dict[str, dict[str, str]]]
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
