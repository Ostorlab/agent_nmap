"""Module responsible for markdown formatting."""
from typing import Dict, List
import io

from pytablewriter import MarkdownTableWriter
from agent import generators

def prepare_data_for_markdown_formatting(scans: Dict) -> List[List[str]]:
    """Method responsible for formatting the data into the correct form for the MarkdownTableWriter.
    Args:
        scans: Dictionary containing the scans, from the nmap scan response.
    Returns:
        data: List of lists, each containing the name of the host, port, version, protocol, state,
        and service of its scan.
    """
    scan_data = []
    if scans is not None:
        for data in generators.get_services(scans):
            row = [data['host'], data['port'], data['version'], data['protocol'], data['state'], data['service']]
            scan_data.append(row)
    return scan_data


def table_markdown(data: List[List[str]]) -> str:
    """Method responsible for generating a markdown table from a dictionary.
    Args:
        data: List of the data to be transformed into markdown table.
    Returns:
        table: Complete markdown table
    """
    headers = ['Host', 'Port', 'Version', 'Protocol', 'State', 'Service']
    markdown_writer = MarkdownTableWriter(
        headers=headers,
        value_matrix=data
    )
    markdown_writer.stream = io.StringIO()
    markdown_writer.write_table()
    table = markdown_writer.stream.getvalue()
    # Two spaces \n for a new line  in markdown.
    table = table.replace('\n', '  \n')

    return table
