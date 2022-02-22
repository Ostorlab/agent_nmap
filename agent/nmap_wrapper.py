"""Wrapper for Nmap Network Scanner."""

import ipaddress
import logging
import subprocess
from typing import Any, Dict, List

from agent import nmap_options

import xmltodict

logger = logging.getLogger(__name__)


def _parse_output(xml_output: str) -> Dict[str, Any]:
    """Parse the xml_output of the nmap scan command.

    Args:
        xml_output: output of the nmap scan command.

    Returns:
        dict of the scan's result.
    """
    parsed_xml = xmltodict.parse(xml_output)
    return parsed_xml


class NmapWrapper:
    """Wrapper class for the Nmap Security Scanner."""

    def __init__(self, options: nmap_options.NmapOptions) -> None:
        """Constructs all the necessary attributes for the object.

        Args:
            options: options of the nmap scan.
        """
        self._options = options

    def _construct_command(self, host: str, mask: str = '32') -> List[str]:
        """
        Construct the Nmap command to be run.

        Args:
            host: which host to be scanned.
            mask: mask to be used in the scan.

        Returns:
            list of the arguments that will be used to run the scan process.
        """
        ip_version = ipaddress.ip_address(host).version
        if ip_version == 6:
            hosts_and_mask = f'-6 {host}/{mask}'
        else:
            hosts_and_mask = f'{host}/{mask}'

        command = ['nmap',
                   *self._options.command_options,
                   '-oX',
                   '-',
                   hosts_and_mask]
        return command

    def scan(self, hosts: str, mask: str = '') -> Dict[str, Any]:
        """Run the scan with nmap.

        Args:
            hosts: which hosts to be scanned.
            mask: mask to be used in the scan.

        Returns:
            result of the scan.
        """
        command = self._construct_command(hosts, mask)
        with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
            xml_output = process.communicate()[0]
            xml_output = xml_output.decode(encoding='utf-8')
            scan_results = _parse_output(xml_output)
            return scan_results
