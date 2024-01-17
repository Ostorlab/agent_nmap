"""Wrapper for Nmap Network Scanner."""

import ipaddress
import logging
import subprocess
import xml
from typing import Any, Dict, List, Tuple

import xmltodict

from agent import nmap_options

XML_OUTPUT_PATH = "/tmp/xmloutput"
NORMAL_OUTPUT_PATH = "/tmp/normal"

logger = logging.getLogger(__name__)


def parse_output(xml_output: str) -> dict[str, Any]:
    """Parse the xml_output of the nmap scan command.

    Args:
        xml_output: output of the nmap scan command.

    Returns:
        dict of the scan's result.
    """
    try:
        parsed_xml: dict[str, Any] = xmltodict.parse(xml_output, disable_entities=True)
        return parsed_xml
    except xml.parsers.expat.ExpatError as parsing_error:
        logger.error(
            "Error parsing XML output: %s - XML output: %s", parsing_error, xml_output
        )
        raise


class NmapWrapper:
    """Wrapper class for the Nmap Security Scanner."""

    def __init__(self, options: nmap_options.NmapOptions) -> None:
        """Constructs all the necessary attributes for the object.

        Args:
            options: options of the nmap scan.
        """
        self._options = options

    def construct_command_host(self, host: str, mask: int) -> List[str]:
        """
        Construct the Nmap command to be run.

        Args:
            host: which host to be scanned.
            mask: mask to be used in the scan.

        Returns:
            list of the arguments that will be used to run the scan process.
        """
        ip_version = ipaddress.ip_address(host).version
        command = [
            "nmap",
            *self._options.command_options,
            "-oX",
            XML_OUTPUT_PATH,
            "-oN",
            NORMAL_OUTPUT_PATH,
        ]
        if ip_version == 6:
            command.append("-6")
        command.append(f"{host}/{mask}")
        return command

    def _construct_command_domain(self, domain_name: str) -> List[str]:
        """
        Construct the Nmap command to be run.

        Args:
            domain: which domain to be scanned.

        Returns:
            list of the arguments that will be used to run the scan process.
        """
        command = [
            "nmap",
            *self._options.command_options,
            "-oX",
            XML_OUTPUT_PATH,
            "-oN",
            NORMAL_OUTPUT_PATH,
            domain_name,
        ]
        return command

    def scan_hosts(self, hosts: str, mask: int) -> Tuple[Dict[str, Any], str]:
        """Run the scan with nmap.

        Args:
            hosts: which hosts to be scanned.
            mask: mask to be used in the scan.

        Returns:
            result of the scan.
        """
        logger.info("running the nmap scan")
        command = self.construct_command_host(hosts, mask)

        subprocess.run(command, check=True)

        with open(XML_OUTPUT_PATH, "r", encoding="utf-8") as o:
            scan_results = parse_output(o.read())

        with open(NORMAL_OUTPUT_PATH, "r", encoding="utf-8") as o:
            normal_results = o.read()

        return scan_results, normal_results

    def scan_domain(self, domain_name: str) -> Tuple[Dict[str, Any], str]:
        """Run the scan with nmap.

        Args:
            domain_name: which domain name to be scanned.

        Returns:
            result of the scan.
        """
        logger.info("running the nmap scan")
        command = self._construct_command_domain(domain_name)
        subprocess.run(command, check=True)

        with open(XML_OUTPUT_PATH, "r", encoding="utf-8") as o:
            scan_results = parse_output(o.read())

        with open(NORMAL_OUTPUT_PATH, "r", encoding="utf-8") as o:
            normal_results = o.read()

        return scan_results, normal_results
