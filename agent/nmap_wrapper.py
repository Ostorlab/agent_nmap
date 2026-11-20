"""Wrapper for Nmap Network Scanner."""

import ipaddress
import logging
import subprocess
from typing import Any
from xml.parsers import expat

import xmltodict

from agent import nmap_options
from agent import result_parser

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
    except expat.ExpatError as parsing_error:
        logger.error(
            "Error parsing XML output: %s - XML output: %s", parsing_error, xml_output
        )
        return {}


class NmapWrapper:
    """Wrapper class for the Nmap Security Scanner."""

    def __init__(self, options: nmap_options.NmapOptions) -> None:
        """Constructs all the necessary attributes for the object.

        Args:
            options: options of the nmap scan.
        """
        self._options = options

    def construct_command_host(self, host: str, mask: int) -> list[str]:
        """
        Construct the Nmap command to be run.

        Args:
            host: which host to be scanned.
            mask: mask to be used in the scan.

        Returns:
            list of the arguments that will be used to run the scan process.
        """
        ip_version = ipaddress.ip_address(address=host).version
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

    def _construct_command_domain(
        self, domain_name: str, is_ipv6: bool = False
    ) -> list[str]:
        """
        Construct the Nmap command to be run.

        Args:
            domain: which domain to be scanned.
            is_ipv6: scan the domain's IPv6 address instead of its IPv4 address.

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
        ]
        if is_ipv6 is True:
            command.append("-6")
        command.append(domain_name)
        return command

    def scan_hosts(self, hosts: str, mask: int) -> tuple[dict[str, Any], str]:
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

    def discover_open_ports(self, host: str) -> list[str]:
        """Run a port-only scan of a single IP and return its open ports.

        Args:
            host: IP address to scan.

        Returns:
            Sorted list of open port numbers, empty if none were found or the scan timed out.
        """
        mask = 32 if ipaddress.ip_address(address=host).version == 4 else 128
        logger.info("discovering open ports of %s", host)
        command = self.construct_command_host(host=host, mask=mask)
        subprocess.run(command, check=True)

        with open(XML_OUTPUT_PATH, "r", encoding="utf-8") as o:
            scan_results = parse_output(o.read())

        return result_parser.get_open_ports(scan_results=scan_results)

    def scan_domain(
        self, domain_name: str, is_ipv6: bool = False
    ) -> tuple[dict[str, Any], str]:
        """Run the scan with nmap.

        Args:
            domain_name: which domain name to be scanned.
            is_ipv6: scan the domain's IPv6 address instead of its IPv4 address.

        Returns:
            result of the scan.
        """
        logger.info("running the nmap scan")
        command = self._construct_command_domain(
            domain_name=domain_name, is_ipv6=is_ipv6
        )
        subprocess.run(command, check=True)

        with open(XML_OUTPUT_PATH, "r", encoding="utf-8") as o:
            scan_results = parse_output(o.read())

        with open(NORMAL_OUTPUT_PATH, "r", encoding="utf-8") as o:
            normal_results = o.read()

        return scan_results, normal_results
