"""Wrapper for Nmap Network Scanner."""

import ipaddress
import logging
import subprocess
from typing import Any
from xml.parsers import expat

import xmltodict

from agent import nmap_options

XML_OUTPUT_PATH = "/tmp/xmloutput"
NORMAL_OUTPUT_PATH = "/tmp/normal"
# nmap scans the addresses of one IP version per run, so a domain name is scanned once per version.
DOMAIN_IP_VERSIONS = (4, 6)
# A resolver doing DNS64 answers with IPv4 addresses translated into these NAT64 prefixes.
NAT64_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)

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


def _is_nat64_address(address: str | None) -> bool:
    """Whether an address is an IPv4 address translated into a NAT64 prefix."""
    if address is None:
        return False
    try:
        ip_address = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip_address in network for network in NAT64_NETWORKS)


def merge_results(
    results: list[tuple[dict[str, Any], str]],
) -> tuple[dict[str, Any], str]:
    """Merge the results of several nmap runs into one holding the hosts of all of them.

    Hosts at NAT64 addresses are left out: they are IPv4 addresses a DNS64 resolver translated.

    Args:
        results: parsed xml output and normal output of each run.

    Returns:
        the merged parsed xml output and the normal outputs joined.
    """
    merged: dict[str, Any] = {}
    hosts: list[dict[str, Any]] = []
    for scan_results, _ in results:
        nmaprun = scan_results.get("nmaprun")
        if nmaprun is None:
            continue
        if len(merged) == 0:
            merged = {"nmaprun": dict(nmaprun)}
            merged["nmaprun"].pop("host", None)
        run_hosts = nmaprun.get("host", [])
        for host in [run_hosts] if isinstance(run_hosts, dict) else run_hosts:
            address = host.get("address", {}).get("@addr")
            if _is_nat64_address(address) is True:
                logger.info("Leaving out %s, a NAT64 address.", address)
                continue
            hosts.append(host)
    if len(hosts) > 0:
        merged["nmaprun"]["host"] = hosts
    normal_results = "\n".join(normal for _, normal in results if normal != "")
    return merged, normal_results


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

    def _construct_command_domain(self, domain_name: str, ip_version: int) -> list[str]:
        """
        Construct the Nmap command to be run.

        Args:
            domain_name: which domain to be scanned.
            ip_version: version of the domain's addresses to scan.

        Returns:
            list of the arguments that will be used to run the scan process.
        """
        command = [
            "nmap",
            *self._options.command_options,
            "--resolve-all",
            "-oX",
            XML_OUTPUT_PATH,
            "-oN",
            NORMAL_OUTPUT_PATH,
        ]
        if ip_version == 6:
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

    def scan_domain(self, domain_name: str) -> tuple[dict[str, Any], str]:
        """Run the scan with nmap on every IPv4 and IPv6 address of a domain name.

        Args:
            domain_name: which domain name to be scanned.

        Returns:
            result of the scan.

        Raises:
            subprocess.CalledProcessError: nmap failed for every IP version.
        """
        results: list[tuple[dict[str, Any], str]] = []
        errors: list[subprocess.CalledProcessError] = []
        for ip_version in DOMAIN_IP_VERSIONS:
            try:
                results.append(self._scan_domain_addresses(domain_name, ip_version))
            except subprocess.CalledProcessError as e:
                logger.warning(
                    "Nmap failed to scan the IPv%s addresses of %s: %s",
                    ip_version,
                    domain_name,
                    e,
                )
                errors.append(e)
        if len(results) == 0:
            raise errors[0]
        return merge_results(results)

    def _scan_domain_addresses(
        self, domain_name: str, ip_version: int
    ) -> tuple[dict[str, Any], str]:
        """Run the scan with nmap on the addresses of one IP version of a domain name."""
        logger.info(
            "running the nmap scan on the IPv%s addresses of %s",
            ip_version,
            domain_name,
        )
        command = self._construct_command_domain(domain_name, ip_version)
        subprocess.run(command, check=True)

        with open(XML_OUTPUT_PATH, "r", encoding="utf-8") as o:
            scan_results = parse_output(o.read())

        with open(NORMAL_OUTPUT_PATH, "r", encoding="utf-8") as o:
            normal_results = o.read()

        return scan_results, normal_results
