"""MCP tools for port scanning."""

import ipaddress
import logging
import subprocess
from typing_extensions import TypedDict

from agent import nmap_options
from agent import nmap_wrapper
from agent import result_parser
from agent.mcp import mcp_types

logger = logging.getLogger(__name__)


class Error(Exception):
    """Base exception for tools."""


class CalledToolError(Error):
    """Generic exception raised when a tool call fails."""


class ScanResult(TypedDict):
    """Result of scanning an IP address.

    Attributes:
        services: List of discovered services.
        fingerprints: List of discovered fingerprints.
    """

    services: list[mcp_types.ServiceResult]
    fingerprints: list[mcp_types.FingerprintResult]


def scan_ip(ip_address: str) -> ScanResult:
    """

    Scan a given IP address and return discovered services and fingerprints.

    This tool performs a comprehensive port scan and extracts:
    - Service details: port, protocol, state, service name, banner
    - Fingerprint details: OS information and backend component information

    Args:
        ip_address: The IP address to scan (e.g., "192.168.1.1").

    Returns:
        A dictionary with two keys:
        - services: List of ServiceResult objects
        - fingerprints: List of FingerprintResult objects

    Raises:
        ValueError: If the IP address format is invalid.
    """
    try:
        ipaddress.ip_address(ip_address)
    except ValueError as e:
        raise ValueError(f"Invalid IP address format: {ip_address}") from e

    options = nmap_options.NmapOptions(
        dns_resolution=False,
        ports="0-65535",
        timing_template=nmap_options.TimingTemplate.T3,
        version_detection=True,
        script_default=True,
        scripts=["banner"],
        no_ping=True,
        host_timeout=300,
        os_detection=False,
        port_scanning_techniques=[nmap_options.PortScanningTechnique.TCP_CONNECT],
    )

    client = nmap_wrapper.NmapWrapper(options)
    try:
        scan_results, _ = client.scan_hosts(hosts=ip_address, mask=32)

        parsed_services = result_parser.parse_services(scan_results)
        parsed_fingerprints = result_parser.parse_fingerprints(scan_results)

        services: list[mcp_types.ServiceResult] = [
            mcp_types.ServiceResult(
                host=svc.host,
                port=svc.port,
                protocol=svc.protocol,
                state=svc.state,
                service=svc.service,
                banner=svc.banner,
                version=svc.version,
            )
            for svc in parsed_services
        ]

        fingerprints: list[mcp_types.FingerprintResult] = [
            mcp_types.FingerprintResult(
                host=fp.host,
                version=fp.version,
                library_type=fp.library_type,
                service=fp.service,
                port=fp.port,
                protocol=fp.protocol,
                library_name=fp.library_name,
                library_version=fp.library_version,
                detail=fp.detail,
                mask=fp.mask,
            )
            for fp in parsed_fingerprints
        ]

        return {"services": services, "fingerprints": fingerprints}
    except subprocess.CalledProcessError as e:
        logger.error("Nmap command failed to scan host %s", ip_address)
        raise CalledToolError from e
