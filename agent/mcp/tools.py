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
        port_scanning_techniques=[nmap_options.PortScanningTechnique.TCP_CONNECT],
    )

    client = nmap_wrapper.NmapWrapper(options)
    try:
        scan_results, _ = client.scan_hosts(hosts=ip_address, mask=32)

        port_services = result_parser.get_port_services(scan_results)
        service_libraries = result_parser.get_service_libraries(scan_results)
        os_fingerprints = result_parser.get_os_fingerprints(scan_results)

        services: list[mcp_types.ServiceResult] = []
        for svc in port_services:
            port = svc.get("port") or 0
            services.append(
                mcp_types.ServiceResult(
                    host=svc.get("host") or "unknown",
                    port=int(port),
                    protocol=svc.get("protocol") or "",
                    state=svc.get("state") or "",
                    service=svc.get("service") or "",
                    banner=svc.get("banner") or "",
                    version=svc.get("version") or "4",
                )
            )

        fingerprints: list[mcp_types.FingerprintResult] = []
        for svc_fp in service_libraries:
            port = svc_fp.get("port") or 0
            fingerprints.append(
                mcp_types.FingerprintResult(
                    host=svc_fp.get("host") or "unknown",
                    version=svc_fp.get("version") or "4",
                    library_type=svc_fp.get("library_type") or "BACKEND_COMPONENT",
                    service=svc_fp.get("service"),
                    port=int(port),
                    protocol=svc_fp.get("protocol"),
                    library_name=svc_fp.get("library_name") or "",
                    library_version=svc_fp.get("library_version"),
                    detail=svc_fp.get("detail") or "",
                    mask=svc_fp.get("mask") or "32",
                )
            )
        for os_fp in os_fingerprints:
            fingerprints.append(
                mcp_types.FingerprintResult(
                    host=os_fp.get("host") or "unknown",
                    version=os_fp.get("version") or "4",
                    library_type=os_fp.get("library_type") or "OS",
                    service=None,
                    port=None,
                    protocol=None,
                    library_name=os_fp.get("library_name") or "",
                    library_version=os_fp.get("library_version"),
                    detail=os_fp.get("detail") or "",
                    mask="32",
                )
            )

        return {"services": services, "fingerprints": fingerprints}
    except subprocess.CalledProcessError as e:
        logger.error("Nmap command failed to scan host %s", ip_address)
        raise CalledToolError from e


def scan_domain(domain_name: str) -> ScanResult:
    """
    Scan a given domain name and return discovered services and fingerprints.

    This tool performs a comprehensive port scan and extracts:
    - Service details: port, protocol, state, service name, banner
    - Fingerprint details: Backend component information

    Args:
        domain_name: The domain name to scan (e.g., "example.com").

    Returns:
        A dictionary with two keys:
        - services: List of ServiceResult objects
        - fingerprints: List of FingerprintResult objects

    Raises:
        ValueError: If the domain name format is invalid.
    """
    if not domain_name or not isinstance(domain_name, str):
        raise ValueError(f"Invalid domain name format: {domain_name}")

    options = nmap_options.NmapOptions(
        dns_resolution=False,
        ports="0-65535",
        timing_template=nmap_options.TimingTemplate.T3,
        version_detection=True,
        script_default=True,
        scripts=["banner"],
        no_ping=True,
        host_timeout=300,
        port_scanning_techniques=[nmap_options.PortScanningTechnique.TCP_CONNECT],
    )

    client = nmap_wrapper.NmapWrapper(options)
    try:
        scan_results, _ = client.scan_domain(domain_name=domain_name)

        domain_services = result_parser.get_domain_name_services(
            scan_results, domain_name
        )
        domain_fingerprints = (
            result_parser.get_domain_name_service_library_fingerprints(
                scan_results, domain_name
            )
        )

        services: list[mcp_types.ServiceResult] = []
        for svc in domain_services:
            port = svc.get("port") or 0
            services.append(
                mcp_types.ServiceResult(
                    host=domain_name,
                    port=int(port),
                    protocol=svc.get("schema") or "",
                    state=svc.get("state") or "",
                    service=svc.get("schema") or "",
                    banner="",
                    version="4",
                )
            )

        fingerprints: list[mcp_types.FingerprintResult] = []
        for fp in domain_fingerprints:
            port = fp.get("port") or 0
            fingerprints.append(
                mcp_types.FingerprintResult(
                    host=domain_name,
                    version="4",
                    library_type=fp.get("library_type") or "BACKEND_COMPONENT",
                    service=fp.get("schema"),
                    port=int(port),
                    protocol=None,
                    library_name=fp.get("library_name") or "",
                    library_version=fp.get("library_version"),
                    detail=fp.get("detail") or "",
                    mask="32",
                )
            )

        return {"services": services, "fingerprints": fingerprints}
    except subprocess.CalledProcessError as e:
        logger.error("Nmap command failed to scan domain %s", domain_name)
        raise CalledToolError from e


if __name__ == "__main__":
    scan_domain("localhost")
