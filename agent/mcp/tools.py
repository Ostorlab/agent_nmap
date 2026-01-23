"""MCP tools for port scanning."""

import ipaddress
import logging
import subprocess
from typing_extensions import Any, TypedDict

from agent import nmap_options
from agent import nmap_wrapper
from agent import generators
from agent.mcp import mcp_types

logger = logging.getLogger(__name__)
BLACKLISTED_SERVICES = ["tcpwrapped"]


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
        return _parse_scan_results(scan_results)
    except subprocess.CalledProcessError:
        logger.error("Nmap command failed to scan host %s", ip_address)
        return {"services": [], "fingerprints": []}


def _parse_scan_results(scan_results: dict[str, Any]) -> ScanResult:
    """Parse scan results and extract services and fingerprints.

    Args:
        scan_results: The nmap scan results dictionary.

    Returns:
        A dictionary with two keys:
        - services: List of ServiceResult objects
        - fingerprints: List of FingerprintResult objects
    """
    services: list[mcp_types.ServiceResult] = []
    fingerprints: list[mcp_types.FingerprintResult] = []

    if "nmaprun" not in scan_results:
        return {"services": [], "fingerprints": []}

    hosts = scan_results["nmaprun"].get("host", [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    for host in hosts:
        host_ip = host.get("address", {}).get("@addr", "unknown")
        ip_version = host.get("address", {}).get("@addrtype", "ipv4")
        version_str = "4" if ip_version == "ipv4" else "6"
        mask = "32" if ip_version == "ipv4" else "128"

        for service_data in generators.get_services(scan_results):
            if service_data.get("host") != host_ip:
                continue

            service_name = service_data.get("service") or ""
            if service_name in BLACKLISTED_SERVICES:
                continue

            port_val = service_data.get("port")
            port_int = int(port_val) if port_val is not None else 0

            service_result = mcp_types.ServiceResult(
                host=host_ip,
                port=port_int,
                protocol=service_data.get("protocol") or "",
                state=service_data.get("state") or "",
                service=service_name,
                banner=service_data.get("banner") or "",
                version=version_str,
            )
            services.append(service_result)

        os_data = host.get("os", {})
        if os_data and os_data.get("osmatch") is not None:
            os_match = os_data.get("osmatch")
            if isinstance(os_match, list) and len(os_match) > 0:
                os_match_highest = os_match[0]
            elif isinstance(os_match, dict):
                os_match_highest = os_match
            else:
                os_match_highest = None

            if os_match_highest is not None:
                os_class = os_match_highest.get("osclass", {})
                if isinstance(os_class, list) and len(os_class) > 0:
                    os_class = os_class[0]

                if os_class and os_class != []:
                    fingerprint_result = mcp_types.FingerprintResult(
                        host=host_ip,
                        version=version_str,
                        library_type="OS",
                        service=None,
                        port=None,
                        protocol=None,
                        library_name=os_class.get("@osfamily") or "",
                        library_version=os_class.get("@osgen") or "",
                        detail=os_match_highest.get("@name") or "",
                        mask=mask,
                    )
                    fingerprints.append(fingerprint_result)

        for service_data in generators.get_services(scan_results):
            if service_data.get("host") != host_ip:
                continue

            service_name = service_data.get("service") or ""
            if service_name in BLACKLISTED_SERVICES:
                continue

            port_val = service_data.get("port")
            port_int = int(port_val) if port_val is not None else 0

            if port_int is None:
                continue

            protocol = service_data.get("protocol")

            product = service_data.get("product") or ""
            if product:
                fingerprint_result = mcp_types.FingerprintResult(
                    host=host_ip,
                    version=version_str,
                    library_type="BACKEND_COMPONENT",
                    service=service_name,
                    port=port_int,
                    protocol=protocol,
                    library_name=product,
                    library_version=service_data.get("product_version"),
                    detail=product,
                    mask=mask,
                )
                fingerprints.append(fingerprint_result)

            banner = service_data.get("banner") or ""
            if banner:
                fingerprint_result = mcp_types.FingerprintResult(
                    host=host_ip,
                    version=version_str,
                    library_type="BACKEND_COMPONENT",
                    service=service_name,
                    port=port_int,
                    protocol=protocol,
                    library_name=banner,
                    library_version=None,
                    detail=banner,
                    mask=mask,
                )
                fingerprints.append(fingerprint_result)

    return {
        "services": services,
        "fingerprints": fingerprints,
    }
