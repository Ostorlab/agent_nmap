"""MCP tools for port scanning."""

import ipaddress
import logging
import subprocess
from typing import Any

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


class ScanTarget(TypedDict):
    """Input for scanning a target.

    Attributes:
        target: The IP address (with optional /mask) or domain name to scan.
                Examples: "192.168.1.1", "192.168.1.0/24", "2001:db8::1", "example.com"
        target_type: The type of target ("ip" or "domain").
    """

    target: str
    target_type: str


def scan(scan_params: ScanTarget) -> list[mcp_types.ServiceResult]:
    """
    Scan a target and return discovered services with fingerprints.

    This tool performs a comprehensive port scan and extracts:
    - Service details: port, protocol, state, service name, banner
    - Fingerprint details: OS information and backend component information

    Args:
        scan_params: Dictionary with keys:
            - target: The IP address (with optional /mask) or domain name to scan.
                    Examples: "192.168.1.1", "192.168.1.0/24", "2001:db8::1", "example.com"
            - target_type: The type of target ("ip" or "domain")

    Returns:
        A list of ServiceResult objects, each containing service details
        and associated fingerprint information.
    """

    scan_results = _do_scan(scan_params["target"], scan_params["target_type"])

    port_services = result_parser.get_port_services(scan_results)
    service_libraries = result_parser.get_service_libraries(scan_results)
    os_fingerprints = result_parser.get_os_fingerprints(scan_results)

    services: list[mcp_types.ServiceResult] = []
    for svc in port_services:
        port = svc.get("port") or 0
        service = mcp_types.ServiceResult(
            host=svc.get("host") or "unknown",
            port=int(port),
            protocol=svc.get("protocol") or "",
            state=svc.get("state") or "",
            service=svc.get("service") or "",
            banner=svc.get("banner") or "",
            version=svc.get("version") or "4",
            fingerprints=[],
        )
        services.append(service)

    for svc_fp in service_libraries:
        fp = mcp_types.FingerprintResult(
            host=svc_fp.get("host") or "unknown",
            version=svc_fp.get("version") or "4",
            library_type=svc_fp.get("library_type") or "BACKEND_COMPONENT",
            port=int(svc_fp.get("port") or 0),
            protocol=svc_fp.get("protocol"),
            library_name=svc_fp.get("library_name") or "",
            library_version=svc_fp.get("library_version"),
            detail=svc_fp.get("detail") or "",
            mask=int(svc_fp.get("mask", 32)),
        )
        for service in services:
            if service.host == fp.host and service.port == fp.port:
                service.fingerprints.append(fp)

    for os_fp in os_fingerprints:
        fp = mcp_types.FingerprintResult(
            host=os_fp.get("host") or "unknown",
            version=os_fp.get("version") or "4",
            library_type=os_fp.get("library_type") or "OS",
            port=None,
            protocol=None,
            library_name=os_fp.get("library_name") or "",
            library_version=os_fp.get("library_version"),
            detail=os_fp.get("detail") or "",
            mask=32,
        )
        for service in services:
            if service.host == fp.host:
                service.fingerprints.append(fp)

    return services


def _do_scan(target: str, target_type: str) -> dict[str, Any]:
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
        if target_type == "ip":
            return _scan_ip(client, target)
        else:
            scan_results, _ = client.scan_domain(domain_name=target)
            return scan_results
    except subprocess.CalledProcessError as e:
        logger.error("Nmap command failed to scan target %s", target)
        raise CalledToolError from e


def _scan_ip(client: nmap_wrapper.NmapWrapper, target: str) -> dict[str, Any]:
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        host = str(network.network_address)
        mask = network.prefixlen
    else:
        ip = ipaddress.ip_address(target)
        mask = 128 if ip.version == 6 else 32
        host = target

    scan_results, _ = client.scan_hosts(hosts=host, mask=mask)
    return scan_results
