"""MCP tools for port scanning."""

import dataclasses
import ipaddress
from typing import Any

from agent import nmap_options
from agent import nmap_wrapper


@dataclasses.dataclass
class OpenPort:
    """Dataclass representing an open port with service information.

    Attributes:
        host: The IP address of the host.
        port: The port number.
        service_name: The name of the service running on the port.
        service_version: The version of the service if available.
    """

    host: str
    port: int
    service_name: str
    service_version: str


def scan_ip(ip_address: str) -> list[OpenPort]:
    """

    Scan a given IP address and return a list of open ports with service information.

    This tool performs a comprehensive port scan and extracts service details
    including service name and version for each open port found.

    Args:
        ip_address: The IP address to scan (e.g., "192.168.1.1").

    Returns:
        A list of OpenPort objects containing port, service name, and version.

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
    scan_results, _ = client.scan_hosts(hosts=ip_address, mask=32)

    return _get_open_ports(scan_results)


def _get_open_ports(scan_results: dict[str, Any]) -> list[OpenPort]:
    if "nmaprun" not in scan_results:
        return []

    open_ports: list[OpenPort] = []

    hosts = scan_results["nmaprun"].get("host", [])

    if isinstance(hosts, dict):
        hosts = [hosts]

    for host in hosts:
        host_ip = host.get("address", {}).get("@addr", "unknown")
        ports = host.get("ports", {}).get("port", [])

        if isinstance(ports, dict):
            ports = [ports]

        for port in ports:
            state = port.get("state", {}).get("@state", "closed")

            if state == "open":
                port_id = int(port.get("@portid", 0))
                service = port.get("service", {})
                service_name = service.get("@name", "unknown")
                service_version = service.get("@version", "")

                open_ports.append(
                    OpenPort(
                        host=host_ip,
                        port=port_id,
                        service_name=service_name,
                        service_version=service_version,
                    )
                )
    return open_ports
