"""Utility module for parsing Nmap scan results.

This module provides common parsing logic for extracting services and fingerprints
from Nmap scan results. It serves as a single source of truth for result parsing
used by both the agent and MCP tools.
"""

import dataclasses
import logging
from typing import Any

from agent import generators

logger = logging.getLogger(__name__)

BLACKLISTED_SERVICES = ["tcpwrapped"]


@dataclasses.dataclass
class ParsedService:
    """Parsed service information from a port scan.

    Attributes:
        host: The IP address of the host.
        version: The IP version ("4" or "6").
        port: The port number.
        protocol: The protocol (tcp, udp).
        state: The port state (open, closed, filtered).
        service: The service name.
        product: The product name.
        product_version: The product version.
        banner: The banner information.
    """

    host: str
    version: str
    port: int
    protocol: str
    state: str
    service: str
    product: str
    product_version: str
    banner: str | None


@dataclasses.dataclass
class ParsedFingerprint:
    """Parsed fingerprint information (OS or backend component).

    Attributes:
        host: The IP address of the host.
        version: The IP version ("4" or "6").
        library_type: The type of library ("OS" or "BACKEND_COMPONENT").
        library_name: The OS family or product name.
        library_version: The OS generation or product version.
        detail: Detailed information about the OS or product.
        mask: Network mask (default "32" for IPv4, "128" for IPv6).
        service: The service name if applicable.
        port: The port number if applicable.
        protocol: The protocol if applicable.
    """

    host: str
    version: str
    library_type: str
    library_name: str
    library_version: str | None
    detail: str
    mask: str = "32"
    service: str | None = None
    port: int | None = None
    protocol: str | None = None


def _normalize_hosts(
    hosts: dict[str, Any] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize hosts data structure to always return a list.

    Nmap returns a list of hosts, but when there's only one host, it returns
    it as a dict instead of a list. This helper normalizes that.

    Args:
        hosts: Hosts data from nmap scan results (dict or list).

    Returns:
        list of host dictionaries.
    """
    if isinstance(hosts, dict):
        return [hosts]
    return hosts


def parse_services(scan_results: dict[str, Any]) -> list[ParsedService]:
    """Parse services from nmap scan results.

    Extracts all discovered services from scan results, filtering out
    blacklisted services.

    Args:
        scan_results: The nmap scan results dictionary from nmap_wrapper.

    Returns:
        list of ParsedService objects containing service information.
    """
    services: list[ParsedService] = []

    if "nmaprun" not in scan_results:
        return services

    for service_data in generators.get_services(scan_results):
        service_name = service_data.get("service") or ""

        if service_name in BLACKLISTED_SERVICES:
            continue

        port_val = service_data.get("port")
        port_int = int(port_val) if port_val is not None else 0

        banner = service_data.get("banner")

        service = ParsedService(
            host=service_data.get("host") or "unknown",
            version=str(service_data.get("version", "4")),
            port=port_int,
            protocol=service_data.get("protocol") or "",
            state=service_data.get("state") or "",
            service=service_name,
            product=service_data.get("product") or "",
            product_version=service_data.get("product_version") or "",
            banner=banner,
        )
        services.append(service)

    return services


def parse_fingerprints(scan_results: dict[str, Any]) -> list[ParsedFingerprint]:
    """Parse fingerprints (OS and backend components) from nmap scan results.

    Extracts OS information and backend component fingerprints from scan results.

    Args:
        scan_results: The nmap scan results dictionary from nmap_wrapper.

    Returns:
        list of ParsedFingerprint objects containing fingerprint information.
    """
    fingerprints: list[ParsedFingerprint] = []

    if "nmaprun" not in scan_results:
        return fingerprints

    hosts_data = scan_results["nmaprun"].get("host", [])
    hosts = _normalize_hosts(hosts_data)

    for host in hosts:
        ip_version = host.get("address", {}).get("@addrtype", "ipv4")
        version_str = "4" if ip_version == "ipv4" else "6"
        mask = "32" if ip_version == "ipv4" else "128"
        host_ip = host.get("address", {}).get("@addr", "unknown")

        os_fingerprints = _parse_os_fingerprints(host, host_ip, version_str, mask)
        fingerprints.extend(os_fingerprints)

        backend_fingerprints = _parse_backend_fingerprints(
            host, scan_results, host_ip, version_str, mask
        )
        fingerprints.extend(backend_fingerprints)

    return fingerprints


def _parse_os_fingerprints(
    host: dict[str, Any], host_ip: str, version_str: str, mask: str
) -> list[ParsedFingerprint]:
    """Parse OS fingerprints from a host.

    Args:
        host: The host dictionary from nmap results.
        host_ip: The host IP address.
        version_str: The IP version string ("4" or "6").
        mask: The network mask.

    Returns:
        list of ParsedFingerprint objects for OS information.
    """
    fingerprints: list[ParsedFingerprint] = []

    os_data = host.get("os", {})
    if os_data.get("osmatch") is None:
        return fingerprints

    os_match = os_data.get("osmatch")
    if isinstance(os_match, list) and len(os_match) > 0:
        os_match_highest = os_match[0]
        # Handle case where osmatch is nested list like [[{...}]]
        if isinstance(os_match_highest, list) and len(os_match_highest) > 0:
            os_match_highest = os_match_highest[0]
        elif not isinstance(os_match_highest, dict):
            return fingerprints
    elif isinstance(os_match, dict):
        os_match_highest = os_match
    else:
        return fingerprints

    os_class = os_match_highest.get("osclass", {})
    os_class_item: dict[str, Any] | None = None

    if isinstance(os_class, list) and len(os_class) > 0:
        os_class_item = os_class[0]
    elif isinstance(os_class, dict):
        os_class_item = os_class

    if os_class_item is None:
        return fingerprints

    fingerprint = ParsedFingerprint(
        host=host_ip,
        version=version_str,
        library_type="OS",
        library_name=os_class_item.get("@osfamily") or "",
        library_version=os_class_item.get("@osgen") or "",
        detail=os_match_highest.get("@name") or "",
        mask=mask,
    )
    fingerprints.append(fingerprint)

    return fingerprints


def _parse_backend_fingerprints(
    host: dict[str, Any],
    scan_results: dict[str, Any],
    host_ip: str,
    version_str: str,
    mask: str,
) -> list[ParsedFingerprint]:
    """Parse backend component fingerprints from a host.

    Args:
        host: The host dictionary from nmap results.
        scan_results: The full nmap scan results dictionary.
        host_ip: The host IP address.
        version_str: The IP version string ("4" or "6").
        mask: The network mask.

    Returns:
        list of ParsedFingerprint objects for backend components.
    """
    fingerprints: list[ParsedFingerprint] = []

    for service_data in generators.get_services(scan_results):
        if service_data.get("host") != host_ip:
            continue

        service_name = service_data.get("service") or ""
        if service_name in BLACKLISTED_SERVICES:
            continue

        port_val = service_data.get("port")
        port_int = int(port_val) if port_val is not None else None
        if port_int is None:
            continue

        protocol = service_data.get("protocol")

        product = service_data.get("product") or ""
        if product != "":
            fingerprint = ParsedFingerprint(
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
            fingerprints.append(fingerprint)

        banner = service_data.get("banner") or ""
        if banner != "":
            fingerprint = ParsedFingerprint(
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
            fingerprints.append(fingerprint)

    return fingerprints
