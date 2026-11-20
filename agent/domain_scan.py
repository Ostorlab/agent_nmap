"""Scan a domain name on the open ports of its IP, discovered once per IP and cached in redis.

The open ports of an IP do not depend on the name used to reach it, so a ports-only scan runs once per IP.
The name-dependent part still runs for every domain, but only on those ports.
"""

import ipaddress
import logging
import socket
from typing import Any

from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin

from agent import nmap_options
from agent import nmap_wrapper

logger = logging.getLogger(__name__)

# Redis hash mapping an IP to its comma separated open ports.
OPEN_PORTS_CACHE_KEY = b"agent_nmap_ip_open_ports"

# Nmap reads /etc/hosts before querying DNS.
# Pinning the domain there makes nmap scan the same IP whose open ports were cached.
HOSTS_FILE_PATH = "/etc/hosts"
HOSTS_FILE_ENTRY_MARKER = "# agent_nmap"


def scan_domain(
    domain_name: str,
    options: nmap_options.NmapOptions,
    persist: persist_mixin.AgentPersistMixin,
) -> tuple[dict[str, Any], str] | None:
    """Scan a domain name on the open ports of its IP.

    Args:
        domain_name: Domain name to scan.
        options: Options of the scan; the ports-only discovery is derived from them.
        persist: Redis storage holding the open ports cache.

    Returns:
        The XML and normal scan results, or None when the domain can not be resolved or its IP
        has no open ports.

    Raises:
        subprocess.CalledProcessError: an nmap command failed.
        nmap_wrapper.OutputParsingError: the discovery output could not be parsed.
    """
    ip = resolve_ip(domain_name=domain_name)
    if ip is None:
        logger.info("could not resolve %s, skipping it", domain_name)
        return None
    open_ports = get_open_ports(ip=ip, options=options, persist=persist)
    if len(open_ports) == 0:
        logger.info("no open ports on %s (%s), skipping service scan", ip, domain_name)
        return None
    options = nmap_options.get_open_ports_scan_options(
        options=options, open_ports=open_ports
    )
    client = nmap_wrapper.NmapWrapper(options=options)
    logger.info("scanning domain %s with options %s", domain_name, options)
    add_hosts_entry(ip=ip, domain_name=domain_name)
    scan_results, normal_results = client.scan_domain(
        domain_name=domain_name,
        is_ipv6=ipaddress.ip_address(address=ip).version == 6,
    )
    remove_hosts_entry(ip=ip, domain_name=domain_name)
    return scan_results, normal_results


def get_open_ports(
    ip: str,
    options: nmap_options.NmapOptions,
    persist: persist_mixin.AgentPersistMixin,
) -> list[str]:
    """Return the open ports of an IP, from the redis cache or with a ports-only scan."""
    cached_ports = persist.hash_get(hash_name=OPEN_PORTS_CACHE_KEY, key=ip)
    if cached_ports is not None:
        logger.info("open ports of %s found in cache: %s", ip, cached_ports)
        return [port for port in cached_ports.decode().split(",") if port != ""]

    client = nmap_wrapper.NmapWrapper(
        options=nmap_options.get_port_discovery_options(options=options)
    )
    open_ports = client.discover_open_ports(host=ip)
    persist.hash_add(hash_name=OPEN_PORTS_CACHE_KEY, mapping={ip: ",".join(open_ports)})
    logger.info("open ports of %s cached: %s", ip, open_ports)
    return open_ports


def resolve_ip(domain_name: str) -> str | None:
    """Resolve a domain name to a single IP address, IPv4 first and IPv6 when it has no IPv4.

    When the domain has several addresses, the numerically lowest one is used, so the same
    domain always maps to the same cache entry even if the resolver rotates the address order.
    """
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            addresses = socket.getaddrinfo(
                host=domain_name,
                port=None,
                family=family,
                type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, UnicodeError):
            continue
        ips = sorted(
            {str(address[4][0]) for address in addresses},
            key=ipaddress.ip_address,
        )
        if len(ips) > 0:
            return ips[0]
    return None


def add_hosts_entry(ip: str, domain_name: str) -> None:
    """Append an entry resolving the domain to the IP to /etc/hosts."""
    entry = f"{ip} {domain_name} {HOSTS_FILE_ENTRY_MARKER}\n"
    try:
        with open(HOSTS_FILE_PATH, "r+", encoding="utf-8") as hosts_file:
            content = hosts_file.read()
            if content != "" and content.endswith("\n") is False:
                hosts_file.write("\n")
            hosts_file.write(entry)
    except OSError as e:
        logger.warning("could not write %s: %s", HOSTS_FILE_PATH, e)
        return
    logger.info("pinned in %s: %s", HOSTS_FILE_PATH, entry.strip())


def remove_hosts_entry(ip: str, domain_name: str) -> None:
    """Remove the entry resolving the domain to the IP from /etc/hosts."""
    entry = f"{ip} {domain_name} {HOSTS_FILE_ENTRY_MARKER}\n"
    try:
        with open(HOSTS_FILE_PATH, "r+", encoding="utf-8") as hosts_file:
            lines = [line for line in hosts_file if line != entry]
            hosts_file.seek(0)
            hosts_file.writelines(lines)
            hosts_file.truncate()
    except OSError as e:
        logger.warning("could not write %s: %s", HOSTS_FILE_PATH, e)
