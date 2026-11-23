"""Scan a domain name on the open ports of each of its IPs, discovered once per IP and cached in redis.

The open ports of an IP do not depend on the name used to reach it, so a ports-only scan runs once per IP.
The name-dependent part still runs for every domain, but only on those ports.
"""

import ipaddress
import logging
import socket
import subprocess
from typing import Any

from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin

from agent import nmap_options
from agent import nmap_wrapper

logger = logging.getLogger(__name__)

# Redis hash mapping an IP to its comma separated open ports.
# An IP with no open ports is not cached: the host may only have been down or unreachable.
OPEN_PORTS_CACHE_KEY = b"agent_nmap_ip_open_ports"

# Nmap reads /etc/hosts before querying DNS.
# Pinning the domain there makes nmap scan the same IP whose open ports were cached.
HOSTS_FILE_PATH = "/etc/hosts"
HOSTS_FILE_ENTRY_MARKER = "# agent_nmap"

# A resolver doing DNS64 answers with IPv4 addresses translated into these NAT64 prefixes.
NAT64_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


def scan_domain(
    domain_name: str,
    options: nmap_options.NmapOptions,
    persist: persist_mixin.AgentPersistMixin,
) -> tuple[dict[str, Any], str] | None:
    """Scan a domain name on the open ports of each of its IPv4 and IPv6 addresses.

    Args:
        domain_name: Domain name to scan.
        options: Options of the scan; the ports-only discovery is derived from them.
        persist: Redis storage holding the open ports cache.

    Returns:
        The XML and normal scan results of all its IPs, or None when the domain can not be
        resolved or none of its IPs has open ports.

    Raises:
        subprocess.CalledProcessError: an nmap command failed and no IP was scanned.
        nmap_wrapper.OutputParsingError: a discovery output could not be parsed and no IP was
            scanned.
    """
    ips = resolve_ips(domain_name=domain_name)
    if len(ips) == 0:
        logger.info("could not resolve %s, skipping it", domain_name)
        return None
    results: list[tuple[dict[str, Any], str]] = []
    errors: list[subprocess.CalledProcessError | nmap_wrapper.OutputParsingError] = []
    for ip in ips:
        try:
            result = _scan_domain_on_ip(
                domain_name=domain_name, ip=ip, options=options, persist=persist
            )
        except (
            subprocess.CalledProcessError,
            nmap_wrapper.OutputParsingError,
        ) as e:
            logger.warning("could not scan %s on %s: %s", domain_name, ip, e)
            errors.append(e)
            continue
        if result is not None:
            results.append(result)
    if len(results) == 0:
        if len(errors) > 0:
            raise errors[0]
        return None
    return merge_results(results=results)


def _scan_domain_on_ip(
    domain_name: str,
    ip: str,
    options: nmap_options.NmapOptions,
    persist: persist_mixin.AgentPersistMixin,
) -> tuple[dict[str, Any], str] | None:
    """Scan a domain name pinned to one of its IPs, on the open ports of that IP."""
    open_ports = get_open_ports(ip=ip, options=options, persist=persist)
    if len(open_ports) == 0:
        logger.info("no open ports on %s (%s), skipping service scan", ip, domain_name)
        return None
    ip_options = nmap_options.get_open_ports_scan_options(
        options=options, open_ports=open_ports
    )
    client = nmap_wrapper.NmapWrapper(options=ip_options)
    logger.info("scanning domain %s on %s with options %s", domain_name, ip, ip_options)
    add_hosts_entry(ip=ip, domain_name=domain_name)
    try:
        return client.scan_domain(
            domain_name=domain_name,
            is_ipv6=ipaddress.ip_address(address=ip).version == 6,
        )
    finally:
        remove_hosts_entry(ip=ip, domain_name=domain_name)


def merge_results(
    results: list[tuple[dict[str, Any], str]],
) -> tuple[dict[str, Any], str]:
    """Merge the results of several nmap runs into one holding the hosts of all of them.

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
        hosts.extend([run_hosts] if isinstance(run_hosts, dict) else run_hosts)
    if len(hosts) > 0:
        merged["nmaprun"]["host"] = hosts
    normal_results = "\n".join(normal for _, normal in results if normal != "")
    return merged, normal_results


def get_open_ports(
    ip: str,
    options: nmap_options.NmapOptions,
    persist: persist_mixin.AgentPersistMixin,
) -> list[str]:
    """Return the open ports of an IP, from the redis cache or with a ports-only scan.

    An empty result is not cached, so the next domain on the IP runs the discovery again.
    """
    cached_ports = persist.hash_get(hash_name=OPEN_PORTS_CACHE_KEY, key=ip)
    if cached_ports is not None and cached_ports != b"":
        logger.info("open ports of %s found in cache: %s", ip, cached_ports)
        return [port for port in cached_ports.decode().split(",") if port != ""]

    client = nmap_wrapper.NmapWrapper(
        options=nmap_options.get_port_discovery_options(options=options)
    )
    open_ports = client.discover_open_ports(host=ip)
    if len(open_ports) == 0:
        logger.info("no open ports found on %s, not caching it", ip)
        return []
    persist.hash_add(hash_name=OPEN_PORTS_CACHE_KEY, mapping={ip: ",".join(open_ports)})
    logger.info("open ports of %s cached: %s", ip, open_ports)
    return open_ports


def resolve_ips(domain_name: str) -> list[str]:
    """Resolve a domain name to its IPv4 and IPv6 addresses, IPv4 first, each sorted numerically.

    NAT64 addresses are left out: they are IPv4 addresses a DNS64 resolver translated.
    """
    ips: set[str] = set()
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
        ips.update(str(address[4][0]) for address in addresses)
    return sorted(
        (ip for ip in ips if _is_nat64_address(ip=ip) is False),
        key=lambda ip: (ipaddress.ip_address(ip).version, ipaddress.ip_address(ip)),
    )


def _is_nat64_address(ip: str) -> bool:
    """Whether an address is an IPv4 address translated into a NAT64 prefix."""
    address = ipaddress.ip_address(ip)
    return any(address in network for network in NAT64_NETWORKS)


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
