"""Generators of the messages' data that will be sent after the scan is complete."""

import logging
from collections.abc import Iterator
from typing import Any

IP_VERSIONS = {"ipv4": 4, "ipv6": 6}

logger = logging.getLogger(__name__)


def get_services(
    scan_result: dict[str, dict[str, list[dict[str, Any]] | dict[str, dict[str, Any]]]],
) -> Iterator[dict[str, str | None]]:
    """Generator of data for messages of type v3.asset.ip.v[4,6].port.service

    Args:
       scan_result: dictionary of the result of the nmap scan.

    Yields:
        dictionary of the services."""

    try:
        up_hosts = scan_result["nmaprun"].get("host", [])
        # nmap returns a list of hosts, however in the case of only one, it returns it as a dict. thus the lines below.
        if isinstance(up_hosts, dict):
            up_hosts = [up_hosts]

        for host in up_hosts:
            data = {}
            data["host"] = host.get("address", {}).get("@addr")
            ip_version = host.get("address", {}).get("@addrtype")

            data["version"] = IP_VERSIONS.get(ip_version, 4)

            ports = host.get("ports", {}).get("port", [])
            # nmap returns a list of ports, however in the case of only one, it returns it as a dict.
            # thus the lines below.
            if isinstance(ports, dict):
                ports = [ports]
            for port in ports:
                data["port"] = int(port.get("@portid"))
                data["protocol"] = port.get("@protocol")
                data["state"] = port.get("state", {}).get("@state", "closed")
                data["service"] = port.get("service", {}).get("@name", "")
                data["product"] = port.get("service", {}).get("@product", "")
                data["product_version"] = port.get("service", {}).get("@version", "")
                data["banner"] = get_script_by_name(name="banner", port=port)
                yield data
    except KeyError as e:
        logger.error(e)


# get banner from script
def get_script_by_name(
    name: str, port: dict[str, dict[str, str] | list[dict[str, str]]]
) -> str | None:
    """Get the banner from the port.

    Args:
        name: name of the script.
        port: port dictionary.

    Returns: banner string."""

    try:
        # check if script is present and then have multiple scripts
        if "script" in port:
            if isinstance(port["script"], list):
                for script in port["script"]:
                    if script.get("@id") == name:
                        if script.get("@output") is None:
                            return None
                        else:
                            return str(script["@output"])
            else:
                if port["script"].get("@id") == name:
                    if port["script"].get("@output") is None:
                        return None
                    else:
                        return str(port["script"]["@output"])
    except KeyError as e:
        logger.error(e)
    return None
