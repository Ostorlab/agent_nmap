"""Generators of the messages data that will be sent after the scan is complete."""

import logging

from typing import Dict, Iterator, Optional

IP_VERSIONS = {'ipv4': 4, 'ipv6': 6}

logger = logging.getLogger(__name__)


def get_services(scan_result: Dict) -> Iterator[Dict]:
    """Generator of data for messages of type v3.asset.ip.v[4,6].port.service

    Args:
       scan_result: dictionary of the result of the nmap scan.

    Yields:
        dictionary of the services."""

    try:
        up_hosts = scan_result['nmaprun'].get('host', [])
        # nmap returns a list of hosts, however in the case of only one, it returns it as a dict. thus the lines below.
        if isinstance(up_hosts, dict):
            up_hosts = [up_hosts]

        for host in up_hosts:
            data = {}
            data['host'] = host.get('address', {}).get('@addr')
            ip_version = host.get('address', {}).get('@addrtype')

            data['version'] = IP_VERSIONS.get(ip_version)

            ports = host.get('ports', {}).get('port', [])
            # nmap returns a list of ports, however in the case of only one, it returns it as a dict.
            # thus the lines below.
            if isinstance(ports, dict):
                ports = [ports]

            for port in ports:
                data['port'] = int(port.get('@portid'))
                data['protocol'] = port.get('@protocol')
                data['state'] = port.get('state', {}).get('@state', 'closed')
                data['service'] = port.get('service', {}).get('@name', '')
                data['banner'] = get_script_by_name(name='banner', port=port)
                yield data
    except KeyError as e:
        logger.error(e)


# get banner from script
def get_script_by_name(name: str, port: Dict) -> Optional[str]:
    """Get the banner from the port.

    Args:
        name: name of the script.
        port: port dictionary.

    Returns: banner string."""

    try:
        # check if script is present and then have multiple scripts
        if 'script' in port:
            if isinstance(port['script'], list):
                for script in port['script']:
                    if script.get('@id') == name:
                        return script.get('@output')
            else:
                if port['script'].get('@id') == name:
                    return port['script'].get('@output')
    except KeyError as e:
        logger.error(e)
    return None
