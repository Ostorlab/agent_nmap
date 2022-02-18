"""Generators of the messages data that will be sent after the scan is complete."""

import logging

from typing import Dict, Iterator

logger = logging.getLogger(__name__)

def get_services(scan_result: Dict) -> Iterator[Dict]:
    """Generator of data for messages of type v3.asset.ip.port.service

    Args:
       scan_result: dictionary of the result of the nmap scan.

    Yields:
        dictionary of the services."""

    try:
        up_hosts = scan_result['nmaprun'].get('host', [])
        if isinstance(up_hosts, dict):
            up_hosts = [up_hosts]

        for host in up_hosts:
            data = {}
            data['host'] = host.get('address', {}).get('@addr')
            ip_version = host.get('address', {}).get('@addrtype')
            ip_versions = {'ipv4':4, 'ipv6':6}
            data['version'] = ip_versions.get(ip_version)

            open_ports = host.get('ports', {}).get('port', [])
            if isinstance(open_ports, dict):
                open_ports = [open_ports]

            for port in open_ports:
                if port['state']['@state'] == 'open':
                    data['port'] = port.get('@portid')
                    data['protocol'] = port.get('@protocol')
                    data['state'] = port.get('state', {}).get('@state', 'closed')
                    data['service'] = port.get('service', {}).get('@name', '')
                    yield data
    except KeyError as e:
        logger.error(e)
