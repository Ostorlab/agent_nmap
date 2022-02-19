"""Wrapper for Nmap Security Scanner."""

from typing import Any, Dict, List
import dataclasses
import ipaddress
import logging
import subprocess
import json

import xmltodict

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class NmapOptions:
    """Storing the options of the nmap scan."""
    dns_resolution: bool = True
    dns_servers: List = None
    ports: str = None
    timing_template: int = 3

    def get_command_options(self) -> List[str]:
        """Returns a list of nmap options."""
        command_options = []
        if self.dns_resolution is True:
            command_options.append('-R')
            if self.dns_servers:
                dns_servers = ','.join([str(dns) for dns in self.dns_servers])
                command_options.append(f'--dns-servers {dns_servers}')
        else:
            command_options.append('-n')

        ports = f'-p {self.ports}' * (self.ports is not None)
        command_options.append(ports)

        if self.timing_template > 5 or self.timing_template < 0:
            logger.warning('The timing template should be between 0 and 5. The scan will use the default T3.')
        else:
            command_options.append('-T' + str(self.timing_template))

        return command_options


class NmapWrapper:
    """Wrapper class for the Nmap Security Scanner."""

    def __init__(self, nmap_options: NmapOptions) -> None:
        """Constructs all the necessary attributes for the object.

        Args:
            nmap_options: options of the nmap scan.
        """
        self.nmap_options = nmap_options

    def _construct_command(self, host: str, mask: str) -> List[str]:
        """
        Construct the Nmap command to be run.

        Args:
            hosts: which hosts to be scanned.
            mask: mask to be used in the scan.

        Returns:
            list of the arguments that will be used to run the scan process.
        """
        command_options = self.nmap_options.get_command_options()
        ip_version = ipaddress.ip_address(host).version
        ip_version_option = f' -{ip_version} ' * (ip_version == 6)
        hosts_and_mask = ip_version_option + host + f'/{mask}' * (mask != '')

        command = ['nmap',
                   '-sV',
                   *command_options,
                   '--script=banner',
                   '-oX',
                   '-',
                   hosts_and_mask]
        return command

    def _parse_output_to_json(self, xml_output: str) -> Dict[str, Any]:
        """Parse the xml_output of the nmap scan command to json format.

        Args:
            xml_output: output of the nmap scan command.

        Returns:
            json_output
        """
        parsed_xml = xmltodict.parse(xml_output)
        json_output = json.dumps(parsed_xml, indent=4, sort_keys=True)
        json_output = json.loads(json_output)
        return json_output

    def scan(self, hosts: str, mask: str = '') -> Dict[str, Any]:
        """Run the scan with nmap.

        Args:
            hosts: which hosts to be scanned.
            mask: mask to be used in the scan.

        Returns:
            result of the scan.
        """
        command = self._construct_command(hosts, mask)
        with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
            xml_output = process.communicate()[0]
            xml_output = xml_output.decode(encoding='utf-8')
            scan_results = self._parse_output_to_json(xml_output)
            return scan_results
