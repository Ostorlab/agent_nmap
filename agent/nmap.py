"""Wrapper for Nmap Security Scanner."""

from typing import Any, Dict, List, Optional
import dataclasses
import ipaddress
import logging
import subprocess
import enum


import xmltodict

logger = logging.getLogger(__name__)


class NmapTimingTemplate(enum.Enum):
    T0 = '-T0'
    T1 = '-T1'
    T2 = '-T2'
    T3 = '-T3'
    T4 = '-T4'


@dataclasses.dataclass
class NmapOptions:
    """Storing the options of the nmap scan."""
    dns_resolution: bool = True
    dns_servers: List[str] = None
    ports: Optional[str] = None
    timing_template: NmapTimingTemplate = NmapTimingTemplate.T3
    enable_version_detection: bool = True
    command_options: List[str] = dataclasses.field(default_factory=list)

    def _append_enable_version_detection_option(self):
        """Appends the  option to the list of nmap options."""
        if self.enable_version_detection is True:
            self.command_options.append('-sV')
            self.command_options.append('--script=banner')

    def _append_dns_resolution_option(self):
        """Appends the dns resolution option to the list of nmap options."""
        if self.dns_resolution is True:
            self.command_options.append('-R')
            if self.dns_servers:
                dns_servers = ','.join([str(dns) for dns in self.dns_servers])
                self.command_options.append(f'--dns-servers {dns_servers}')
        else:
            self.command_options.append('-n')

    def _append_ports_option(self):
        """Appends the ports option to the list of nmap options."""
        ports = f'-p {self.ports}' * (self.ports is not None)
        self.command_options.append(ports)

    def _append_timing_option(self):
        """Appends the timing template option to the list of nmap options."""
        self.command_options.append(self.timing_template.value)

    def get_command_options(self) -> List[str]:
        """Returns the list of nmap options."""
        self._append_enable_version_detection_option()
        self._append_dns_resolution_option()
        self._append_ports_option()
        self._append_timing_option()

        return self.command_options


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
                   *command_options,
                   '-oX',
                   '-',
                   hosts_and_mask]
        return command

    def _parse_output(self, xml_output: str) -> Dict[str, Any]:
        """Parse the xml_output of the nmap scan command.

        Args:
            xml_output: output of the nmap scan command.

        Returns:
            dict of the scan's result.
        """
        parsed_xml = xmltodict.parse(xml_output)
        return parsed_xml

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
            scan_results = self._parse_output(xml_output)
            return scan_results
