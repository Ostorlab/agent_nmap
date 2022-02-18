"""Wrapper for Nmap Security Scanner."""

from typing import Any, Dict, List
import subprocess
import json

import xmltodict


class NmapWrapper:
    """Wrapper class for the Nmap Security Scanner."""

    def __init__(
            self,
            hosts: str = '127.0.0.1',
            mask: str = '32',
            ip_version: int = 4,
            ports: str = '22,8080',
            arguments: str = '-sV'
        ) -> None:
        """Constructs all the necessary attributes for the object.

        Args:
            hosts: which hosts do you want to scan.
            mask: mask to be used in the scan.
            ip_version: ipv4 or ipv6.
            ports: ports to be scanned.
            arguments: arguments of the nmap command.
        """
        self.hosts = hosts
        self.ip_version = ip_version
        self.mask = mask
        self.ports = ports
        self.arguments = arguments + f' -{self.ip_version}' * (self.ip_version==6)
        self.command = self._construct_command()

    def _construct_command(self) -> List[str]:
        """
        Construct the Nmap command to be run.

        Returns:
            list of the arguments that will be used to run the scan process.
        """
        ports = f'-p {self.ports}' * (self.ports is not None)
        hosts_and_mask = self.hosts + '/' + self.mask
        command = ['nmap',
                   self.arguments,
                   '--script=banner',
                   '-oX -',
                   hosts_and_mask,
                   ports]
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

    def scan(self) -> Dict[str, Any]:
        """Run the scan with nmap.

        Returns:
            result of the scan.
        """
        with subprocess.Popen(self.command, stdout=subprocess.PIPE) as process:
            xml_output = process.communicate()[0]
            xml_output= xml_output.decode(encoding='utf-8')
            scan_results = self._parse_output_to_json(xml_output)
            return scan_results
