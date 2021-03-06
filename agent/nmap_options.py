"""Options defining an Nmap scan settings."""

import dataclasses
import enum
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class TimingTemplate(enum.Enum):
    """Timing config template"""
    T0 = '-T0'
    T1 = '-T1'
    T2 = '-T2'
    T3 = '-T3'
    T4 = '-T4'
    T5 = '-T5'


@dataclasses.dataclass
class NmapOptions:
    """Storing the options of an Nmap scan."""
    dns_resolution: bool = True
    dns_servers: List[str] = None
    ports: Optional[str] = None
    timing_template: TimingTemplate = TimingTemplate.T3
    version_detection: bool = True

    def _set_version_detection_option(self):
        """Appends the  option to the list of nmap options."""
        command_options = []
        if self.version_detection is True:
            command_options.append('-sV')
            command_options.append('--script=banner')
        return command_options

    def _set_dns_resolution_option(self):
        """Appends the dns resolution option to the list of nmap options."""
        command_options = []
        if self.dns_resolution is True:
            command_options.append('-R')
            if self.dns_servers:
                dns_servers = ','.join([str(dns) for dns in self.dns_servers])
                command_options.append(f'--dns-servers {dns_servers}')
        else:
            command_options.append('-n')
        return command_options

    def _set_ports_option(self):
        """Appends the ports option to the list of nmap options."""
        if self.ports is not None:
            return ['-p', self.ports]
        else:
            return []


    def _set_timing_option(self):
        """Appends the timing template option to the list of nmap options."""
        return [self.timing_template.value]

    @property
    def command_options(self) -> List[str]:
        """Computes the list of nmap options."""
        command_options = []
        command_options.extend(self._set_version_detection_option())
        command_options.extend(self._set_dns_resolution_option())
        command_options.extend(self._set_ports_option())
        command_options.extend(self._set_timing_option())
        return command_options

