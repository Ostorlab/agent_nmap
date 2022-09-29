"""Options defining an Nmap scan settings."""

import dataclasses
import enum
import logging
import os
from typing import List, Optional

import pathlib
import requests

logger = logging.getLogger(__name__)

SCRIPTS_PATH = '/tmp/scripts'


class TimingTemplate(enum.Enum):
    """Timing config template"""
    T0 = '-T0'
    T1 = '-T1'
    T2 = '-T2'
    T3 = '-T3'
    T4 = '-T4'
    T5 = '-T5'


class PortScanningTechnique(enum.Enum):
    """Nmap multiple port scanning techniques."""
    TCP_SYN = '-sS'
    TCP_CONNECT = '-sT'
    UDP = '-sU'
    SCTP_INIT = '-sY'
    TCP_FULL = '-sN'
    TCP_FIN = '-sF'
    XMAS = '-sX'
    TCP_ACK = '-sA'
    TCP_WINDOW = '-sW'
    TCP_MAIMON = '-sM'
    SCTP_COOKIE = '-sZ'




@dataclasses.dataclass
class NmapOptions:
    """Storing the options of a Nmap scan."""
    dns_resolution: bool = True
    dns_servers: List[str] | None = None
    ports: Optional[str] | None = None
    fast_mode: bool = False
    timing_template: TimingTemplate = TimingTemplate.T3
    script_default: bool = False
    scripts: List[str] | None = dataclasses.field(default_factory=lambda: ['default', 'banner'])
    version_detection: bool = True
    port_scanning_technique: PortScanningTechnique = PortScanningTechnique.TCP_CONNECT
    no_ping: bool = True
    privileged: Optional[bool] = None


    def _set_version_detection_option(self) -> List[str]:
        """Appends the  option to the list of nmap options."""
        command_options = []
        if self.version_detection is True:
            command_options.append('-sV')
            command_options.append('--script=banner')
        return command_options

    def _set_no_ping_options(self) -> List[str]:
        if self.no_ping is True:
            return ['-Pn']
        else:
            return []

    def _set_privileged(self) -> List[str]:
        if self.privileged is True:
            return ['--privileged']
        elif self.privileged is False:
            return ['--unprivileged']
        else:
            return []

    def _set_dns_resolution_option(self) -> List[str]:
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

    def _set_ports_option(self) -> List[str]:
        """Appends the ports option to the list of nmap options."""
        if self.fast_mode is True:
            return ['-F']
        elif self.ports is not None:
            return ['-p', self.ports]
        else:
            return []

    def _set_timing_option(self) -> List[str]:
        """Appends the timing template option to the list of nmap options."""
        return [self.timing_template.value]

    def _set_port_scanning_technique(self) -> List[str]:
        """Appends the port scanning technique to the list of nmap options."""
        return [self.port_scanning_technique.value]

    def _set_script_default(self) -> List[str]:
        if self.script_default is True:
            return ['-sC']
        else:
            return []
    def _set_scripts(self) -> List[str]:
        if self.scripts is not None and len(self.scripts) > 0:
            return self._run_scripts_command(self.scripts)
        else:
            return []

    def _run_scripts_command(self, scripts: List[str]) -> List[str]:
        """Run nmap scan on the provided scripts"""
        command = []
        path = pathlib.Path(SCRIPTS_PATH)
        if not pathlib.Path.exists(path):
            os.mkdir(SCRIPTS_PATH)
        for script_url in scripts:
            if script_url.startswith('http'):
                temp_path = (path / script_url.split('/')[-1])
                r = requests.get(script_url, allow_redirects=True, timeout=60)
                with temp_path.open(mode='wb') as f:
                    f.write(r.content)
            else:
                command += ['--script', script_url]

        command = ['--script', SCRIPTS_PATH]
        return command

    @property
    def command_options(self) -> List[str]:
        """Computes the list of nmap options."""
        command_options = []
        command_options.extend(self._set_version_detection_option())
        command_options.extend(self._set_dns_resolution_option())
        command_options.extend(self._set_ports_option())
        command_options.extend(self._set_timing_option())
        command_options.extend(self._set_port_scanning_technique())
        command_options.extend(self._set_no_ping_options())
        command_options.extend(self._set_privileged())
        command_options.extend(self._set_scripts())
        command_options.extend(self._set_script_default())
        return command_options
