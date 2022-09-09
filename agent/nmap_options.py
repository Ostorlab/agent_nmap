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


@dataclasses.dataclass
class NmapOptions:
    """Storing the options of an Nmap scan."""
    dns_resolution: bool = True
    dns_servers: List[str] | None = None
    ports: Optional[str] | None = None
    timing_template: TimingTemplate = TimingTemplate.T3
    scripts: List[str] | None = None
    version_detection: bool = True

    def _set_version_detection_option(self) -> List[str]:
        """Appends the  option to the list of nmap options."""
        command_options = []
        if self.version_detection is True:
            command_options.append('-sV')
            command_options.append('--script=banner')
        return command_options

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
        if self.ports is not None:
            return ['-p', self.ports]
        else:
            return []

    def _set_timing_option(self) -> List[str]:
        """Appends the timing template option to the list of nmap options."""
        return [self.timing_template.value]

    def _set_scripts(self) -> List[str]:
        if self.scripts is not None and len(self.scripts) > 0:
            return self._run_scripts_command(self.scripts)
        else:
            return []

    def _run_scripts_command(self, scripts: List[str]) -> List[str]:
        """Run nmap scan on the provided scripts"""
        path = pathlib.Path(SCRIPTS_PATH)
        if not pathlib.Path.exists(path):
            os.mkdir(SCRIPTS_PATH)
        for script_url in scripts:
            temp_path = (path / script_url.split('/')[-1])
            r = requests.get(script_url, allow_redirects=True, timeout=60)
            with temp_path.open(mode='wb') as f:
                f.write(r.content)
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
        command_options.extend(self._set_scripts())
        return command_options
