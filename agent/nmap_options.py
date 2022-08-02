"""Options defining an Nmap scan settings."""

import dataclasses
import enum
import logging
from typing import List, Optional

import tempfile
import pathlib

logger = logging.getLogger(__name__)

OUTPUT_PATH = '/tmp/result_nmap.json'
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
    scripts: List[str] = None
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

    def _set_scripts(self):
        if self.scripts is not None:
            self._run_scripts_command(self.scripts)
        else:
            return []

    def _run_scripts_command(self, scripts: List[str]):
        """Run nmap scan on the provided scripts"""
        scripts_temp = []
        # create scripts
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = pathlib.Path(tmp_dir)
            for script in scripts:
                temp_path = (path / script)
                content = ""
                with pathlib.Path(script).open(mode='rb') as r:
                    content = r.read()
                with temp_path.open(mode='wb') as f:
                    f.write(content)
                scripts_temp.append(str(temp_path))

                # build commands
                if len(scripts_temp) > 0:
                    command = ['--script']
                    if scripts_temp is not None:
                        for script in scripts_temp:
                            command.extend([script])
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
