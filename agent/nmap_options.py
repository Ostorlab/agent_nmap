"""Options defining an Nmap scan settings."""

import dataclasses
import enum
import logging
import tempfile
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)


class TimingTemplate(enum.Enum):
    """Timing config template"""

    T0 = "-T0"
    T1 = "-T1"
    T2 = "-T2"
    T3 = "-T3"
    T4 = "-T4"
    T5 = "-T5"


class PortScanningTechnique(enum.Enum):
    """Nmap multiple port scanning techniques."""

    TCP_SYN = "-sS"
    TCP_CONNECT = "-sT"
    UDP = "-sU"
    SCTP_INIT = "-sY"
    TCP_FULL = "-sN"
    TCP_FIN = "-sF"
    XMAS = "-sX"
    TCP_ACK = "-sA"
    TCP_WINDOW = "-sW"
    TCP_MAIMON = "-sM"
    SCTP_COOKIE = "-sZ"


@dataclasses.dataclass
class NmapOptions:
    """Storing the options of a Nmap scan."""

    dns_resolution: bool = True
    dns_servers: List[str] | None = None
    ports: str | None = None
    tcp_syn_ping_ports: str | None = None
    top_ports: None | int = None
    fast_mode: bool = False
    firewall_evasion: bool = False
    decoys : None | int = None
    timing_template: TimingTemplate = TimingTemplate.T3
    script_default: bool = False
    scripts: List[str] | None = dataclasses.field(
        default_factory=lambda: ["default", "banner"]
    )
    version_detection: bool = True
    os_detection: bool = True
    port_scanning_techniques: List[PortScanningTechnique] = dataclasses.field(
        default_factory=lambda: [
            PortScanningTechnique.TCP_SYN,
        ]
    )
    no_ping: bool = True
    privileged: Optional[bool] = None

    def _set_os_detection_option(self) -> List[str]:
        """Appends the os detection option to the list of nmap options."""
        command_options = []
        if self.os_detection is True:
            command_options.append("-O")
        return command_options

    def _set_version_detection_option(self) -> List[str]:
        """Appends the version detection option to the list of nmap options."""
        command_options = []
        if self.version_detection is True:
            command_options.append("-sV")
        return command_options

    def _set_decoys_options(self) -> list[str]:
        """ using decoys to minimize IPS detection, DISCLAIMER this might increase the likelihood of raising suspicion if service traffic is low"""
        command_options = []
        if self.decoys is not None:
            command_options.append("-D")
            command_options.append("RND:{self.decoys}")
        return command_options


    def _set_firewall_evasion_flags(self) -> List[str]:
        """Adds various techniques to nmap to bypass firewall evasions ref: https://nmap.org/book/man-bypass-firewalls-ids.html"""
        command_options = []
        if self.firewall_evasion is True:
            # Disabling arp pings, DNS resolution, and ping host discovery.
            command_options.append("--disable-arp-ping")
            command_options.append("-Pn")
            command_options.append("-n")
            # Request fragmentation to bypass custom packet filters.
            command_options.append("-f")
            command_options.append("--mtu")
            command_options.append("8")
            # Scans from HTTP port might be interpreted as false positives
            command_options.append("--source-port")
            command_options.append("80")
            ''' reducing timing template to evade IDSs like snort '''
            self.timing_template = TimingTemplate.T2
        return command_options

    def _set_host_discovery_options(self) -> List[str]:
        options = []
        if self.no_ping is True:
            options.append("-Pn")
        if self.tcp_syn_ping_ports is not None:
            options.append(f"-PS{self.tcp_syn_ping_ports}")
        return options

    def _set_privileged(self) -> List[str]:
        if self.privileged is True:
            return ["--privileged"]
        elif self.privileged is False:
            return ["--unprivileged"]
        else:
            return []

    def _set_dns_resolution_option(self) -> List[str]:
        """Appends the dns resolution option to the list of nmap options."""
        command_options = []
        if self.dns_resolution is True:
            command_options.append("-R")
            if self.dns_servers:
                dns_servers = ",".join([str(dns) for dns in self.dns_servers])
                command_options.append("--dns-servers")
                command_options.append(dns_servers)
        else:
            command_options.append("-n")
        return command_options

    def _set_ports_option(self) -> List[str]:
        """Appends the ports option to the list of nmap options."""
        if self.fast_mode is True and self.firewall_evasion is False:
            return ["-F"]
        elif self.top_ports is not None:
            return ["--top-ports", str(self.top_ports)]
        elif self.ports is not None:
            return ["-p", self.ports]
        else:
            return []

    def _set_timing_option(self) -> List[str]:
        """Appends the timing template option to the list of nmap options."""
        return [self.timing_template.value]

    def _set_port_scanning_techniques(self) -> List[str]:
        """Appends the port scanning technique to the list of nmap options."""
        return [tech.value for tech in self.port_scanning_techniques]

    def _set_script_default(self) -> List[str]:
        if self.script_default is True:
            return ["-sC"]
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
        for script in scripts:
            if script.startswith("http"):
                with tempfile.NamedTemporaryFile(delete=False) as t:
                    r = requests.get(script, allow_redirects=True, timeout=60)
                    t.write(r.content)
                    command.extend(["--script", t.name])
            else:
                command += ["--script", script]

        return command

    @property
    def command_options(self) -> List[str]:
        """Computes the list of nmap options."""
        command_options = []
        command_options.extend(self._set_os_detection_option())
        command_options.extend(self._set_version_detection_option())
        command_options.extend(self._set_dns_resolution_option())
        command_options.extend(self._set_ports_option())
        command_options.extend(self._set_firewall_evasion_flags())
        command_options.extend(self._set_timing_option())
        command_options.extend(self._set_port_scanning_techniques())
        command_options.extend(self._set_decoys_options())
        command_options.extend(self._set_host_discovery_options())
        command_options.extend(self._set_privileged())
        command_options.extend(self._set_scripts())
        command_options.extend(self._set_script_default())
        return command_options
