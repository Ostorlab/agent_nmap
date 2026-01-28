"""Nmap agent : Responsible for running scans on IP assets with Nmap Security Scanner.

The agent expects messages of type `v3.asset.ip.[v4,v6]`, `v3.asset.domain_name`, `v3.asset.link`,
or `v3.asset.file.api_schema`, and emits back messages of type `v3.asset.ip.v[4,6].port.service`,
and `v3.report.vulnerability` with a technical report of the scan.
"""

import datetime
import ipaddress
import logging
import re
import subprocess
from typing import Dict, Any, Tuple, Optional, List, cast
from urllib import parse

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.assets import domain_name as domain_name_asset
from ostorlab.assets import ipv4 as ipv4_asset
from ostorlab.assets import ipv6 as ipv6_asset
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import parsing_utils
from agent import nmap_options
from agent import nmap_wrapper
from agent import process_scans
from agent.mcp import runner as mcp_runner

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = datetime.timedelta(minutes=1)

WIREGUARD_CONFIG_FILE_PATH = "/etc/wireguard/wg0.conf"
DNS_RESOLV_CONFIG_PATH = "/etc/resolv.conf"

DEFAULT_MASK_IPV6 = 128
# scan up to 65536 host
IPV6_CIDR_LIMIT = 112


class Error(Exception):
    """Base Custom Error Class."""


class RunCommandError(Error):
    """Error when running a command using a subprocess."""


class NmapAgent(
    agent.Agent, vuln_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin
):
    """Agent responsible for running scans over IP assets with Nmap Security Scanner.
    For more visit https://github.com/Ostorlab/ostorlab."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_domain_regex: Optional[str] = self.args.get("scope_domain_regex")
        self._vpn_config: Optional[str] = self.args.get("vpn_config")
        self._dns_config: Optional[str] = self.args.get("dns_config")
        self._host_timeout: Optional[int] = self.args.get("host_timeout")

        self.should_start_mcp_server: bool = self.args.get(
            "should_start_mcp_server", False
        )

    def start(self) -> None:
        if self._vpn_config is not None and self._dns_config is not None:
            self._connect_to_vpn()

        if self.should_start_mcp_server is True:
            logger.info("Running Nmap agent in MCP mode.")
            mcp_runner.run()

    def process(self, message: msg.Message) -> None:
        """Process messages of type v3.asset.ip.[v4,v6] and performs a network scan. Once the scan is completed, it
        emits messages of type : `v3.asset.ip.port.service` and message of type `v3.report.vulnerability` with the
        technical report of the scan.

        Args:
            message: message containing the IP to scan, the mask & the version.
        """

        if self.should_start_mcp_server is True:
            logger.warning("Oxo messages are ignored in MCP mode: %s", message.selector)
            return None

        logger.debug("processing message of selector : %s", message.selector)
        host = message.data.get("host", "")
        hosts: List[Tuple[str, int]] = []

        if "v4" in message.selector:
            mask = int(message.data.get("mask", "32"))
            max_mask = int(self.args.get("max_network_mask_ipv4", "32"))
            if mask < max_mask:
                for subnet in ipaddress.ip_network(f"{host}/{mask}").subnets(
                    new_prefix=max_mask
                ):
                    hosts.append((str(subnet.network_address), max_mask))
            else:
                hosts = [(host, mask)]
        elif "v6" in message.selector:
            mask = int(message.data.get("mask", DEFAULT_MASK_IPV6))
            if mask < IPV6_CIDR_LIMIT:
                raise ValueError(
                    f"Subnet mask below {IPV6_CIDR_LIMIT} is not supported"
                )

            max_mask = int(self.args.get("max_network_mask_ipv6", "128"))
            if mask < max_mask:
                for subnet in ipaddress.ip_network(
                    f"{host}/{mask}", strict=False
                ).subnets(new_prefix=max_mask):
                    hosts.append((str(subnet.network_address), max_mask))
            else:
                hosts = [(host, mask)]

        domain_name = self._prepare_domain_name(
            message.data.get("name"),
            message.data.get("url") or message.data.get("endpoint_url"),
        )

        if len(hosts) > 0:
            logger.info("Scanning hosts `%s`.", hosts)
            for host, mask in hosts:
                if not self.add_ip_network(
                    b"agent_nmap_asset",
                    ipaddress.ip_network(f"{host}/{mask}", strict=False),
                ):
                    logger.debug(
                        "target %s/%s was processed before, exiting", host, mask
                    )
                    return
                try:
                    scan_results, normal_results = self._scan_host(host, mask)
                except subprocess.CalledProcessError:
                    logger.error("Nmap command failed to scan host %s", host)
                    continue
                logger.info("scan results %s", scan_results)

                self._emit_services(scan_results, domain_name)
                self._emit_network_scan_finding(scan_results, normal_results)
                self._emit_fingerprints(scan_results, domain_name)
        elif domain_name is not None:
            logger.info("Scanning domain `%s`.", domain_name)
            if not self.set_add(b"agent_nmap_asset", domain_name):
                logger.debug("target %s was processed before, exiting", domain_name)
                return
            if self._is_domain_in_scope(domain_name) is False:
                return
            try:
                scan_results, normal_results = self._scan_domain(domain_name)
            except subprocess.CalledProcessError:
                logger.error("Nmap command failed to scan domain name %s", domain_name)
                return
            logger.info("scan results %s", scan_results)

            self._emit_services(scan_results, domain_name)
            self._emit_network_scan_finding(scan_results, normal_results)
            self._emit_fingerprints(scan_results, domain_name)
        else:
            logger.error("Neither host or domain are set.")

    def _scan_host(self, host: str, mask: int) -> Tuple[Dict[str, Any], str]:
        options = nmap_options.NmapOptions(
            dns_resolution=False,
            ports=self.args.get("ports"),
            tcp_syn_ping_ports=self.args.get("tcp_syn_ping_ports"),
            top_ports=self.args.get("top_ports"),
            fast_mode=self.args.get("fast_mode", False),
            no_ping=self.args.get("no_ping", False),
            timing_template=nmap_options.TimingTemplate[self.args["timing_template"]],
            scripts=self.args.get("scripts"),
            script_default=self.args.get("script_default", False),
            version_detection=self.args.get("version_info", False),
            host_timeout=self._host_timeout,
        )
        client = nmap_wrapper.NmapWrapper(options)

        logger.info("scanning target %s/%s with options %s", host, mask, options)
        scan_results, normal_results = client.scan_hosts(hosts=host, mask=mask)
        return scan_results, normal_results

    def _scan_domain(self, domain_name: str) -> Tuple[Dict[str, Any], str]:
        options = nmap_options.NmapOptions(
            dns_resolution=False,
            ports=self.args.get("ports"),
            tcp_syn_ping_ports=self.args.get("tcp_syn_ping_ports"),
            top_ports=self.args.get("top_ports"),
            fast_mode=self.args.get("fast_mode", False),
            no_ping=self.args.get("no_ping", False),
            timing_template=nmap_options.TimingTemplate[self.args["timing_template"]],
            scripts=self.args.get("scripts"),
            script_default=self.args.get("script_default", False),
            version_detection=self.args.get("version_info", False),
            os_detection=self.args.get("os", False),
            host_timeout=self._host_timeout,
        )
        client = nmap_wrapper.NmapWrapper(options)
        logger.info("scanning domain %s with options %s", domain_name, options)
        scan_results, normal_results = client.scan_domain(domain_name=domain_name)
        return scan_results, normal_results

    def _is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is in the scan scope with a regular expression."""
        if self._scope_domain_regex is None:
            return True
        domain_in_scope = re.match(self._scope_domain_regex, domain)
        if domain_in_scope is None:
            logger.warning(
                "Domain %s is not in scanning scope %s",
                domain,
                self._scope_domain_regex,
            )
            return False
        else:
            return True

    def _prepare_domain_name(
        self, domain_name: Optional[str], url: Optional[str]
    ) -> Optional[str]:
        """Prepare domain name based on type, if a url is provided, return its domain."""
        if domain_name is not None:
            return domain_name
        elif url is not None:
            return parse.urlparse(url).hostname
        else:
            return None

    def _prepare_metadata(
        self, ports: Dict[str, Any] | List[Dict[str, Any]]
    ) -> List[vuln_mixin.VulnerabilityLocationMetadata]:
        ret = []
        if isinstance(ports, List):
            for port_dict in ports:
                port = port_dict.get("@portid", "")
                ret.append(
                    vuln_mixin.VulnerabilityLocationMetadata(
                        metadata_type=vuln_mixin.MetadataType.PORT, value=port
                    )
                )
        elif isinstance(ports, Dict):
            port = ports.get("@portid", "")
            ret.append(
                vuln_mixin.VulnerabilityLocationMetadata(
                    metadata_type=vuln_mixin.MetadataType.PORT, value=port
                )
            )
        return ret

    def _emit_network_domain_name_finding(
        self,
        domains: dict[str, dict[str, str]] | dict[str, list[dict[str, str]]],
        technical_detail: str,
        ports: list[dict[str, str]],
    ) -> None:
        domains_hostname: dict[str, str] | list[dict[str, str]] = domains.get(
            "hostname", {}
        )
        if isinstance(domains_hostname, list):
            for domain_dict in domains_hostname:
                domain = domain_dict.get("@name", "")
                self.report_vulnerability(
                    entry=kb.KB.NETWORK_PORT_SCAN,
                    technical_detail=technical_detail,
                    risk_rating=vuln_mixin.RiskRating.INFO,
                    vulnerability_location=vuln_mixin.VulnerabilityLocation(
                        metadata=self._prepare_metadata(ports),
                        asset=domain_name_asset.DomainName(name=domain),
                    ),
                )
        elif isinstance(domains_hostname, dict):
            domain = domains_hostname.get("@name", "")
            self.report_vulnerability(
                entry=kb.KB.NETWORK_PORT_SCAN,
                technical_detail=technical_detail,
                risk_rating=vuln_mixin.RiskRating.INFO,
                vulnerability_location=vuln_mixin.VulnerabilityLocation(
                    metadata=self._prepare_metadata(ports),
                    asset=domain_name_asset.DomainName(name=domain),
                ),
            )

    def _emit_network_scan_finding(
        self, scan_results: Dict[str, Any], normal_results: str
    ) -> None:
        scan_result_technical_detail = process_scans.get_technical_details(scan_results)
        if normal_results is not None:
            technical_detail = (
                f"{scan_result_technical_detail}\n```xml\n{normal_results}\n```"
            )
            hosts = scan_results.get("nmaprun", {}).get("host", {})
            if isinstance(hosts, dict) is True:
                hosts = [hosts]
            for host in hosts:
                domains = host.get("hostnames", {})
                ports = host.get("ports", {}).get("port", "")
                address = host.get("address", {})
                if domains is not None and len(domains.values()) > 0:
                    self._emit_network_domain_name_finding(
                        domains, technical_detail, ports
                    )
                elif address.get("@addrtype", "") == "ipv4":
                    self.report_vulnerability(
                        entry=kb.KB.NETWORK_PORT_SCAN,
                        technical_detail=technical_detail,
                        risk_rating=vuln_mixin.RiskRating.INFO,
                        vulnerability_location=vuln_mixin.VulnerabilityLocation(
                            metadata=self._prepare_metadata(ports),
                            asset=ipv4_asset.IPv4(host=address.get("@addr", "")),
                        ),
                    )
                elif address.get("@addrtype", "") == "ipv6":
                    self.report_vulnerability(
                        entry=kb.KB.NETWORK_PORT_SCAN,
                        technical_detail=technical_detail,
                        risk_rating=vuln_mixin.RiskRating.INFO,
                        vulnerability_location=vuln_mixin.VulnerabilityLocation(
                            metadata=self._prepare_metadata(ports),
                            asset=ipv6_asset.IPv6(host=address.get("@addr", "")),
                        ),
                    )

    def _emit_services(
        self, scan_results: Dict[str, Any], domain_name: Optional[str]
    ) -> None:
        if domain_name is not None:
            logger.info("Services targeting domain `%s`.", domain_name)
            for data in parsing_utils.get_domain_name_services(
                scan_results, domain_name
            ):
                logger.info("Domain Service Identified %s.", data)
                self.emit("v3.asset.domain_name.service", dict(data))

        port_services = parsing_utils.get_port_services(scan_results)
        for service in port_services:
            addr_version = service.get("addr_version")
            address = service.get("address")
            if addr_version == "ipv4":
                selector = "v3.asset.ip.v4.port.service"
                self.set_add(b"agent_nmap_asset", f"{address}/32")
            elif addr_version == "ipv6":
                selector = "v3.asset.ip.v6.port.service"
                self.set_add(b"agent_nmap_asset", f"{address}/64")
            else:
                raise ValueError(f"Incorrect ip version {addr_version}")

            service_dict = dict(service)
            service_dict.pop("address")
            service_dict.pop("addr_version")
            self.emit(selector, service_dict)

    def _emit_fingerprints(
        self, scan_results: Dict[str, Any], domain_name: Optional[str]
    ) -> None:
        self._emit_os_fingerprints(scan_results)
        self._emit_service_library_fingerprints(scan_results)
        self._emit_domain_name_service_library_fingerprints(domain_name, scan_results)

    def _emit_domain_name_service_library_fingerprints(
        self, domain_name: str | None, scan_results: dict[str, Any]
    ) -> None:
        if domain_name is not None:
            for (
                fingerprint
            ) in parsing_utils.get_domain_name_service_library_fingerprints(
                scan_results, domain_name
            ):
                self.emit(
                    selector="v3.fingerprint.domain_name.service.library",
                    data=dict(fingerprint),
                )

    def _emit_service_library_fingerprints(self, scan_results: dict[str, Any]) -> None:
        for data in parsing_utils.get_service_libraries(scan_results):
            version = data.get("addr_version")
            address = data.get("host")
            if version == "ipv4":
                selector = "v3.fingerprint.ip.v4.service.library"
                self.set_add(b"agent_nmap_asset", f"{address}/32")
            elif version == "ipv6":
                selector = "v3.fingerprint.ip.v6.service.library"
                self.set_add(b"agent_nmap_asset", f"{address}/64")
            else:
                raise ValueError(f"Incorrect ip version {version}")
            data_dict = dict(data)
            data_dict.pop("addr_version")
            self.emit(selector, data_dict)

    def _emit_os_fingerprints(self, scan_results: dict[str, Any]) -> None:
        os_fingerprints = parsing_utils.get_os_fingerprints(scan_results)
        for fingerprint in os_fingerprints:
            version = fingerprint.get("version")
            address = fingerprint.get("host")
            if version == "ipv4":
                selector = "v3.fingerprint.ip.v4.service.library"
                self.set_add(b"agent_nmap_asset", f"{address}/32")
            elif version == "ipv6":
                selector = "v3.fingerprint.ip.v6.service.library"
                self.set_add(b"agent_nmap_asset", f"{address}/64")
            else:
                raise ValueError(f"Incorrect ip version {version}")

            fingerprint_dict = dict(fingerprint)
            fingerprint_dict.pop("version")
            self.emit(selector, fingerprint_dict)

    def _connect_to_vpn(self) -> None:
        """Connect to VPN."""
        logger.info("Trying to scan the asset with VPN")
        try:
            with open(WIREGUARD_CONFIG_FILE_PATH, "w", encoding="utf-8") as conf_file:
                conf_file.write(cast(str, self._vpn_config))

            self._exec_command(["wg-quick", "up", "wg0"])

            with open(DNS_RESOLV_CONFIG_PATH, "w", encoding="utf-8") as conf_file:
                conf_file.write(cast(str, self._dns_config))

            logger.info("connected with %s", WIREGUARD_CONFIG_FILE_PATH)

        except RunCommandError as e:
            logger.warning("%s", e)

    def _exec_command(self, command: List[str]) -> None:
        """Execute a command."""
        try:
            logger.info("%s", " ".join(command))
            output = subprocess.run(
                command,
                capture_output=True,
                timeout=COMMAND_TIMEOUT.seconds,
                check=True,
            )
            logger.debug("process returned: %s", output.returncode)
            logger.debug("output: %s", output.stdout.decode())
            logger.debug("err: %s", output.stderr.decode())

        except subprocess.CalledProcessError as e:
            raise RunCommandError(
                f"An error occurred while running the command {' '.join(command)}"
            ) from e
        except subprocess.TimeoutExpired:
            logger.warning("Command timed out for command %s", " ".join(command))


if __name__ == "__main__":
    logger.info("starting agent ...")
    NmapAgent.main()
