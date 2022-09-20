"""Nmap agent : Responsible for running scans on IP assets with Nmap Security Scanner.

The agent expects messages of type `v3.asset.ip.[v4,v6]`, and emits back messages of type
`v3.asset.ip.v[4,6].port.service`, and `v3.report.vulnerability` with a technical report of the scan.
"""
import ipaddress
import logging
from typing import Dict, Any, Tuple, Optional, List
from urllib import parse

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import generators
from agent import nmap_options
from agent import nmap_wrapper
from agent import process_scans

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)


class NmapAgent(agent.Agent, vuln_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin):
    """Agent responsible for running scans over IP assets with Nmap Security Scanner.
       For more visit https://github.com/Ostorlab/ostorlab."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: msg.Message) -> None:
        """Process messages of type v3.asset.ip.[v4,v6] and performs a network scan. Once the scan is completed, it
        emits messages of type : `v3.asset.ip.port.service` and message of type `v3.report.vulnerability` with the
        technical report of the scan.

        Args:
            message: message containing the IP to scan, the mask & the version.
        """
        logger.info('processing message of selector : %s', message.selector)
        host = message.data.get('host', '')
        hosts: List[Tuple[str, int]] = []

        # Differentiate between a single IP mask in IPv4 and IPv6.
        if 'v4' in message.selector:
            mask = int(message.data.get('mask', '32'))
            max_mask = int(self.args.get('max_network_mask_ipv4', '32'))
            if mask < max_mask:
                for subnet in ipaddress.ip_network(f'{host}/{mask}').subnets(new_prefix=max_mask):
                    hosts.append((str(subnet.network_address), max_mask))
            else:
                hosts = [(host, mask)]
        elif 'v6' in message.selector:
            mask = int(message.data.get('mask', '64'))
            max_mask = int(self.args.get('max_network_mask_ipv6', '64'))
            if mask < max_mask:
                for subnet in ipaddress.ip_network(f'{host}/{mask}').subnets(new_prefix=max_mask):
                    hosts.append((str(subnet.network_address), max_mask))
            else:
                hosts = [(host, mask)]

        domain_name = self._prepare_domain_name(message.data.get('name'), message.data.get('url'))

        if len(hosts) > 0:
            for host, mask in hosts:
                if not self.add_ip_network(b'agent_nmap_asset', ipaddress.ip_network(f'{host}/{mask}', strict=False)):
                    logger.info('target %s/%s was processed before, exiting', host, mask)
                    return
                scan_results, normal_results = self._scan_host(host, mask)
                logger.info('scan results %s', scan_results)

                self._emit_services(scan_results, domain_name)
                self._emit_network_scan_finding(scan_results, normal_results)
                self._emit_fingerprints(scan_results, domain_name)
        elif domain_name is not None:
            if not self.set_add(b'agent_nmap_asset', domain_name):
                logger.info('target %s was processed before, exiting', domain_name)
                return
            scan_results, normal_results = self._scan_domain(domain_name)
            logger.info('scan results %s', scan_results)

            self._emit_services(scan_results, domain_name)
            self._emit_network_scan_finding(scan_results, normal_results)
            self._emit_fingerprints(scan_results, domain_name)
        else:
            raise ValueError('not host or domain name are set')

    def _scan_host(self, host: str, mask: int) -> Tuple[Dict[str, Any], str]:
        options = nmap_options.NmapOptions(dns_resolution=False,
                                           ports=self.args.get('ports'),
                                           fast_mode=self.args.get('fast_mode', False),
                                           no_ping=self.args.get('no_ping', False),
                                           timing_template=nmap_options.TimingTemplate[
                                               self.args['timing_template']],
                                           scripts=self.args.get('scripts'),
                                           script_default=self.args.get('script_default', False),
                                           version_detection=self.args.get('version_info', False))
        client = nmap_wrapper.NmapWrapper(options)

        logger.info('scanning target %s/%s with options %s', host, mask, options)
        scan_results, normal_results = client.scan_hosts(hosts=host, mask=mask)
        return scan_results, normal_results

    def _scan_domain(self, domain_name: str) -> Tuple[Dict[str, Any], str]:
        options = nmap_options.NmapOptions(dns_resolution=False,
                                           ports=self.args.get('ports'),
                                           fast_mode=self.args.get('fast_mode', False),
                                           no_ping=self.args.get('no_ping', False),
                                           timing_template=nmap_options.TimingTemplate[
                                               self.args['timing_template']],
                                           scripts=self.args.get('scripts'),
                                           script_default=self.args.get('script_default', False),
                                           version_detection=self.args.get('version_info', False))
        client = nmap_wrapper.NmapWrapper(options)
        logger.info('scanning domain %s with options %s', domain_name, options)
        scan_results, normal_results = client.scan_domain(domain_name=domain_name)
        return scan_results, normal_results

    def _prepare_domain_name(self, domain_name: Optional[str], url: Optional[str]) -> Optional[str]:
        """Prepare domain name based on type, if a url is provided, return its domain."""
        if domain_name is not None:
            return domain_name
        elif url is not None:
            return parse.urlparse(url).hostname
        else:
            return None

    def _emit_network_scan_finding(self, scan_results: Dict[str, Any], normal_results: str) -> None:
        scan_result_technical_detail = process_scans.get_technical_details(scan_results)
        if normal_results is not None:
            technical_detail = f'{scan_result_technical_detail}\n```xml\n{normal_results}\n```'
            self.report_vulnerability(entry=kb.KB.NETWORK_PORT_SCAN,
                                      technical_detail=technical_detail,
                                      risk_rating=vuln_mixin.RiskRating.INFO)

    def _emit_services(self, scan_results: Dict[str, Any], domain_name: Optional[str]) -> None:
        logger.info('sending results to %s', domain_name)
        if (scan_results is not None and
                scan_results.get('nmaprun') is not None and
                scan_results['nmaprun'].get('host') is not None):

            up_hosts = scan_results['nmaprun'].get('host', [])
            if isinstance(up_hosts, dict):
                up_hosts = [up_hosts]

            for host in up_hosts:
                version = host.get('address', {}).get('@addrtype')
                address = host.get('address', {}).get('@addr')
                if version == 'ipv4':
                    selector = 'v3.asset.ip.v4.port.service'
                    self.set_add(b'agent_nmap_asset', f'{address}/32')
                elif version == 'ipv6':
                    selector = 'v3.asset.ip.v6.port.service'
                    self.set_add(b'agent_nmap_asset', f'{address}/64')
                else:
                    raise ValueError(f'Incorrect ip version {version}')

                for data in generators.get_services(scan_results):
                    logger.info('sending results to selector %s', selector)
                    self.emit(selector, data)
                    if domain_name is not None:
                        domain_name_service = {'name': domain_name, 'port': data.get('port'),
                                               'schema': data.get('service')}
                        logger.info('sending results to selector domain service selector')
                        self.emit('v3.asset.domain_name.service', domain_name_service)

    def _emit_fingerprints(self, scan_results: Dict[str, Any], domain_name: Optional[str]) -> None:
        logger.info('sending results to %s', domain_name)
        if (scan_results is not None and
                scan_results.get('nmaprun') is not None and
                scan_results['nmaprun'].get('host') is not None):

            up_hosts = scan_results['nmaprun'].get('host', [])
            if isinstance(up_hosts, dict):
                up_hosts = [up_hosts]

            for host in up_hosts:
                version = host.get('address', {}).get('@addrtype')
                address = host.get('address', {}).get('@addr')
                if version == 'ipv4':
                    selector = 'v3.fingerprint.ip.v4.service.library'
                    default_mask = 32
                    self.set_add(b'agent_nmap_asset', f'{address}/32')
                elif version == 'ipv6':
                    selector = 'v3.fingerprint.ip.v6.service.library'
                    default_mask = 164
                    self.set_add(b'agent_nmap_asset', f'{address}/64')
                else:
                    raise ValueError(f'Incorrect ip version {version}')

                for data in generators.get_services(scan_results):
                    if data.get('banner') is not None:
                        logger.info('sending results to selector %s', selector)
                        fingerprint_data = {
                            'host': data.get('host'),
                            'mask': data.get('mask', str(default_mask)),
                            'version': data.get('version'),
                            'library_type': 'BACKEND_COMPONENT',
                            'service': data.get('service'),
                            'port': data.get('port'),
                            'protocol': data.get('protocol'),
                            'library_name': data.get('banner'),
                            'detail': data.get('banner'),
                        }
                        self.emit(selector, fingerprint_data)


if __name__ == '__main__':
    logger.info('starting agent ...')
    NmapAgent.main()
