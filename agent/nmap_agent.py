"""Nmap agent : Responsible for running scans on IP assets with Nmap Security Scanner.

The agent expects messages of type `v3.asset.ip.[v4,v6]`, and emits back messages of type
`v3.asset.ip.v[4,6].port.service`, and `v3.report.vulnerability` with a technical report of the scan.
"""

import logging
from typing import Optional
from urllib import parse

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent import message as msg
from ostorlab.agent.kb import kb
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
        host = message.data.get('host')

        # Differentiate between a single IP mask in IPv4 and IPv6.
        if 'v4' in message.selector:
            mask = message.data.get('mask', '32')
        else:
            mask = message.data.get('mask', '64')

        domain_name = self._prepare_domain_name(message.data.get('name'), message.data.get('url'))

        if host is not None:
            if not self.set_add(b'agent_nmap_asset', f'{host}/{mask}'):
                logger.info('target %s/%s was processed before, exiting', host, mask)
                return
            scan_results, normal_results = self._scan_host(host, mask)
        elif domain_name is not None:
            if not self.set_add(b'agent_nmap_asset', domain_name):
                logger.info('target %s was processed before, exiting', domain_name)
                return
            scan_results, normal_results = self._scan_domain(domain_name)
        else:
            raise ValueError('not host or domain name are set')

        logger.info('scan results %s', scan_results)

        self._emit_services(scan_results, domain_name)
        self._emit_network_scan_finding(scan_results, normal_results)

    def _scan_host(self, host: str, mask: str):
        options = nmap_options.NmapOptions(dns_resolution=False,
                                           ports=self.args.get('ports'),
                                           timing_template=nmap_options.TimingTemplate[
                                               self.args.get('timing_template')],
                                           scripts=self.args.get('scripts'),
                                           version_detection=True)
        client = nmap_wrapper.NmapWrapper(options)

        logger.info('scanning target %s/%s with options %s', host, mask, options)
        scan_results, normal_results = client.scan_hosts(hosts=host, mask=mask)
        return scan_results, normal_results

    def _scan_domain(self, domain_name: str):
        options = nmap_options.NmapOptions(dns_resolution=False,
                                           ports=self.args.get('ports'),
                                           timing_template=nmap_options.TimingTemplate[
                                               self.args.get('timing_template')],
                                           scripts=self.args.get('scripts'),
                                           version_detection=True)
        client = nmap_wrapper.NmapWrapper(options)
        logger.info('scanning domain %s with options %s', domain_name, options)
        scan_results, normal_results = client.scan_domain(domain_name=domain_name)
        return scan_results, normal_results

    def _prepare_domain_name(self, domain_name: Optional[str], url: Optional[str]):
        """Prepare domain name based on type, if a url is provided, return its domain."""
        if domain_name is not None:
            return domain_name
        elif url is not None:
            return parse.urlparse(url).hostname

    def _emit_network_scan_finding(self, scan_results, normal_results):
        scan_result_technical_detail = process_scans.get_technical_details(scan_results)
        if normal_results is not None:
            technical_detail = f'{scan_result_technical_detail}\n```xml\n{normal_results}\n```'
            self.report_vulnerability(entry=kb.KB.NETWORK_PORT_SCAN,
                                      technical_detail=technical_detail,
                                      risk_rating=vuln_mixin.RiskRating.INFO)

    def _emit_services(self, scan_results, domain_name):
        logger.info('sending results to %s', domain_name)
        if scan_results is not None and\
                scan_results.get('nmaprun') is not None and\
                scan_results['nmaprun'].get('host') is not None:
            version = scan_results['nmaprun'].get('host', {}).get('address', {}).get('@addrtype')
            address = scan_results['nmaprun'].get('host', {}).get('address', {}).get('@addr')
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


if __name__ == '__main__':
    logger.info('starting agent ...')
    NmapAgent.main()
