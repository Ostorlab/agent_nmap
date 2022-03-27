"""Nmap agent : Responsible for running scans on IP assets with Nmap Security Scanner.

The agent expects messages of type `v3.asset.ip.[v4,v6]`, and emits back messages of type
`v3.asset.ip.v[4,6].port.service`, and `v3.report.vulnerability` with a technical report of the scan.
"""

import json
import logging

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from rich import logging as rich_logging

from agent import generators
from agent import nmap_options
from agent import nmap_wrapper


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

# TODO (Abderrahim) : Disable till resolving the messages loops by adding the seen message mixin.
ENABLE_SERVICE_MESSAGES = False


class NmapAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Agent responsible for running scans over IP assets with Nmap Security Scanner.
       For more visit https://github.com/Ostorlab/ostorlab."""

    def process(self, message: msg.Message) -> None:
        """Process messages of type v3.asset.ip.[v4,v6] and performs a network scan. Once the scan is completed, it
        emits messages of type : `v3.asset.ip.port.service` and message of type `v3.report.vulnerability` with the
         technical report of the scan.

        Args:
            message: message containing the IP to scan, the mask & the version.
        """
        logger.info('processing message of selector : %s', message.selector)
        hosts = message.data.get('host')
        mask = message.data.get('mask', '32')
        domain_name = message.data.get('name')
        options = nmap_options.NmapOptions(dns_resolution=False,
                                           ports='0-65535',
                                           timing_template=nmap_options.TimingTemplate.T5,
                                           version_detection=True)
        client = nmap_wrapper.NmapWrapper(options)
        scan_results = None
        if hosts is not None:
            logger.info('scanning target %s/%s with options %s', hosts, mask, options)
            scan_results = client.scan_hosts(hosts=hosts, mask=mask)
        elif domain_name is not None:
            logger.info('scanning domain %s with options %s', domain_name, options)
            scan_results = client.scan_domain(domain_name=domain_name)

        logger.info('scan results %s', scan_results)

        if ENABLE_SERVICE_MESSAGES is True:
            self._emit_services(message, scan_results)
        self._emit_network_scan_finding(scan_results)

    def _emit_network_scan_finding(self, scan_results):
        if scan_results is not None:
            scan_results = json.dumps(scan_results, indent=4, sort_keys=True)
            technical_detail = f'```json\n{scan_results}\n```'
            self.report_vulnerability(entry=kb.KB.NETWORK_PORT_SCAN,
                                      technical_detail=technical_detail,
                                      risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)

    def _emit_services(self, message, scan_results):
        if scan_results is not None:
            version = message.data['version']
            if version == 4:
                selector = 'v3.asset.ip.v4.port.service'
            elif version == 6:
                selector = 'v3.asset.ip.v6.port.service'
            else:
                raise ValueError(f'Incorrect ip version {version}')
            for data in generators.get_services(scan_results):
                self.emit(selector, data)


if __name__ == '__main__':
    logger.info('starting agent ...')
    NmapAgent.main()
