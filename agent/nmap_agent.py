"""Nmap agent : Responsible for running scans on IP assets with Nmap Security Scanner.
Expects messages of type v3.asset.ip, and emits back messages of type
v3.asset.ip.port.service, and finally emits message of type v3.report.vulnerability with a technical report of the scan.
"""

import logging

from rich import logging as rich_logging
from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent import nmap
from agent import generators


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)


class NmapAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Agent responsible for running scans over IP assets with Nmap Security Scanner.
       For more visit https://github.com/Ostorlab/ostorlab."""

    def process(self, message: msg.Message) -> None:
        """Process message of type v3.asset.ip, perform the respective scan and
        ,emits messages of type : v3.asset.ip.port.service, and finally emits a
        message of type v3.report.vulnerability with the technical report of the scan.

        Args:
            message: message containing the IP to scan, the mask & the version.
        """
        hosts = message.data['host']
        mask = message.data.get('mask', '32')
        version = message.data['version']
        if version==4:
            selector = 'v3.asset.ip.v4.port.service'
        elif version==6:
            selector = 'v3.asset.ip.v6.port.service'
        else:
            raise ValueError(f'Incorrect ip version {version}')

        nmap_scanner = nmap.NmapWrapper(hosts=hosts, mask=mask, ip_version=version)
        scan_results = nmap_scanner.scan()

        for data in generators.get_services(scan_results):
            self.emit(selector, data)

        technical_detail = f'```json\n{scan_results}\n```'

        self.report_vulnerability(entry=kb.KB.NETWORK_PORT_SCAN,
                                  technical_detail=technical_detail,
                                  risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO, dna='')


if __name__ == '__main__':
    logger.debug('Nmap Agent starting..')
    NmapAgent.main()
