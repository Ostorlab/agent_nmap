"""Unittests for Nmap agent."""
import pathlib

from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent import message
from ostorlab.runtimes import definitions as runtime_definitions

from agent import nmap_agent

OSTORLAB_YAML_PATH = (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').absolute()

JSON_OUTPUT = {
    'nmaprun': {
        'host': {
            'address': {'@addr': '127.0.0.1', '@addrtype': 'ipv4'},
            'ports': {
                'port': {
                    '@portid': '21',
                    '@protocol': 'tcp',
                    'state': {
                        '@state': 'open'
                    },
                    'service': {
                        '@name': 'ssh'
                    }
                }
            }
        }
    }
}

HUMAN_OUTPUT = """
# Nmap 7.92 scan initiated Mon Mar 28 15:05:11 2022 as: nmap -sV --script=banner -n "-p 0-65535" -T5 -oX /tmp/xmloutput -oN /tmp/normal 8.8.8.8                                                                 │ │
Warning: 8.8.8.8 giving up on port because retransmission cap hit (2).                                                                                                                                                   │ │
Nmap scan report for 8.8.8.8 (8.8.8.8)                                                                                                                                                                     │ │
Host is up (0.0061s latency).                                                                                                                                                                                                 │ │
Other addresses for 8.8.8.8 (not scanned): 8.8.8.8                                                                                                                                                       │ │
Not shown: 65532 filtered tcp ports (no-response)                                                                                                                                                                             │ │
PORT     STATE  SERVICE  VERSION                                                                                                                                                                                              │ │
22/tcp   closed ssh                                                                                                                                                                                                           │ │
80/tcp   open   http     awselb/2.0   
"""


def testAgentLifeCyle_whenScanRunsWithoutErrors_emitsBackMessagesAndVulnerability( \
        agent_mock, agent_persist_mock, mocker):
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service, and of type vulnerability.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(JSON_OUTPUT, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert len(agent_mock) == 2
        assert agent_mock[0].selector == 'v3.asset.ip.v4.port.service'
        assert agent_mock[1].selector == 'v3.report.vulnerability'
        assert agent_mock[1].data['risk_rating'] == 'INFO'
        assert agent_mock[1].data['title'] == 'Network Port Scan'
        assert agent_mock[1].data['short_description'] == 'List of open network ports.'


def testAgentLifeCyle_whenScanRunsWithoutErrors_emitsBackVulnerabilityMsg(agent_mock, agent_persist_mock, mocker):
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type vulnerability.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(JSON_OUTPUT, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert len(agent_mock) == 2
        assert agent_mock[1].selector == 'v3.report.vulnerability'
        assert agent_mock[1].data['risk_rating'] == 'INFO'
        assert agent_mock[1].data['title'] == 'Network Port Scan'
        assert agent_mock[1].data['short_description'] == 'List of open network ports.'


def testAgentLifeCyle_whenLinkAssetAndScanRunsWithoutErrors_emitsBackMessagesAndVulnerability(agent_mock,
                                                                                              agent_persist_mock,
                                                                                              mocker):
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service, and of type vulnerability.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_domain', return_value=(JSON_OUTPUT, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.link', data={'url': 'https://test.ostorlab.co',
                                                                    'method': 'GET'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert len(agent_mock) == 2
        assert agent_mock[0].selector == 'v3.asset.ip.v4.port.service'
        assert agent_mock[1].selector == 'v3.report.vulnerability'
        assert agent_mock[1].data['risk_rating'] == 'INFO'
        assert agent_mock[1].data['title'] == 'Network Port Scan'
        assert agent_mock[1].data['short_description'] == 'List of open network ports.'
