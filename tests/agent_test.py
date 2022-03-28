"""Unittests for Nmap agent."""
import pathlib

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent import message
from ostorlab.runtimes import definitions as runtime_definitions

from agent import nmap_agent

OSTORLAB_YAML_PATH = (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').absolute()

@pytest.mark.skip(reason='This will be part of the v2 nmap agent.')
def testAgentLifeCyle_whenScanRunsWithoutErrors_emitsBackMessagesAndVulnerability(agent_mock, mocker):
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service, and of type vulnerability.
    """
    scan_output = {
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
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=scan_output)

    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1'})

    out_selectors = ['v3.report.vulnerability', 'v3.asset.ip.v4.port.service']
    definition = agent_definitions.AgentDefinition(name='nmap_agent', out_selectors=out_selectors)
    settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap')
    test_agent = nmap_agent.NmapAgent(definition, settings)

    test_agent.process(msg)

    assert len(agent_mock) == 2
    assert agent_mock[0].selector == 'v3.asset.ip.v4.port.service'
    assert agent_mock[1].selector == 'v3.report.vulnerability'
    assert agent_mock[1].data['risk_rating'] == 'INFO'
    assert agent_mock[1].data['title'] == 'Network Port Scan'
    assert agent_mock[1].data['short_description'] == 'List of open network ports.'


def testAgentLifeCyle_whenScanRunsWithoutErrors_emitsBackVulnerabilityMsg(agent_mock, mocker):
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type vulnerability.
    """
    scan_output = {
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

    human_output = """
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

    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(scan_output, human_output))

    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert len(agent_mock) == 1
        assert agent_mock[0].selector == 'v3.report.vulnerability'
        assert agent_mock[0].data['risk_rating'] == 'INFO'
        assert agent_mock[0].data['title'] == 'Network Port Scan'
        assert agent_mock[0].data['short_description'] == 'List of open network ports.'
