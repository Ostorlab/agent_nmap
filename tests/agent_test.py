"""Unittests for agent."""

from ostorlab.agent import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import nmap_agent


def testAgent(agent_mock, mocker):
    """Fake test."""
    scan_output = {
        'nmaprun':{
            'host':{
                'address':{'@addr': '127.0.0.1', '@addrtype': 'ipv4'},
                'ports':{
                    'port':{
                        '@portid': '21',
                        '@protocol': 'tcp',
                        'state': {
                            '@state': 'open'
	  	                },
                        'service':{
                            '@name': 'ssh'
                        }
                    }
                }
            }
        }
    }
    mocker.patch('agent.nmap.NmapWrapper.scan', return_value=scan_output)

    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1'})

    out_selectors=['v3.report.vulnerability', 'v3.asset.ip.v4.port.service']
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
    