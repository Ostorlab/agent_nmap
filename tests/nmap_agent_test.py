"""Unittests for Nmap agent."""
import pathlib
import json

from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.utils import defintions as utils_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import nmap_agent
from agent import nmap_options

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


def testAgentLifecycle_whenScanRunsWithoutErrors_emitsBackMessagesAndVulnerability(agent_mock, agent_persist_mock,
                                                                                   mocker):
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


def testAgentLifecycle_whenScanRunsWithoutErrors_emitsBackVulnerabilityMsg(agent_mock, agent_persist_mock, mocker):
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


def testAgentLifecycle_whenLinkAssetAndScanRunsWithoutErrors_emitsBackMessagesAndVulnerability(agent_mock,
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

        assert len(agent_mock) == 3
        assert agent_mock[0].selector == 'v3.asset.ip.v4.port.service'

        assert agent_mock[1].selector == 'v3.asset.domain_name.service'
        assert agent_mock[1].data['name'] == 'test.ostorlab.co'
        assert agent_mock[1].data['port'] == 21
        assert agent_mock[1].data['schema'] == 'ssh'

        assert agent_mock[2].selector == 'v3.report.vulnerability'
        assert agent_mock[2].data['risk_rating'] == 'INFO'
        assert agent_mock[2].data['title'] == 'Network Port Scan'
        assert agent_mock[2].data['short_description'] == 'List of open network ports.'


def testAgentEmitBanner_whenScanRunsWithoutErrors_emitsMsgWithBanner(agent_mock, agent_persist_mock,
                                                                     mocker, fake_output):
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(fake_output, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert len(agent_mock) == 6
        # check string in banner
        assert 'Dummy Banner 1' in agent_mock[0].data['banner']
        assert 'Dummy Banner 2' in agent_mock[1].data['banner']

        # check banner is None for last port
        assert agent_mock[2].data.get('banner', None) is None


def testAgentEmitBannerScanDomain_whenScanRunsWithoutErrors_emitsMsgWithBanner(agent_mock, agent_persist_mock,
                                                                               mocker, fake_output):
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_domain', return_value=(fake_output, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'ostorlab.co'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert len(agent_mock) == 9
        # check string in banner
        assert 'Dummy Banner 1' in agent_mock[0].data['banner']
        assert 'Dummy Banner 2' in agent_mock[2].data['banner']


def testAgentScanDomain_whenScanRunsWithoutErrors_emitsDomainService(agent_mock, agent_persist_mock,
                                                                     mocker, fake_output):
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type domain name service.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_domain', return_value=(fake_output, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'ostorlab.co'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert len(agent_mock) == 9
        # check string in banner
        assert agent_mock[1].selector == 'v3.asset.domain_name.service'
        assert agent_mock[1].data.get('name') == agent_mock[1].data.get('name')
        assert agent_mock[1].data['port'] == 80
        assert agent_mock[1].data['schema'] == 'http'


def testAgentNmap_whenUrlsScriptsGivent_RunScan(requests_mock, agent_mock, agent_persist_mock, mocker, fake_output):
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_domain', return_value=(fake_output, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'ostorlab.co'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis', args=[
            utils_definitions.Arg(
                name='scripts',
                type='array',
                value=json.dumps(['https://raw.githubusercontent.com/nmap-scripts/main/test1',
                                  'https://raw.githubusercontent.com/nmap-scripts/main/test2']).encode())]
                                                     )
        test_agent = nmap_agent.NmapAgent(definition, settings)
        requests_mock.get('https://raw.githubusercontent.com/nmap-scripts/main/test1', content=b'test1')
        requests_mock.get('https://raw.githubusercontent.com/nmap-scripts/main/test2', content=b'test2')
        test_agent.process(msg)
    # check string in banner
    assert agent_mock[1].selector == 'v3.asset.domain_name.service'
    assert agent_mock[1].data.get('name') == agent_mock[1].data.get('name')
    assert agent_mock[1].data['port'] == 80
    assert agent_mock[1].data['schema'] == 'http'


def testAgentNmapOptions_whenUrlsScriptsGivent_RunScan(requests_mock, agent_mock, agent_persist_mock, mocker,
                                                       fake_output):
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_domain', return_value=(fake_output, HUMAN_OUTPUT))
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis', args=[
            utils_definitions.Arg(
                name='scripts',
                type='array',
                value=json.dumps(['https://raw.githubusercontent.com/nmap-scripts/main/test1',
                                  'https://raw.githubusercontent.com/nmap-scripts/main/test2']).encode())]
                                                     )
        test_agent = nmap_agent.NmapAgent(definition, settings)
        requests_mock.get('https://raw.githubusercontent.com/nmap-scripts/main/test1', content=b'test1')
        requests_mock.get('https://raw.githubusercontent.com/nmap-scripts/main/test2', content=b'test2')
        options = nmap_options.NmapOptions(dns_resolution=False,
                                           ports=test_agent.args.get('ports'),
                                           timing_template=nmap_options.TimingTemplate[
                                               test_agent.args.get('timing_template')],
                                           scripts=test_agent.args.get('scripts'),
                                           version_detection=True)
        # check string in banner
        assert options.command_options == ['-sV', '--script=banner', '-n', '-p', '0-65535', '-T4', '--script',
                                           '/tmp/scripts']


def testAgentNmapOptions_whenUrlsScriptsGivent_RunScan2(requests_mock, agent_mock, agent_persist_mock, mocker,
                                                        fake_output_range):
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_domain', return_value=(fake_output_range, HUMAN_OUTPUT))
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis', args=[
            utils_definitions.Arg(
                name='scripts',
                type='array',
                value=json.dumps(['https://raw.githubusercontent.com/nmap-scripts/main/test1',
                                  'https://raw.githubusercontent.com/nmap-scripts/main/test2']).encode())]
                                                     )
        test_agent = nmap_agent.NmapAgent(definition, settings)
        requests_mock.get('https://raw.githubusercontent.com/nmap-scripts/main/test1', content=b'test1')
        requests_mock.get('https://raw.githubusercontent.com/nmap-scripts/main/test2', content=b'test2')
        options = nmap_options.NmapOptions(dns_resolution=False,
                                           ports=test_agent.args.get('ports'),
                                           timing_template=nmap_options.TimingTemplate[
                                               test_agent.args.get('timing_template')],
                                           scripts=test_agent.args.get('scripts'),
                                           version_detection=True)
        # check string in banner
        assert options.command_options == ['-sV', '--script=banner', '-n', '-p', '0-65535', '-T4', '--script',
                                           '/tmp/scripts']


def testEmitFingerprints_whenScanFindsBanner_emitsFingerprint(agent_mock, agent_persist_mock,
                                                              mocker, fake_output):
    """Test when nmap banner agent reports service, fingerprint is sent.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_domain', return_value=(fake_output, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'ostorlab.co'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert 'v3.fingerprint.ip.v4.service.library' in [m.selector for m in agent_mock]
        assert {'host': '45.33.32.156', 'mask': '32', 'version': 4, 'service': 'nping-echo', 'port': 9929,
                'protocol': 'tcp', 'library_type': 'BACKEND_COMPONENT', 'library_name': 'Dummy Banner 2',
                'detail': 'Dummy Banner 2'} in [m.data for m in agent_mock]
