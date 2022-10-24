"""Unittests for Nmap agent."""
import json
import pathlib
from typing import List, Dict, Union

import requests_mock as rq_mock
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions
from pytest_mock import plugin

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


def testAgentLifecycle_whenScanRunsWithoutErrors_emitsBackMessagesAndVulnerability(agent_mock: List[message.Message],
                                                                                   agent_persist_mock:
                                                                                   Dict[Union[str, bytes],
                                                                                        Union[str, bytes]],
                                                                                   mocker: plugin.MockerFixture
                                                                                   ) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service, and of type vulnerability.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(JSON_OUTPUT, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1', 'mask': '32'})
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
        vulne_location = agent_mock[1].data['vulnerability_location']
        assert vulne_location['ipv4']['host'] == '127.0.0.1'
        assert vulne_location['ipv4']['version'] == 4
        assert vulne_location['metadata'][0]['value'] == '21'
        assert vulne_location['metadata'][0]['type'] == 'PORT'



def testAgentLifecycle_whenScanRunsWithoutErrors_emitsBackVulnerabilityMsg(agent_mock: List[message.Message],
                                                                           agent_persist_mock: Dict[Union[str, bytes],
                                                                                                    Union[str, bytes]],
                                                                           mocker: plugin.MockerFixture) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type vulnerability.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(JSON_OUTPUT, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1', 'mask': '32'})
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


def testAgentLifecycle_whenLinkAssetAndScanRunsWithoutErrors_emitsBackMessagesAndVulnerability(
        agent_mock: List[message.Message],
        agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
        mocker: plugin.MockerFixture) -> None:
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


def testAgentEmitBanner_whenScanRunsWithoutErrors_emitsMsgWithBanner(
        agent_mock: List[message.Message],
        agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
        mocker: plugin.MockerFixture, fake_output: None | Dict[str, str]) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(fake_output, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '127.0.0.1', 'mask': '32'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        assert len(agent_mock) == 7
        # check string in banner
        assert 'Dummy Banner 1' in agent_mock[0].data['banner']
        assert 'Dummy Banner 2' in agent_mock[1].data['banner']

        # check banner is None for last port
        assert agent_mock[2].data.get('banner', None) is None
        vulne_location = agent_mock[3].data['vulnerability_location']
        assert vulne_location['domain_name']['name'] == 'scanme.nmap.org'
        assert vulne_location['metadata'][0]['value'] == '80'
        assert vulne_location['metadata'][1]['type'] == 'PORT'
        assert vulne_location['metadata'][1]['value'] == '9929'
        assert vulne_location['metadata'][2]['type'] == 'PORT'
        assert vulne_location['metadata'][2]['value'] == '31337'


def testAgentEmitBannerScanDomain_whenScanRunsWithoutErrors_emitsMsgWithBanner(
        agent_mock: List[message.Message], agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
        mocker: plugin.MockerFixture, fake_output: None | Dict[str, str]) -> None:
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

        assert len(agent_mock) == 10
        # check string in banner
        assert 'Dummy Banner 1' in agent_mock[0].data['banner']
        assert 'Dummy Banner 2' in agent_mock[2].data['banner']


def testAgentScanDomain_whenScanRunsWithoutErrors_emitsDomainService(
        agent_mock: List[message.Message],
        agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
        mocker: plugin.MockerFixture,
        fake_output: None | Dict[str, str]) -> None:
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

        assert len(agent_mock) == 10
        # check string in banner
        assert agent_mock[1].selector == 'v3.asset.domain_name.service'
        assert agent_mock[1].data.get('name') == agent_mock[1].data.get('name')
        assert agent_mock[1].data['port'] == 80
        assert agent_mock[1].data['schema'] == 'http'


def testAgentNmap_whenUrlsScriptsGivent_RunScan(requests_mock: rq_mock.mocker.Mocker,
                                                agent_mock: List[message.Message],
                                                agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
                                                mocker: plugin.MockerFixture,
                                                fake_output: None | Dict[str, str]) -> None:
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


def testAgentNmapOptions_whenUrlsScriptsGivent_RunScan(requests_mock: rq_mock.mocker.Mocker,
                                                       agent_mock: List[message.Message],
                                                       agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
                                                       mocker: plugin.MockerFixture,
                                                       fake_output: None | Dict[str, str]) -> None:
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
                                               test_agent.args['timing_template']],
                                           scripts=test_agent.args['scripts'],
                                           version_detection=True)
        assert all(a in options.command_options for a in
                   ['-sV', '-n', '-p', '0-65535', '-T5', '-sT', '-Pn', '--script'])


def testAgentNmapOptions_whenUrlsScriptsGivent_RunScan2(requests_mock: rq_mock.mocker.Mocker,
                                                        agent_mock: List[message.Message],
                                                        agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
                                                        mocker: plugin.MockerFixture,
                                                        fake_output_range: None | Dict[str, str]) -> None:
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
                                               test_agent.args['timing_template']],
                                           scripts=test_agent.args['scripts'],
                                           version_detection=True)
        assert all(a in options.command_options for a in
                   ['-sV', '-n', '-p', '0-65535', '-T5', '-sT', '-Pn', '--script'])


def testEmitFingerprints_whenScanFindsBanner_emitsFingerprint(
        agent_mock: List[message.Message],
        agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
        mocker: plugin.MockerFixture, fake_output: None | Dict[str, str]) -> None:
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


def testAgentNmapOptions_withMaxNetworkMask_scansEachSubnet(
        agent_mock: List[message.Message],
        agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
        mocker: plugin.MockerFixture, fake_output: None | Dict[str, str]) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(fake_output, HUMAN_OUTPUT))
    msg = message.Message.from_data(selector='v3.asset.ip.v4', data={'version': 4, 'host': '192.168.0.0', 'mask': '30'})
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis',
                                                     args=[
                                                         utils_definitions.Arg(
                                                             name='max_network_mask_ipv4',
                                                             type='int',
                                                             value=json.dumps('32').encode())]
                                                     )
        test_agent = nmap_agent.NmapAgent(definition, settings)

        test_agent.process(msg)

        # 4 is count of IPs in a /30.
        assert len(agent_mock) == 7 * 4
        # check string in banner
        assert 'Dummy Banner 1' in agent_mock[0].data['banner']
        assert 'Dummy Banner 2' in agent_mock[1].data['banner']

        # check banner is None for last port
        assert agent_mock[2].data.get('banner', None) is None


def testAgentProcessMessage_whenASubnetIsTargetdAfterABiggerRangeIsPreviouslyScanned_subnetIsNotScanned(
        agent_mock: List[message.Message],
        agent_persist_mock:
        Dict[Union[str, bytes],
             Union[str, bytes]],
        mocker: plugin.MockerFixture
) -> None:
    """The agent must not scan subnets if a larger network has been scanned before.
    """
    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(JSON_OUTPUT, HUMAN_OUTPUT))

    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)

        msg = message.Message.from_data(selector='v3.asset.ip.v4',
                                        data={'version': 4, 'host': '10.10.10.0', 'mask': '24'})
        test_agent.process(msg)
        # first scan must pass.
        assert len(agent_mock) == 8

        # subnet /27 of /24.
        msg = message.Message.from_data(selector='v3.asset.ip.v4',
                                        data={'version': 4, 'host': '10.10.10.0', 'mask': '27'})
        test_agent.process(msg)
        # scan subnet must not send any extra messages.
        assert len(agent_mock) == 8


def testAgentNmapOptions_whenIpAddressGiven_scansWithUDP(
        agent_mock: List[message.Message],
        mocker: plugin.MockerFixture, fake_output: None | Dict[str, str]) -> None:

    mocker.patch('agent.nmap_wrapper.NmapWrapper.scan_hosts', return_value=(fake_output, HUMAN_OUTPUT))
    with open(OSTORLAB_YAML_PATH, 'r', encoding='utf-8') as o:
        definition = agent_definitions.AgentDefinition.from_yaml(o)
        settings = runtime_definitions.AgentSettings(key='agent/ostorlab/nmap', redis_url='redis://redis')
        test_agent = nmap_agent.NmapAgent(definition, settings)
        options = nmap_options.NmapOptions(dns_resolution=False,
                                           ports=test_agent.args.get('ports'),
                                           timing_template=nmap_options.TimingTemplate[
                                               test_agent.args['timing_template']],
                                           scripts=test_agent.args['scripts'],
                                           version_detection=True)
        assert all(a in options.command_options for a in
                   ['-sV', '-n', '-p', '0-65535', '-T5', '-sT', '-sU', '-Pn', '--script', 'banner'])

