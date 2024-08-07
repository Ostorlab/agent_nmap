"""Unittests for Nmap agent."""

import json
from typing import List, Dict, Union
import subprocess

import requests_mock as rq_mock
from ostorlab.agent.message import message
from ostorlab.utils import defintions as utils_definitions
from pytest_mock import plugin

from agent import nmap_agent
from agent import nmap_options
import pytest

JSON_OUTPUT = {
    "nmaprun": {
        "host": {
            "address": {"@addr": "127.0.0.1", "@addrtype": "ipv4"},
            "ports": {
                "port": {
                    "@portid": "21",
                    "@protocol": "tcp",
                    "state": {"@state": "open"},
                    "service": {"@name": "ssh"},
                }
            },
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

IPV6_JSON_OUTPUT = {
    "nmaprun": {
        "host": {
            "address": {
                "@addr": "2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f",
                "@addrtype": "ipv6",
            },
            "ports": {
                "port": {
                    "@portid": "21",
                    "@protocol": "tcp",
                    "state": {"@state": "open"},
                    "service": {"@name": "ssh"},
                }
            },
        }
    }
}

IPV6_HUMAN_OUTPUT = """
# Nmap 7.92 scan initiated Mon Mar 28 15:05:11 2022 as: nmap -sV --script=banner -n "-p 0-65535" -T5 -oX /tmp/xmloutput -oN /tmp/normal 2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f                                                                 │ │
Warning: 2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f giving up on port because retransmission cap hit (2).                                                                                                                                                   │ │
Nmap scan report for 2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f (2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f)                                                                                                                                                                     │ │
Host is up (0.0061s latency).                                                                                                                                                                                                 │ │
Other addresses for 2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f (not scanned): 2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f                                                                                                                                                       │ │
Not shown: 65532 filtered tcp ports (no-response)                                                                                                                                                                             │ │
PORT     STATE  SERVICE  VERSION                                                                                                                                                                                              │ │
22/tcp   closed ssh                                                                                                                                                                                                           │ │
80/tcp   open   http     awselb/2.0
"""


def testAgentLifecycle_whenScanRunsWithoutErrors_emitsBackMessagesAndVulnerability(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service, and of type vulnerability.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(JSON_OUTPUT, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 3
    assert agent_mock[0].selector == "v3.asset.ip.v4.port.service"
    assert agent_mock[1].selector == "v3.report.vulnerability"
    assert agent_mock[1].data["risk_rating"] == "INFO"
    assert agent_mock[1].data["title"] == "Network Port Scan"
    assert agent_mock[1].data["short_description"] == "List of open network ports."
    vulne_location = agent_mock[1].data["vulnerability_location"]
    assert vulne_location["ipv4"]["host"] == "127.0.0.1"
    assert vulne_location["ipv4"]["version"] == 4
    assert vulne_location["metadata"][0]["value"] == "21"
    assert vulne_location["metadata"][0]["type"] == "PORT"


def testAgentLifecycle_whenScanRunsWithoutErrors_emitsBackVulnerabilityMsg(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type vulnerability.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(JSON_OUTPUT, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 3
    assert agent_mock[1].selector == "v3.report.vulnerability"
    assert agent_mock[1].data["risk_rating"] == "INFO"
    assert agent_mock[1].data["title"] == "Network Port Scan"
    assert agent_mock[1].data["short_description"] == "List of open network ports."


def testAgentLifecycle_whenLinkAssetAndScanRunsWithoutErrors_emitsBackMessagesAndVulnerability(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    link_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service, and of type vulnerability.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(JSON_OUTPUT, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(link_msg)

    assert len(agent_mock) == 5
    assert any(m.selector == "v3.asset.ip.v4.port.service" for m in agent_mock) is True

    assert any(m.selector == "v3.asset.domain_name.service" for m in agent_mock) is True
    assert any(m.data["name"] == "test.ostorlab.co" for m in agent_mock) is True
    assert any(m.data["port"] == 21 for m in agent_mock) is True
    assert any(m.data["schema"] == "ssh" for m in agent_mock) is True

    assert any(m.selector == "v3.report.vulnerability" for m in agent_mock) is True
    assert any(m.data.get("risk_rating") == "INFO" for m in agent_mock) is True
    assert any(m.data.get("title") == "Network Port Scan" for m in agent_mock) is True
    assert (
        any(
            m.data.get("short_description") == "List of open network ports."
            for m in agent_mock
        )
        is True
    )


def testAgentEmitBanner_whenScanRunsWithoutErrors_emitsMsgWithBanner(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 10
    # check string in banner
    assert "Dummy Banner 1" in agent_mock[0].data["banner"]
    assert "Dummy Banner 2" in agent_mock[1].data["banner"]

    # check banner is None for last port
    assert agent_mock[2].data.get("banner", None) is None
    vulne_location = agent_mock[3].data["vulnerability_location"]
    assert vulne_location["domain_name"]["name"] == "scanme.nmap.org"
    assert vulne_location["metadata"][0]["value"] == "80"
    assert vulne_location["metadata"][1]["type"] == "PORT"
    assert vulne_location["metadata"][1]["value"] == "9929"
    assert vulne_location["metadata"][2]["type"] == "PORT"
    assert vulne_location["metadata"][2]["value"] == "31337"


def testAgentEmitBannerScanDomain_whenScanRunsWithoutErrors_emitsMsgWithBanner(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert len(agent_mock) == 18
    # check string in banner
    assert any("Dummy Banner 1" in m.data.get("banner", "") for m in agent_mock) is True
    assert any("Dummy Banner 2" in m.data.get("banner", "") for m in agent_mock) is True


def testAgentScanDomain_whenScanRunsWithoutErrors_emitsDomainService(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type domain name service.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert len(agent_mock) == 18
    # check string in banner
    assert (
        any(
            m.selector == "v3.asset.domain_name.service"
            and m.data["port"] == 80
            and m.data["schema"] == "http"
            for m in agent_mock
        )
        is True
    )


def testAgentNmap_whenUrlsScriptsGivent_RunScan(
    nmap_test_agent_with_scripts_arg: nmap_agent.NmapAgent,
    requests_mock: rq_mock.mocker.Mocker,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/nmap-scripts/main/test1",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/nmap-scripts/main/test2",
        content=b"test2",
    )

    nmap_test_agent_with_scripts_arg.process(domain_msg)

    # check string in banner
    assert (
        any(
            m.selector == "v3.asset.domain_name.service"
            and m.data["port"] == 80
            and m.data["schema"] == "http"
            for m in agent_mock
        )
        is True
    )


def testAgentNmapOptions_whenUrlsScriptsGivent_RunScan(
    nmap_test_agent_with_scripts_arg: nmap_agent.NmapAgent,
    requests_mock: rq_mock.mocker.Mocker,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    requests_mock.get(
        "https://raw.githubusercontent.com/nmap-scripts/main/test1",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/nmap-scripts/main/test2",
        content=b"test2",
    )
    options = nmap_options.NmapOptions(
        dns_resolution=False,
        ports=nmap_test_agent_with_scripts_arg.args.get("ports"),
        timing_template=nmap_options.TimingTemplate[
            nmap_test_agent_with_scripts_arg.args["timing_template"]
        ],
        scripts=nmap_test_agent_with_scripts_arg.args["scripts"],
        version_detection=True,
    )

    assert all(
        a in options.command_options
        for a in ["-sV", "-n", "-p", "0-65535", "-T3", "-sS", "-Pn", "--script"]
    )


def testAgentNmapOptions_whenUrlsScriptsGivent_RunScan2(
    nmap_test_agent_with_scripts_arg: nmap_agent.NmapAgent,
    requests_mock: rq_mock.mocker.Mocker,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
    fake_output_range: None | Dict[str, str],
) -> None:
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output_range, HUMAN_OUTPUT),
    )

    requests_mock.get(
        "https://raw.githubusercontent.com/nmap-scripts/main/test1",
        content=b"test1",
    )
    requests_mock.get(
        "https://raw.githubusercontent.com/nmap-scripts/main/test2",
        content=b"test2",
    )
    options = nmap_options.NmapOptions(
        dns_resolution=False,
        ports=nmap_test_agent_with_scripts_arg.args.get("ports"),
        timing_template=nmap_options.TimingTemplate[
            nmap_test_agent_with_scripts_arg.args["timing_template"]
        ],
        scripts=nmap_test_agent_with_scripts_arg.args["scripts"],
        version_detection=True,
    )

    assert all(
        a in options.command_options
        for a in ["-sV", "-n", "-p", "0-65535", "-T3", "-sS", "-Pn", "--script"]
    )


def testEmitFingerprints_whenScanFindsBanner_emitsFingerprint(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    """Test when nmap banner agent reports service, fingerprint is sent."""
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert "v3.fingerprint.ip.v4.service.library" in [m.selector for m in agent_mock]
    assert {
        "host": "45.33.32.156",
        "mask": "32",
        "version": 4,
        "service": "nping-echo",
        "port": 9929,
        "protocol": "tcp",
        "library_type": "BACKEND_COMPONENT",
        "library_name": "Dummy Banner 2",
        "detail": "Dummy Banner 2",
    } in [m.data for m in agent_mock]


def testAgentNmapOptions_withMaxNetworkMask_scansEachSubnet(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg2: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.settings.args = [
        utils_definitions.Arg(
            name="max_network_mask_ipv4",
            type="number",
            value=json.dumps("32").encode(),
        )
    ]

    nmap_test_agent.process(ipv4_msg2)

    # 4 is count of IPs in a /30.
    assert len(agent_mock) == 10 * 4
    # check string in banner
    assert "Dummy Banner 1" in agent_mock[0].data["banner"]
    assert "Dummy Banner 2" in agent_mock[1].data["banner"]

    # check banner is None for last port
    assert agent_mock[2].data.get("banner", None) is None


def testAgentProcessMessage_whenASubnetIsTargetdAfterABiggerRangeIsPreviouslyScanned_subnetIsNotScanned(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg_with_mask: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """The agent must not scan subnets if a larger network has been scanned before."""
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(JSON_OUTPUT, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv4_msg_with_mask)
    # first scan must pass.
    assert len(agent_mock) == 12

    # subnet /27 of /24.
    msg = message.Message.from_data(
        selector="v3.asset.ip.v4",
        data={"version": 4, "host": "10.10.10.0", "mask": "27"},
    )

    nmap_test_agent.process(msg)

    # scan subnet must not send any extra messages.
    assert len(agent_mock) == 12


def testAgentEmitBannerScanDomain_withMultiplehostnames_reportVulnerabilities(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    """Unittest for testing the reporting of vulnerabilities in case multiple hostnames from scan result."""
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert (
        len([msg for msg in agent_mock if msg.selector == "v3.report.vulnerability"])
        == 2
    )


def testNmapAgent_withDomainScopeArgAndLinkMessageNotInScope_targetShouldNotBeScanned(
    agent_mock: List[message.Message],
    nmap_agent_with_scope_arg: nmap_agent.NmapAgent,
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
    fake_output: None | Dict[str, str],
) -> None:
    """Ensure the domain scope argument is enforced, and urls in the scope should be scanned."""
    del agent_persist_mock
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )
    msg = message.Message.from_data(
        selector="v3.asset.link",
        data={"url": "https://www.google.com", "method": "GET"},
    )

    nmap_agent_with_scope_arg.process(msg)

    assert len(agent_mock) == 0


def testAgentNmapOptions_whenServiceHasProduct_reportsFingerprint(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_product: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output_product, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    # 4 is count of IPs in a /30.
    assert len(agent_mock) == 9
    assert (
        any(
            m.selector == "v3.fingerprint.domain_name.service.library"
            for m in agent_mock
        )
        is True
    )
    assert (
        all(
            m.data.get("schema") is not None and m.data.get("schema") != ""
            for m in agent_mock
            if m.selector == "v3.fingerprint.domain_name.service.library"
        )
        is True
    )
    assert any("F5 BIG" in m.data.get("library_name", "") for m in agent_mock) is True


def testNmapAgent_whenHostIsNotUp_shouldNotRaisAnError(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_with_down_host: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_output_with_down_host, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 0


def testNmapAgent_whenDomainIsNotUp_shouldNotRaisAnError(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    domain_is_down_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_with_down_host: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output_with_down_host, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_is_down_msg)

    assert len(agent_mock) == 0


def testAgentLifecycle_whenScanRunsWithVpn_shouldConnectToVPN(
    nmap_agent_with_vpn_config_arg: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for the full life cycle of the agent: case where the  nmap scan runs without errors,
    the agent scans with the vpn, the agent emits back messages of type service, and of type vulnerability.
    """
    exec_cmd_mock = mocker.patch("agent.nmap_agent.NmapAgent._exec_command")
    mocker.patch("builtins.open")
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(JSON_OUTPUT, HUMAN_OUTPUT),
    )

    nmap_agent_with_vpn_config_arg.start()

    assert " ".join(exec_cmd_mock.call_args_list[0][0][0]) == "wg-quick up wg0"


def testAgentNmap_whenNoHost_agentShouldNotCrash(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    junk_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for making sure that the agent not crashing when no host provided."""

    parse_mock = mocker.patch("urllib.parse.urlparse")

    nmap_test_agent.process(junk_msg)

    assert parse_mock.call_count == 0


def testNmapAgentLifecycle_whenIpv6WithHostBits_agentShouldNotCrash(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv6_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test of nmap agent when ipv6 with host bits is provided, the agent should not crash."""
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(IPV6_JSON_OUTPUT, IPV6_HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv6_msg)

    assert len(agent_mock) == 3
    assert agent_mock[0].selector == "v3.asset.ip.v6.port.service"
    assert agent_mock[1].selector == "v3.report.vulnerability"
    assert agent_mock[1].data["risk_rating"] == "INFO"
    assert agent_mock[1].data["title"] == "Network Port Scan"
    assert (
        "2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f"
        in agent_mock[1].data["technical_detail"]
    )


def testNmapAgent_whenIpv6WithoutMask_agentShouldNotGetStuck(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv6_msg_without_mask: message.Message,
) -> None:
    """Unit test of nmap agent when ipv6 without mask is provided, the agent should not get stuck."""
    nmap_test_agent.process(ipv6_msg_without_mask)

    assert len(agent_mock) == 0


def testNmapAgent_whenIpv6AboveLimit_agentShouldRaiseError(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv6_msg_above_limit: message.Message,
) -> None:
    """Unit test of nmap agent when ipv6 above limit is provided, the agent should raise an error."""
    with pytest.raises(ValueError) as error_message:
        nmap_test_agent.process(ipv6_msg_above_limit)

    assert len(agent_mock) == 0
    assert error_message.value.args[0] == "Subnet mask below 112 is not supported"


def testAgentNmap_whenInvalidDomainName_doesNotCrash(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    invalid_domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for testing agent handling of an invalid domain name."""
    mocker.patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(255, ""),
    )

    nmap_test_agent.process(invalid_domain_msg)

    assert len(agent_mock) == 0


def testAgent_whenServiceWithProductAndVersion_fingerprintMessageShouldHaveLibraryNameAndVersion(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agents emits the detected library name with its version."""
    del agent_persist_mock
    product_fake_output = {
        "nmaprun": {
            "host": {
                "address": {"@addr": "127.0.0.1", "@addrtype": "ipv4"},
                "ports": {
                    "port": {
                        "@portid": "22",
                        "@protocol": "tcp",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "0",
                        },
                        "service": {
                            "@name": "ssh",
                            "@product": "OpenSSH",
                            "@version": "7.4",
                            "cpe": "cpe:/a:openbsd:openssh:7.4",
                        },
                    }
                },
            }
        }
    }

    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(product_fake_output, ""),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 3
    assert agent_mock[0].selector == "v3.asset.ip.v4.port.service"
    assert agent_mock[1].selector == "v3.report.vulnerability"
    fingerprint_msg = agent_mock[2]
    assert fingerprint_msg.selector == "v3.fingerprint.ip.v4.service.library"
    assert fingerprint_msg.data["host"] == "127.0.0.1"
    assert fingerprint_msg.data["mask"] == "32"
    assert fingerprint_msg.data["service"] == "ssh"
    assert fingerprint_msg.data["port"] == 22
    assert fingerprint_msg.data["library_name"] == "OpenSSH"
    assert fingerprint_msg.data["library_version"] == "7.4"
