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

SCAN_RESULT_NO_PRODUCT = {
    "nmaprun": {
        "@scanner": "nmap",
        "@args": "nmap -sV -n -p 0-6111515135 -T3 -sS --script banner -sC -oX /tmp/xm -oN /tmp/normal photo-rw.som.cm",
        "@start": "11423487",
        "@startstr": "Sun Aug 32 24:56:27 2424",
        "@version": "5.50",
        "@xmloutputversion": "1.01",
        "scaninfo": {
            "@type": "syn",
            "@protocol": "tcp",
            "@numservices": "3223",
            "@services": "0-62341",
        },
        "verbose": {"@level": "0"},
        "debugging": {"@level": "0"},
        "host": {
            "@starttime": "1724553457",
            "@endtime": "17243453456",
            "status": {"@state": "up", "@reason": "syn-ack", "@reason_ttl": "19"},
            "address": {"@addr": "184.11.11.13", "@addrtype": "ipv4"},
            "hostnames": {"hostname": {"@name": "video-cf.twimg.com", "@type": "user"}},
            "ports": {
                "extraports": {
                    "@state": "filtered",
                    "@count": "62343",
                    "extrareasons": {"@reason": "no-responses", "@count": "62343"},
                },
                "port": [
                    {
                        "@protocol": "tcp",
                        "@portid": "80",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "52",
                        },
                        "service": {
                            "@name": "http",
                            "@servicefp": 'SF-Port80-TCPdy>\\r\\n</html>\\r\\nRequest\\r\\nServer:\\x20cloudflare\\r\\nDate:\\x20Sun,\\x2025\\x20Aug\\x202024\\x2014:58:18\\x20GMT\\r\\nContent-Type:\\x20text/html\\r\\nContent-Length:\\x20")%dm\x20r>\\r\\n</body>\\r\\n</html>\\r\\n");',
                            "@method": "probed",
                            "@conf": "12",
                        },
                    }
                ],
            },
        },
    }
}

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

    assert len(agent_mock) == 2
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

    assert len(agent_mock) == 2
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

    assert len(agent_mock) == 3
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

    assert len(agent_mock) == 7
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

    assert len(agent_mock) == 12
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

    assert len(agent_mock) == 12
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
    assert len(agent_mock) == 7 * 4
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
    assert len(agent_mock) == 8

    # subnet /27 of /24.
    msg = message.Message.from_data(
        selector="v3.asset.ip.v4",
        data={"version": 4, "host": "10.10.10.0", "mask": "27"},
    )

    nmap_test_agent.process(msg)

    # scan subnet must not send any extra messages.
    assert len(agent_mock) == 8


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
    assert (
        any(
            m.data.get("detail") == "Nmap Detected http-proxy on ostorlab.co"
            for m in agent_mock
        )
        is True
    )
    assert (
        any(
            m.data.get("detail") == "Nmap Detected http on ostorlab.co"
            for m in agent_mock
        )
        is True
    )


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

    assert len(agent_mock) == 2
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


def testAgent_whenHostHaveOs_fingerprintMessageShouldHaveOs(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent fingerprint OS."""
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
                "os": {
                    "osmatch": [
                        {
                            "@name": "Microsoft Windows 10 1511",
                            "@accuracy": "88",
                            "@line": "69505",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Microsoft",
                                "@osfamily": "Windows",
                                "@osgen": "10",
                                "@accuracy": "88",
                                "cpe": "cpe:/o:microsoft:windows_10:1511",
                            },
                        }
                    ]
                },
            }
        }
    }

    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(product_fake_output, ""),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 4
    assert agent_mock[0].selector == "v3.asset.ip.v4.port.service"
    assert agent_mock[1].selector == "v3.report.vulnerability"
    fingerprint_msg = agent_mock[2]
    assert fingerprint_msg.selector == "v3.fingerprint.ip.v4.service.library"
    assert fingerprint_msg.data["host"] == "127.0.0.1"
    assert fingerprint_msg.data["library_name"] == "Windows"
    assert fingerprint_msg.data["library_version"] == "10"


def testAgent_whenOsClassIsList_fingerprintMessageShouldHaveOs(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent handel osclass when it's a list."""
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
                "os": {
                    "osmatch": [
                        [
                            {
                                "@name": "Microsoft Windows 10 1511",
                                "@accuracy": "88",
                                "@line": "69505",
                                "osclass": [
                                    {
                                        "@type": "specialized",
                                        "@vendor": "Microsoft",
                                        "@osfamily": "Windows",
                                        "@osgen": "10",
                                        "@accuracy": "88",
                                        "cpe": "cpe:/o:microsoft:windows_10:1511",
                                    }
                                ],
                            }
                        ]
                    ]
                },
            }
        }
    }

    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(product_fake_output, ""),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 4
    assert agent_mock[0].selector == "v3.asset.ip.v4.port.service"
    assert agent_mock[1].selector == "v3.report.vulnerability"
    fingerprint_msg = agent_mock[2]
    assert fingerprint_msg.selector == "v3.fingerprint.ip.v4.service.library"
    assert fingerprint_msg.data["host"] == "127.0.0.1"
    assert fingerprint_msg.data["library_name"] == "Windows"
    assert fingerprint_msg.data["library_version"] == "10"


def testAgent_whenOsMatchIsEmptyList_fingerprintMessageShouldHaveOs(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent handel osmatch when it's an empty list."""
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
                "os": {"osmatch": []},
            }
        }
    }

    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(product_fake_output, ""),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 2


def testAgent_whenOsMatchIsList_fingerprintMessageShouldHaveOs(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent handel osmatch when it's a list."""
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
                "os": {
                    "osmatch": [
                        [
                            {
                                "@name": "Microsoft Windows 10 1511",
                                "@accuracy": "88",
                                "@line": "69505",
                                "osclass": [],
                            }
                        ]
                    ]
                },
            }
        }
    }

    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(product_fake_output, ""),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) == 2


def testAgentNmap_withOSFingerprintCrash1_noException(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg2: message.Message,
    mocker: plugin.MockerFixture,
    fake_crash_1_output: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_crash_1_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.settings.args = [
        utils_definitions.Arg(
            name="max_network_mask_ipv4",
            type="number",
            value=json.dumps("32").encode(),
        )
    ]

    nmap_test_agent.process(ipv4_msg2)

    assert len(agent_mock) > 0


def testAgentNmap_withOSFingerprintCrash2_noException(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg2: message.Message,
    mocker: plugin.MockerFixture,
    fake_crash_2_output: None | Dict[str, str],
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_crash_2_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.settings.args = [
        utils_definitions.Arg(
            name="max_network_mask_ipv4",
            type="number",
            value=json.dumps("32").encode(),
        )
    ]

    nmap_test_agent.process(ipv4_msg2)

    assert len(agent_mock) > 0


def testAgentLifecycle_whenTCPWrappedService_emitsNoService(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Check `tcpwrapped` services are not emitted."""
    json_output = {
        "nmaprun": {
            "host": {
                "address": {"@addr": "127.0.0.1", "@addrtype": "ipv4"},
                "ports": {
                    "port": {
                        "@portid": "222",
                        "@protocol": "tcp",
                        "state": {"@state": "open"},
                        "service": {"@name": "tcpwrapped"},
                    }
                },
            }
        }
    }

    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(json_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv4_msg)

    assert len(agent_mock) > 0
    assert "tcpwrapped" not in [m.data.get("service") for m in agent_mock]


def testAgentLifecycle_whenDomainTCPWrappedService_emitsNoService(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: List[message.Message],
    domain_msg: message.Message,
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent handel osmatch when it's a list."""
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
                            "@name": "tcpwrapped",
                        },
                    }
                },
                "os": {
                    "osmatch": [
                        [
                            {
                                "@name": "Microsoft Windows 10 1511",
                                "@accuracy": "88",
                                "@line": "69505",
                                "osclass": [],
                            }
                        ]
                    ]
                },
            }
        }
    }

    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(product_fake_output, ""),
    )

    nmap_test_agent.process(domain_msg)

    assert len(agent_mock) == 0


def testAgentNmapOptions_whenServiceHasNoProduct_reportsFingerprintzzz(
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
        return_value=(SCAN_RESULT_NO_PRODUCT, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert any("fingerprint" in msg.selector for msg in agent_mock) is False

scan_results = {
    "nmaprun": {
        "@scanner": "nmap",
        "@args": "nmap -O -sV -n -p 0-65535 -T3 -sS --script banner -sC -oX /tmp/xmloutput -oN /tmp/normal 35.198.136.0/26",
        "@start": "1725329231",
        "@startstr": "Tue Sep  3 02:07:11 2024",
        "@version": "7.80",
        "@xmloutputversion": "1.04",
        "scaninfo": {
            "@type": "syn",
            "@protocol": "tcp",
            "@numservices": "65536",
            "@services": "0-65535",
        },
        "verbose": {"@level": "0"},
        "debugging": {"@level": "0"},
        "host": [
            {
                "@starttime": "1725329231",
                "@endtime": "1725329803",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "113",
                },
                "address": {"@addr": "35.198.136.1", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65536",
                        "extrareasons": {"@reason": "no-responses", "@count": "65536"},
                    }
                },
                "os": {
                    "portused": {
                        "@state": "closed",
                        "@proto": "udp",
                        "@portid": "39742",
                    },
                    "osmatch": [
                        {
                            "@name": "Brother HL-2070N printer",
                            "@accuracy": "100",
                            "@line": "10995",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Brother",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:brother:hl-2070n",
                            },
                        },
                        {
                            "@name": "Brother HL-5070N printer",
                            "@accuracy": "100",
                            "@line": "11284",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Brother",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:brother:hl-5070n",
                            },
                        },
                        {
                            "@name": "Brother MFC-7820N printer",
                            "@accuracy": "100",
                            "@line": "11652",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Brother",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:brother:mfc-7820n",
                            },
                        },
                        {
                            "@name": "Elk ELK-M1EXP Ethernet-to-serial bridge",
                            "@accuracy": "100",
                            "@line": "23982",
                            "osclass": {
                                "@type": "bridge",
                                "@vendor": "Elk",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:elk:elk-m1exp",
                            },
                        },
                        {
                            "@name": "Novatel MiFi 2200 3G WAP or iDirect Evolution X1 satellite router",
                            "@accuracy": "100",
                            "@line": "39944",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "iDirect",
                                    "@osfamily": "embedded",
                                    "@accuracy": "100",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Novatel",
                                    "@osfamily": "embedded",
                                    "@accuracy": "100",
                                    "cpe": "cpe:/h:novatel:mifi_2200_3g",
                                },
                            ],
                        },
                        {
                            "@name": "Tripp Lite SMART1500SLT UPS, or PDUMV30HVNET or PDUMH15AT power distribution unit",
                            "@accuracy": "100",
                            "@line": "102617",
                            "osclass": {
                                "@type": "power-device",
                                "@vendor": "Tripp Lite",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": [
                                    "cpe:/h:tripplite:smart1500slt",
                                    "cpe:/h:tripplite:pdumv30hvnet",
                                ],
                            },
                        },
                    ],
                },
                "distance": {"@value": "6"},
                "times": {"@srtt": "5477", "@rttvar": "4363", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725329826",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.2", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "3307",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "58",
                        },
                        "service": {
                            "@name": "opsession-prxy",
                            "@tunnel": "ssl",
                            "@method": "table",
                            "@conf": "3",
                        },
                    },
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "3307"},
                        {"@state": "closed", "@proto": "udp", "@portid": "33332"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "92",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "89",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "89",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "85",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "2979459",
                    "@lastboot": "Tue Jul 30 14:39:27 2024",
                },
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "256",
                    "@difficulty": "Good luck!",
                    "@values": "2C81AA74,F101F0C4,8EEE563D,E5B44E2E,9AC8D26,DBC6756C",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "B1969A26,B1969A85,B1969AE9,B1969B4D,B1969BB1,B1969C1B",
                },
                "times": {"@srtt": "10833", "@rttvar": "1373", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725329826",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "110",
                },
                "address": {"@addr": "35.198.136.5", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "3307",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "58",
                        },
                        "service": {
                            "@name": "opsession-prxy",
                            "@tunnel": "ssl",
                            "@method": "table",
                            "@conf": "3",
                        },
                    },
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "3307"},
                        {"@state": "closed", "@proto": "udp", "@portid": "39084"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "92",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "89",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "89",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "85",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "2005547",
                    "@lastboot": "Sat Aug 10 21:11:19 2024",
                },
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "256",
                    "@difficulty": "Good luck!",
                    "@values": "F6FF8F40,1783D9ED,5F330B7E,A8AE66F,3FD5C616,DFD1B9E6",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "7789E4BF,7789E51D,7789E581,7789E5E5,7789E649,7789E6B3",
                },
                "times": {"@srtt": "9483", "@rttvar": "2884", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725329826",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "109",
                },
                "address": {"@addr": "35.198.136.8", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "443",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "57",
                        },
                        "service": {
                            "@name": "https",
                            "@servicefp": 'SF-Port443-TCP:V=7.80%T=SSL%I=7%D=9/3%Time=66D67134%P=x86_64-pc-linux-gnu%r(GetRequest,22F,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x205930233e-3882-47e7-80c1-716b229e90cf\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x20b2ff1591-feb0-4a92-943f-dbedef2bc00a\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x2031796055-503d-4a41-bce2-c96932635c01\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:15:16\\x20GMT\\r\\nContent-Length:\\x20185\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20get\\x20path\\x20\\\\\\"/\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n")%r(HTTPOptions,233,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x20250219f6-411e-40dd-a0bb-234057196095\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x20b2ff1591-feb0-4a92-943f-dbedef2bc00a\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x2031796055-503d-4a41-bce2-c96932635c01\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:15:16\\x20GMT\\r\\nContent-Length:\\x20189\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20options\\x20path\\x20\\\\\\"/\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n")%r(FourOhFourRequest,24A,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x20fcf3d895-786f-4d47-bcdd-05f4c3825b49\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x20b2ff1591-feb0-4a92-943f-dbedef2bc00a\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x2031796055-503d-4a41-bce2-c96932635c01\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:15:16\\x20GMT\\r\\nContent-Length:\\x20212\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20get\\x20path\\x20\\\\\\"/nice\\x20ports,/Trinity\\.txt\\.bak\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n");',
                            "@tunnel": "ssl",
                            "@method": "probed",
                            "@conf": "10",
                        },
                        "script": {
                            "@id": "fingerprint-strings",
                            "@output": '\n  FourOhFourRequest: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: fcf3d895-786f-4d47-bcdd-05f4c3825b49\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: b2ff1591-feb0-4a92-943f-dbedef2bc00a\n    X-Kubernetes-Pf-Prioritylevel-Uid: 31796055-503d-4a41-bce2-c96932635c01\n    Date: Tue, 03 Sep 2024 02:15:16 GMT\n    Content-Length: 212\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}\n  GetRequest: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: 5930233e-3882-47e7-80c1-716b229e90cf\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: b2ff1591-feb0-4a92-943f-dbedef2bc00a\n    X-Kubernetes-Pf-Prioritylevel-Uid: 31796055-503d-4a41-bce2-c96932635c01\n    Date: Tue, 03 Sep 2024 02:15:16 GMT\n    Content-Length: 185\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}\n  HTTPOptions: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: 250219f6-411e-40dd-a0bb-234057196095\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: b2ff1591-feb0-4a92-943f-dbedef2bc00a\n    X-Kubernetes-Pf-Prioritylevel-Uid: 31796055-503d-4a41-bce2-c96932635c01\n    Date: Tue, 03 Sep 2024 02:15:16 GMT\n    Content-Length: 189\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}',
                            "elem": [
                                {
                                    "@key": "FourOhFourRequest",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: fcf3d895-786f-4d47-bcdd-05f4c3825b49\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: b2ff1591-feb0-4a92-943f-dbedef2bc00a\n    X-Kubernetes-Pf-Prioritylevel-Uid: 31796055-503d-4a41-bce2-c96932635c01\n    Date: Tue, 03 Sep 2024 02:15:16 GMT\n    Content-Length: 212\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}',
                                },
                                {
                                    "@key": "GetRequest",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: 5930233e-3882-47e7-80c1-716b229e90cf\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: b2ff1591-feb0-4a92-943f-dbedef2bc00a\n    X-Kubernetes-Pf-Prioritylevel-Uid: 31796055-503d-4a41-bce2-c96932635c01\n    Date: Tue, 03 Sep 2024 02:15:16 GMT\n    Content-Length: 185\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}',
                                },
                                {
                                    "@key": "HTTPOptions",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: 250219f6-411e-40dd-a0bb-234057196095\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: b2ff1591-feb0-4a92-943f-dbedef2bc00a\n    X-Kubernetes-Pf-Prioritylevel-Uid: 31796055-503d-4a41-bce2-c96932635c01\n    Date: Tue, 03 Sep 2024 02:15:16 GMT\n    Content-Length: 189\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}',
                                },
                            ],
                        },
                    },
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "443"},
                        {"@state": "closed", "@proto": "udp", "@portid": "31519"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "93",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "93",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "90",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "86",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "86",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                        {
                            "@name": "HP P2000 G3 NAS device",
                            "@accuracy": "85",
                            "@line": "34647",
                            "osclass": {
                                "@type": "storage-misc",
                                "@vendor": "HP",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:hp:p2000_g3",
                            },
                        },
                        {
                            "@name": "Crestron MPC-M5 AV controller or Wago Kontakttechnik 750-852 PLC",
                            "@accuracy": "85",
                            "@line": "19564",
                            "osclass": [
                                {
                                    "@type": "media device",
                                    "@vendor": "Crestron",
                                    "@osfamily": "embedded",
                                    "@accuracy": "85",
                                    "cpe": "cpe:/h:crestron:mpc-m5",
                                },
                                {
                                    "@type": "specialized",
                                    "@vendor": "Wago Kontakttechnik",
                                    "@osfamily": "embedded",
                                    "@accuracy": "85",
                                    "cpe": "cpe:/h:wago_kontakttechnik:750-852",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.16",
                            "@accuracy": "85",
                            "@line": "64070",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "85",
                                "cpe": "cpe:/o:linux:linux_kernel:3.16",
                            },
                        },
                        {
                            "@name": "ASUS RT-N56U WAP (Linux 3.4)",
                            "@accuracy": "85",
                            "@line": "8344",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "Asus",
                                    "@osfamily": "embedded",
                                    "@accuracy": "85",
                                    "cpe": "cpe:/h:asus:rt-n56u",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "85",
                                    "cpe": "cpe:/o:linux:linux_kernel:3.4",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.1",
                            "@accuracy": "85",
                            "@line": "62708",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "85",
                                "cpe": "cpe:/o:linux:linux_kernel:3.1",
                            },
                        },
                        {
                            "@name": "Linux 3.2",
                            "@accuracy": "85",
                            "@line": "64455",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "85",
                                "cpe": "cpe:/o:linux:linux_kernel:3.2",
                            },
                        },
                    ],
                },
                "uptime": {"@seconds": "22", "@lastboot": "Tue Sep  3 02:16:44 2024"},
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "264",
                    "@difficulty": "Good luck!",
                    "@values": "599DA8FC,3F95FEBC,C1AB3E1F,219A6412,70F09EB1,6B7B0637",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "other",
                    "@values": "8D3AD68B,B429F97,8D3AD74D,B5D4304,9A1BB84C,B5D43D2",
                },
                "times": {"@srtt": "9930", "@rttvar": "2142", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331811",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "113",
                },
                "address": {"@addr": "35.198.136.11", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "443",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "57",
                        },
                        "service": {
                            "@name": "https",
                            "@tunnel": "ssl",
                            "@method": "probed",
                            "@conf": "10",
                        },
                    },
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "443"},
                        {"@state": "closed", "@proto": "udp", "@portid": "43101"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "92",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "89",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "89",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "85",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                    ],
                },
                "uptime": {"@seconds": "25", "@lastboot": "Tue Sep  3 02:49:46 2024"},
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "257",
                    "@difficulty": "Good luck!",
                    "@values": "7FD83B27,541AAC22,8810B941,B6B06D3E,CD253A9A,2ECB37CB",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "other",
                    "@values": "36F2B946,BACDB1AA,36F2BA11,BACDB26F,BACDB2D3,36F2BB3F",
                },
                "times": {"@srtt": "10371", "@rttvar": "2475", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {"@state": "up", "@reason": "syn-ack", "@reason_ttl": "58"},
                "address": {"@addr": "35.198.136.16", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "443",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "58",
                        },
                        "service": {
                            "@name": "https",
                            "@servicefp": 'SF-Port443-TCP:V=7.80%T=SSL%I=7%D=9/3%Time=66D678F1%P=x86_64-pc-linux-gnu%r(GetRequest,22F,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x20dfbf23af-ac8a-49cb-84a6-19a6d32bfd37\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x2025fb76a0-f47d-4a90-839c-08decf43b217\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x206a46e4d2-1b32-4de4-9143-5d92e4815c0b\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:17\\x20GMT\\r\\nContent-Length:\\x20185\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20get\\x20path\\x20\\\\\\"/\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n")%r(HTTPOptions,233,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x2022b0af9d-a171-4875-bede-de8aa7412726\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x2025fb76a0-f47d-4a90-839c-08decf43b217\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x206a46e4d2-1b32-4de4-9143-5d92e4815c0b\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:17\\x20GMT\\r\\nContent-Length:\\x20189\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20options\\x20path\\x20\\\\\\"/\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n")%r(FourOhFourRequest,24A,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x204a8d6ee6-7bb2-4714-80b9-9d7b6b1ec63e\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x2025fb76a0-f47d-4a90-839c-08decf43b217\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x206a46e4d2-1b32-4de4-9143-5d92e4815c0b\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:17\\x20GMT\\r\\nContent-Length:\\x20212\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20get\\x20path\\x20\\\\\\"/nice\\x20ports,/Trinity\\.txt\\.bak\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n");',
                            "@tunnel": "ssl",
                            "@method": "probed",
                            "@conf": "10",
                        },
                        "script": {
                            "@id": "fingerprint-strings",
                            "@output": '\n  FourOhFourRequest: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: 4a8d6ee6-7bb2-4714-80b9-9d7b6b1ec63e\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 25fb76a0-f47d-4a90-839c-08decf43b217\n    X-Kubernetes-Pf-Prioritylevel-Uid: 6a46e4d2-1b32-4de4-9143-5d92e4815c0b\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 212\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}\n  GetRequest: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: dfbf23af-ac8a-49cb-84a6-19a6d32bfd37\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 25fb76a0-f47d-4a90-839c-08decf43b217\n    X-Kubernetes-Pf-Prioritylevel-Uid: 6a46e4d2-1b32-4de4-9143-5d92e4815c0b\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 185\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}\n  HTTPOptions: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: 22b0af9d-a171-4875-bede-de8aa7412726\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 25fb76a0-f47d-4a90-839c-08decf43b217\n    X-Kubernetes-Pf-Prioritylevel-Uid: 6a46e4d2-1b32-4de4-9143-5d92e4815c0b\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 189\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}',
                            "elem": [
                                {
                                    "@key": "FourOhFourRequest",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: 4a8d6ee6-7bb2-4714-80b9-9d7b6b1ec63e\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 25fb76a0-f47d-4a90-839c-08decf43b217\n    X-Kubernetes-Pf-Prioritylevel-Uid: 6a46e4d2-1b32-4de4-9143-5d92e4815c0b\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 212\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}',
                                },
                                {
                                    "@key": "GetRequest",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: dfbf23af-ac8a-49cb-84a6-19a6d32bfd37\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 25fb76a0-f47d-4a90-839c-08decf43b217\n    X-Kubernetes-Pf-Prioritylevel-Uid: 6a46e4d2-1b32-4de4-9143-5d92e4815c0b\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 185\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}',
                                },
                                {
                                    "@key": "HTTPOptions",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: 22b0af9d-a171-4875-bede-de8aa7412726\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 25fb76a0-f47d-4a90-839c-08decf43b217\n    X-Kubernetes-Pf-Prioritylevel-Uid: 6a46e4d2-1b32-4de4-9143-5d92e4815c0b\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 189\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}',
                                },
                            ],
                        },
                    },
                },
                "os": {
                    "portused": {"@state": "open", "@proto": "tcp", "@portid": "443"},
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "87",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "87",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "HP P2000 G3 NAS device",
                            "@accuracy": "85",
                            "@line": "34647",
                            "osclass": {
                                "@type": "storage-misc",
                                "@vendor": "HP",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:hp:p2000_g3",
                            },
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "45839",
                    "@lastboot": "Mon Sep  2 14:06:12 2024",
                },
                "tcpsequence": {
                    "@index": "259",
                    "@difficulty": "Good luck!",
                    "@values": "ACF6AF61,3C2EF4E5,76A7AF2C,2843870A,3CEBB00E,712DDAFE",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "2BB1446,2BB14AC,2BB1511,2BB157D,2BB15E2,2BB1640",
                },
                "times": {"@srtt": "6964", "@rttvar": "2743", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "113",
                },
                "address": {"@addr": "35.198.136.17", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "3307",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "59",
                        },
                        "service": {
                            "@name": "opsession-prxy",
                            "@tunnel": "ssl",
                            "@method": "table",
                            "@conf": "3",
                        },
                    },
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "3307"},
                        {"@state": "closed", "@proto": "udp", "@portid": "30707"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "92",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "89",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "89",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Linux 3.16",
                            "@accuracy": "85",
                            "@line": "64070",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "85",
                                "cpe": "cpe:/o:linux:linux_kernel:3.16",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "85",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "2029583",
                    "@lastboot": "Sat Aug 10 15:03:48 2024",
                },
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "259",
                    "@difficulty": "Good luck!",
                    "@values": "604F9DC7,5F5067EA,80C39DF,112C7A4A,F9B5822A,D2B670E5",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "78F89A5C,78F89AC1,78F89B26,78F89B86,78F89BEA,78F89C55",
                },
                "times": {"@srtt": "9669", "@rttvar": "2561", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331788",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "57",
                },
                "address": {"@addr": "35.198.136.18", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65536",
                        "extrareasons": {"@reason": "no-responses", "@count": "65536"},
                    }
                },
                "os": {
                    "portused": {
                        "@state": "closed",
                        "@proto": "udp",
                        "@portid": "44507",
                    }
                },
                "distance": {"@value": "6"},
                "times": {"@srtt": "19181", "@rttvar": "10531", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "59",
                },
                "address": {"@addr": "35.198.136.20", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65532",
                        "extrareasons": {"@reason": "no-responses", "@count": "65532"},
                    },
                    "port": [
                        {
                            "@protocol": "tcp",
                            "@portid": "22",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "ssh",
                                "@product": "OpenSSH",
                                "@version": "7.9p1 Debian 10+deb10u4",
                                "@extrainfo": "protocol 2.0",
                                "@ostype": "Linux",
                                "@method": "probed",
                                "@conf": "10",
                                "cpe": [
                                    "cpe:/a:openbsd:openssh:7.9p1",
                                    "cpe:/o:linux:linux_kernel",
                                ],
                            },
                            "script": {
                                "@id": "banner",
                                "@output": "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "80",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "57",
                            },
                            "service": {
                                "@name": "http",
                                "@product": "nginx",
                                "@version": "1.14.2",
                                "@method": "probed",
                                "@conf": "10",
                                "cpe": "cpe:/a:igor_sysoev:nginx:1.14.2",
                            },
                            "script": {
                                "@id": "http-server-header",
                                "@output": "nginx/1.14.2",
                                "elem": "nginx/1.14.2",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "443",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "https",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "3389",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "ms-wbt-server",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                    ],
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "22"},
                        {"@state": "closed", "@proto": "tcp", "@portid": "443"},
                    ],
                    "osmatch": [
                        {
                            "@name": "HP P2000 G3 NAS device",
                            "@accuracy": "91",
                            "@line": "34647",
                            "osclass": {
                                "@type": "storage-misc",
                                "@vendor": "HP",
                                "@osfamily": "embedded",
                                "@accuracy": "91",
                                "cpe": "cpe:/h:hp:p2000_g3",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32",
                            "@accuracy": "90",
                            "@line": "55078",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "2.6.X",
                                "@accuracy": "90",
                                "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                            },
                        },
                        {
                            "@name": "Infomir MAG-250 set-top box",
                            "@accuracy": "90",
                            "@line": "59437",
                            "osclass": [
                                {
                                    "@type": "media device",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "media device",
                                    "@vendor": "Infomir",
                                    "@osfamily": "embedded",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/h:infomir:mag-250",
                                },
                            ],
                        },
                        {
                            "@name": "Ubiquiti AirMax NanoStation WAP (Linux 2.6.32)",
                            "@accuracy": "90",
                            "@line": "61488",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Ubiquiti",
                                    "@osfamily": "embedded",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/h:ubnt:airmax_nanostation",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.7",
                            "@accuracy": "90",
                            "@line": "65676",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "90",
                                "cpe": "cpe:/o:linux:linux_kernel:3.7",
                            },
                        },
                        {
                            "@name": "Netgear RAIDiator 4.2.21 (Linux 2.6.37)",
                            "@accuracy": "90",
                            "@line": "87985",
                            "osclass": [
                                {
                                    "@type": "storage-misc",
                                    "@vendor": "Netgear",
                                    "@osfamily": "RAIDiator",
                                    "@osgen": "4.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:netgear:raidiator:4.2.21",
                                },
                                {
                                    "@type": "storage-misc",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6.37",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 2.6.32 - 3.13",
                            "@accuracy": "89",
                            "@line": "56411",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.3",
                            "@accuracy": "89",
                            "@line": "65197",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3.3",
                            },
                        },
                        {
                            "@name": "Ubiquiti AirOS 5.5.9",
                            "@accuracy": "89",
                            "@line": "102769",
                            "osclass": {
                                "@type": "WAP",
                                "@vendor": "Ubiquiti",
                                "@osfamily": "AirOS",
                                "@osgen": "5.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:ubnt:airos:5.5.9",
                            },
                        },
                        {
                            "@name": "Ubiquiti Pico Station WAP (AirOS 5.2.6)",
                            "@accuracy": "88",
                            "@line": "102825",
                            "osclass": {
                                "@type": "WAP",
                                "@vendor": "Ubiquiti",
                                "@osfamily": "AirOS",
                                "@osgen": "5.X",
                                "@accuracy": "88",
                                "cpe": "cpe:/o:ubnt:airos:5.2.6",
                            },
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "1222471",
                    "@lastboot": "Mon Aug 19 23:15:40 2024",
                },
                "tcpsequence": {
                    "@index": "254",
                    "@difficulty": "Good luck!",
                    "@values": "C136BA49,66350B12,346D34F1,71C52A8D,D64E9997,2436EEB1",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "48DD0E2A,48DD0E90,48DD0EF5,48DD0F61,48DD0FC5,48DD1024",
                },
                "times": {"@srtt": "8861", "@rttvar": "3748", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331788",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.24", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65536",
                        "extrareasons": {"@reason": "no-responses", "@count": "65536"},
                    }
                },
                "os": {
                    "portused": {
                        "@state": "closed",
                        "@proto": "udp",
                        "@portid": "31751",
                    }
                },
                "distance": {"@value": "6"},
                "times": {"@srtt": "10818", "@rttvar": "3523", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331810",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.29", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65532",
                        "extrareasons": {"@reason": "no-responses", "@count": "65532"},
                    },
                    "port": [
                        {
                            "@protocol": "tcp",
                            "@portid": "80",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "http",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "443",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "59",
                            },
                            "service": {
                                "@name": "https",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "8080",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "http-proxy",
                                "@servicefp": 'SF-Port8080-TCP:V=7.80%I=7%D=9/3%Time=66D678EB%P=x86_64-pc-linux-gnu%r(GetRequest,8E,"HTTP/1\\.0\\x20404\\x20Not\\x20Found\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:11\\x20GMT\\r\\nContent-Length:\\x2018\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\n\\r\\ndomain\\x20not\\x20accept\\n")%r(HTTPOptions,125,"HTTP/1\\.0\\x20200\\x20OK\\r\\nAccess-Control-Allow-Headers:\\x20Content-Type,\\x20X-Content-Type,\\x20X-Content-Encoding,\\x20X-Auth-User,\\x20X-Auth-Token\\r\\nAccess-Control-Allow-Methods:\\x20GET,\\x20POST,\\x20OPTIONS\\r\\nAccess-Control-Allow-Origin:\\x20\\*\\r\\nAccess-Control-Max-Age:\\x20300\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:11\\x20GMT\\r\\nContent-Length:\\x200\\r\\n\\r\\n")%r(RTSPRequest,67,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\nConnection:\\x20close\\r\\n\\r\\n400\\x20Bad\\x20Request")%r(FourOhFourRequest,8E,"HTTP/1\\.0\\x20404\\x20Not\\x20Found\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:11\\x20GMT\\r\\nContent-Length:\\x2018\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\n\\r\\ndomain\\x20not\\x20accept\\n")%r(Socks5,67,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\nConnection:\\x20close\\r\\n\\r\\n400\\x20Bad\\x20Request")%r(GenericLines,67,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\nConnection:\\x20close\\r\\n\\r\\n400\\x20Bad\\x20Request")%r(Help,67,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\nConnection:\\x20close\\r\\n\\r\\n400\\x20Bad\\x20Request")%r(SSLSessionReq,67,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\nConnection:\\x20close\\r\\n\\r\\n400\\x20Bad\\x20Request")%r(TerminalServerCookie,67,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\nConnection:\\x20close\\r\\n\\r\\n400\\x20Bad\\x20Request")%r(TLSSessionReq,67,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\nConnection:\\x20close\\r\\n\\r\\n400\\x20Bad\\x20Request")%r(Kerberos,67,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nContent-Type:\\x20text/plain;\\x20charset=utf-8\\r\\nConnection:\\x20close\\r\\n\\r\\n400\\x20Bad\\x20Request");',
                                "@method": "probed",
                                "@conf": "10",
                            },
                            "script": {
                                "@id": "fingerprint-strings",
                                "@output": "\n  FourOhFourRequest, GetRequest: \n    HTTP/1.0 404 Not Found\n    Date: Tue, 03 Sep 2024 02:48:11 GMT\n    Content-Length: 18\n    Content-Type: text/plain; charset=utf-8\n    domain not accept\n  GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: \n    HTTP/1.1 400 Bad Request\n    Content-Type: text/plain; charset=utf-8\n    Connection: close\n    Request\n  HTTPOptions: \n    HTTP/1.0 200 OK\n    Access-Control-Allow-Headers: Content-Type, X-Content-Type, X-Content-Encoding, X-Auth-User, X-Auth-Token\n    Access-Control-Allow-Methods: GET, POST, OPTIONS\n    Access-Control-Allow-Origin: *\n    Access-Control-Max-Age: 300\n    Date: Tue, 03 Sep 2024 02:48:11 GMT\n    Content-Length: 0",
                                "elem": [
                                    {
                                        "@key": "FourOhFourRequest, GetRequest",
                                        "#text": "HTTP/1.0 404 Not Found\n    Date: Tue, 03 Sep 2024 02:48:11 GMT\n    Content-Length: 18\n    Content-Type: text/plain; charset=utf-8\n    domain not accept",
                                    },
                                    {
                                        "@key": "GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie",
                                        "#text": "HTTP/1.1 400 Bad Request\n    Content-Type: text/plain; charset=utf-8\n    Connection: close\n    Request",
                                    },
                                    {
                                        "@key": "HTTPOptions",
                                        "#text": "HTTP/1.0 200 OK\n    Access-Control-Allow-Headers: Content-Type, X-Content-Type, X-Content-Encoding, X-Auth-User, X-Auth-Token\n    Access-Control-Allow-Methods: GET, POST, OPTIONS\n    Access-Control-Allow-Origin: *\n    Access-Control-Max-Age: 300\n    Date: Tue, 03 Sep 2024 02:48:11 GMT\n    Content-Length: 0",
                                    },
                                ],
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "8081",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "blackice-icecap",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                    ],
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "8080"},
                        {"@state": "closed", "@proto": "tcp", "@portid": "80"},
                    ],
                    "osmatch": [
                        {
                            "@name": "HP P2000 G3 NAS device",
                            "@accuracy": "91",
                            "@line": "34647",
                            "osclass": {
                                "@type": "storage-misc",
                                "@vendor": "HP",
                                "@osfamily": "embedded",
                                "@accuracy": "91",
                                "cpe": "cpe:/h:hp:p2000_g3",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32",
                            "@accuracy": "90",
                            "@line": "55579",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "2.6.X",
                                "@accuracy": "90",
                                "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                            },
                        },
                        {
                            "@name": "Ubiquiti AirMax NanoStation WAP (Linux 2.6.32)",
                            "@accuracy": "90",
                            "@line": "61488",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Ubiquiti",
                                    "@osfamily": "embedded",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/h:ubnt:airmax_nanostation",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.7",
                            "@accuracy": "90",
                            "@line": "65676",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "90",
                                "cpe": "cpe:/o:linux:linux_kernel:3.7",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32 - 3.13",
                            "@accuracy": "89",
                            "@line": "56411",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.0 - 3.2",
                            "@accuracy": "89",
                            "@line": "62456",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3",
                            },
                        },
                        {
                            "@name": "Linux 3.3",
                            "@accuracy": "89",
                            "@line": "65197",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3.3",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32 - 3.1",
                            "@accuracy": "89",
                            "@line": "56315",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                            ],
                        },
                        {
                            "@name": "Infomir MAG-250 set-top box",
                            "@accuracy": "89",
                            "@line": "59437",
                            "osclass": [
                                {
                                    "@type": "media device",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "media device",
                                    "@vendor": "Infomir",
                                    "@osfamily": "embedded",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/h:infomir:mag-250",
                                },
                            ],
                        },
                        {
                            "@name": "Netgear RAIDiator 4.2.21 (Linux 2.6.37)",
                            "@accuracy": "89",
                            "@line": "87985",
                            "osclass": [
                                {
                                    "@type": "storage-misc",
                                    "@vendor": "Netgear",
                                    "@osfamily": "RAIDiator",
                                    "@osgen": "4.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:netgear:raidiator:4.2.21",
                                },
                                {
                                    "@type": "storage-misc",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6.37",
                                },
                            ],
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "3761669",
                    "@lastboot": "Sun Jul 21 13:55:42 2024",
                },
                "tcpsequence": {
                    "@index": "254",
                    "@difficulty": "Good luck!",
                    "@values": "EED45757,FA864C9A,C05EFF34,97EDC37D,73FBF544,BA88E4E2",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "E036248E,E03624F4,E0362559,E03625C5,E036262A,E0362688",
                },
                "times": {"@srtt": "10611", "@rttvar": "4691", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331788",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "113",
                },
                "address": {"@addr": "35.198.136.30", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65536",
                        "extrareasons": {"@reason": "no-responses", "@count": "65536"},
                    }
                },
                "os": {
                    "portused": {
                        "@state": "closed",
                        "@proto": "udp",
                        "@portid": "34489",
                    }
                },
                "distance": {"@value": "6"},
                "times": {"@srtt": "4702", "@rttvar": "1699", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.33", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "22",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "57",
                        },
                        "service": {
                            "@name": "ssh",
                            "@product": "OpenSSH",
                            "@version": "8.4p1 Debian 5+deb11u3",
                            "@extrainfo": "protocol 2.0",
                            "@ostype": "Linux",
                            "@method": "probed",
                            "@conf": "10",
                            "cpe": [
                                "cpe:/a:openbsd:openssh:8.4p1",
                                "cpe:/o:linux:linux_kernel",
                            ],
                        },
                        "script": {
                            "@id": "banner",
                            "@output": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
                        },
                    },
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "22"},
                        {"@state": "closed", "@proto": "udp", "@portid": "39047"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "92",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "89",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "89",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "85",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "742954",
                    "@lastboot": "Sun Aug 25 12:27:37 2024",
                },
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "262",
                    "@difficulty": "Good luck!",
                    "@values": "414498F1,2BFAE964,DEFB74B2,A1BA1EC6,A2583EBB,DDBE14B",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "2C483554,2C4835BA,2C48361F,2C48367F,2C4836E3,2C48374D",
                },
                "times": {"@srtt": "10219", "@rttvar": "1526", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331788",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "113",
                },
                "address": {"@addr": "35.198.136.35", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65536",
                        "extrareasons": {"@reason": "no-responses", "@count": "65536"},
                    }
                },
                "os": None,
                "times": {"@srtt": "10736", "@rttvar": "6078", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331788",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.38", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65532",
                        "extrareasons": {"@reason": "no-responses", "@count": "65532"},
                    },
                    "port": [
                        {
                            "@protocol": "tcp",
                            "@portid": "80",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "http",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "443",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "https",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "3478",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "57",
                            },
                            "service": {
                                "@name": "stun",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "5349",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "59",
                            },
                            "service": {
                                "@name": "stuns",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                    ],
                },
                "os": {
                    "portused": {"@state": "closed", "@proto": "tcp", "@portid": "80"}
                },
                "times": {"@srtt": "11173", "@rttvar": "997", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.42", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "closed",
                        "@count": "65533",
                        "extrareasons": {"@reason": "resets", "@count": "65533"},
                    },
                    "port": [
                        {
                            "@protocol": "tcp",
                            "@portid": "22",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "59",
                            },
                            "service": {
                                "@name": "ssh",
                                "@extrainfo": "protocol 2.0",
                                "@servicefp": 'SF-Port22-TCP:V=7.80%I=7%D=9/3%Time=66D678EB%P=x86_64-pc-linux-gnu%r(NULL,1A,"SSH-2\\.0-OpenSSH_9\\.6p1\\x20r4\\r\\n");',
                                "@method": "probed",
                                "@conf": "10",
                            },
                            "script": [
                                {
                                    "@id": "banner",
                                    "@output": "SSH-2.0-OpenSSH_9.6p1 r4",
                                },
                                {
                                    "@id": "fingerprint-strings",
                                    "@output": "\n  NULL: \n    SSH-2.0-OpenSSH_9.6p1 r4",
                                    "elem": {
                                        "@key": "NULL",
                                        "#text": "SSH-2.0-OpenSSH_9.6p1 r4",
                                    },
                                },
                            ],
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "9200",
                            "state": {
                                "@state": "filtered",
                                "@reason": "no-response",
                                "@reason_ttl": "0",
                            },
                            "service": {
                                "@name": "wap-wsp",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "31339",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "unknown",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                    ],
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "22"},
                        {"@state": "closed", "@proto": "tcp", "@portid": "1"},
                        {"@state": "closed", "@proto": "udp", "@portid": "33229"},
                    ],
                    "osmatch": [
                        {
                            "@name": "HP P2000 G3 NAS device",
                            "@accuracy": "93",
                            "@line": "34647",
                            "osclass": {
                                "@type": "storage-misc",
                                "@vendor": "HP",
                                "@osfamily": "embedded",
                                "@accuracy": "93",
                                "cpe": "cpe:/h:hp:p2000_g3",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32",
                            "@accuracy": "92",
                            "@line": "55409",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "2.6.X",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32 - 3.1",
                            "@accuracy": "92",
                            "@line": "56315",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "92",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "92",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                            ],
                        },
                        {
                            "@name": "Ubiquiti AirMax NanoStation WAP (Linux 2.6.32)",
                            "@accuracy": "92",
                            "@line": "61488",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "92",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Ubiquiti",
                                    "@osfamily": "embedded",
                                    "@accuracy": "92",
                                    "cpe": "cpe:/h:ubnt:airmax_nanostation",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.7",
                            "@accuracy": "92",
                            "@line": "65676",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:linux:linux_kernel:3.7",
                            },
                        },
                        {
                            "@name": "Ubiquiti Pico Station WAP (AirOS 5.2.6)",
                            "@accuracy": "92",
                            "@line": "102825",
                            "osclass": {
                                "@type": "WAP",
                                "@vendor": "Ubiquiti",
                                "@osfamily": "AirOS",
                                "@osgen": "5.X",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:ubnt:airos:5.2.6",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32 - 3.13",
                            "@accuracy": "92",
                            "@line": "56411",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "92",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "92",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.0 - 3.2",
                            "@accuracy": "92",
                            "@line": "62456",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:linux:linux_kernel:3",
                            },
                        },
                        {
                            "@name": "Linux 3.3",
                            "@accuracy": "92",
                            "@line": "65197",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:linux:linux_kernel:3.3",
                            },
                        },
                        {
                            "@name": "Infomir MAG-250 set-top box",
                            "@accuracy": "91",
                            "@line": "59437",
                            "osclass": [
                                {
                                    "@type": "media device",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "91",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "media device",
                                    "@vendor": "Infomir",
                                    "@osfamily": "embedded",
                                    "@accuracy": "91",
                                    "cpe": "cpe:/h:infomir:mag-250",
                                },
                            ],
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "3455686",
                    "@lastboot": "Thu Jul 25 02:55:25 2024",
                },
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "260",
                    "@difficulty": "Good luck!",
                    "@values": "A0183043,9D9E6E82,8A67540E,C97649C0,FF70E035,5F48A5BC",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "CDF9364A,CDF936AF,CDF93714,CDF93780,CDF937E5,CDF93843",
                },
                "times": {"@srtt": "6518", "@rttvar": "2094", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.43", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65534",
                        "extrareasons": {"@reason": "no-responses", "@count": "65534"},
                    },
                    "port": [
                        {
                            "@protocol": "tcp",
                            "@portid": "22",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "ssh",
                                "@extrainfo": "protocol 2.0",
                                "@servicefp": 'SF-Port22-TCP:V=7.80%I=7%D=9/3%Time=66D678EB%P=x86_64-pc-linux-gnu%r(NULL,1A,"SSH-2\\.0-OpenSSH_9\\.6p1\\x20r3\\r\\n");',
                                "@method": "probed",
                                "@conf": "10",
                            },
                            "script": [
                                {
                                    "@id": "banner",
                                    "@output": "SSH-2.0-OpenSSH_9.6p1 r3",
                                },
                                {
                                    "@id": "fingerprint-strings",
                                    "@output": "\n  NULL: \n    SSH-2.0-OpenSSH_9.6p1 r3",
                                    "elem": {
                                        "@key": "NULL",
                                        "#text": "SSH-2.0-OpenSSH_9.6p1 r3",
                                    },
                                },
                            ],
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "3389",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "ms-wbt-server",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                    ],
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "22"},
                        {"@state": "closed", "@proto": "tcp", "@portid": "3389"},
                    ],
                    "osmatch": [
                        {
                            "@name": "HP P2000 G3 NAS device",
                            "@accuracy": "91",
                            "@line": "34647",
                            "osclass": {
                                "@type": "storage-misc",
                                "@vendor": "HP",
                                "@osfamily": "embedded",
                                "@accuracy": "91",
                                "cpe": "cpe:/h:hp:p2000_g3",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32",
                            "@accuracy": "90",
                            "@line": "55409",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "2.6.X",
                                "@accuracy": "90",
                                "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32 - 3.1",
                            "@accuracy": "90",
                            "@line": "56315",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                            ],
                        },
                        {
                            "@name": "Ubiquiti AirMax NanoStation WAP (Linux 2.6.32)",
                            "@accuracy": "90",
                            "@line": "61488",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Ubiquiti",
                                    "@osfamily": "embedded",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/h:ubnt:airmax_nanostation",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.7",
                            "@accuracy": "90",
                            "@line": "65676",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "90",
                                "cpe": "cpe:/o:linux:linux_kernel:3.7",
                            },
                        },
                        {
                            "@name": "Ubiquiti AirOS 5.5.9",
                            "@accuracy": "90",
                            "@line": "102769",
                            "osclass": {
                                "@type": "WAP",
                                "@vendor": "Ubiquiti",
                                "@osfamily": "AirOS",
                                "@osgen": "5.X",
                                "@accuracy": "90",
                                "cpe": "cpe:/o:ubnt:airos:5.5.9",
                            },
                        },
                        {
                            "@name": "Ubiquiti Pico Station WAP (AirOS 5.2.6)",
                            "@accuracy": "89",
                            "@line": "102825",
                            "osclass": {
                                "@type": "WAP",
                                "@vendor": "Ubiquiti",
                                "@osfamily": "AirOS",
                                "@osgen": "5.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:ubnt:airos:5.2.6",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32 - 3.13",
                            "@accuracy": "89",
                            "@line": "56411",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.0 - 3.2",
                            "@accuracy": "89",
                            "@line": "62456",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3",
                            },
                        },
                        {
                            "@name": "Infomir MAG-250 set-top box",
                            "@accuracy": "89",
                            "@line": "59437",
                            "osclass": [
                                {
                                    "@type": "media device",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "media device",
                                    "@vendor": "Infomir",
                                    "@osfamily": "embedded",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/h:infomir:mag-250",
                                },
                            ],
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "3812202",
                    "@lastboot": "Sat Jul 20 23:53:29 2024",
                },
                "tcpsequence": {
                    "@index": "262",
                    "@difficulty": "Good luck!",
                    "@values": "3F9507D0,16D2C514,1E5F63C4,94AA1708,ECE2F8C5,8CF8EC56",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "E33937C7,E339382D,E3393892,E33938F2,E3393956,E33939C1",
                },
                "times": {"@srtt": "9466", "@rttvar": "3067", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {"@state": "up", "@reason": "syn-ack", "@reason_ttl": "57"},
                "address": {"@addr": "35.198.136.45", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65534",
                        "extrareasons": {"@reason": "no-responses", "@count": "65534"},
                    },
                    "port": [
                        {
                            "@protocol": "tcp",
                            "@portid": "80",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "57",
                            },
                            "service": {
                                "@name": "http",
                                "@product": "nginx",
                                "@extrainfo": "reverse proxy",
                                "@method": "probed",
                                "@conf": "10",
                                "cpe": "cpe:/a:igor_sysoev:nginx",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "443",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "59",
                            },
                            "service": {
                                "@name": "http",
                                "@product": "nginx",
                                "@extrainfo": "reverse proxy",
                                "@tunnel": "ssl",
                                "@method": "probed",
                                "@conf": "10",
                                "cpe": "cpe:/a:igor_sysoev:nginx",
                            },
                        },
                    ],
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "80"},
                        {"@state": "closed", "@proto": "udp", "@portid": "31173"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "93",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "93",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "90",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "86",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "86",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                        {
                            "@name": "HP P2000 G3 NAS device",
                            "@accuracy": "85",
                            "@line": "34647",
                            "osclass": {
                                "@type": "storage-misc",
                                "@vendor": "HP",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:hp:p2000_g3",
                            },
                        },
                        {
                            "@name": "Crestron MPC-M5 AV controller or Wago Kontakttechnik 750-852 PLC",
                            "@accuracy": "85",
                            "@line": "19564",
                            "osclass": [
                                {
                                    "@type": "media device",
                                    "@vendor": "Crestron",
                                    "@osfamily": "embedded",
                                    "@accuracy": "85",
                                    "cpe": "cpe:/h:crestron:mpc-m5",
                                },
                                {
                                    "@type": "specialized",
                                    "@vendor": "Wago Kontakttechnik",
                                    "@osfamily": "embedded",
                                    "@accuracy": "85",
                                    "cpe": "cpe:/h:wago_kontakttechnik:750-852",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.16",
                            "@accuracy": "85",
                            "@line": "64070",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "85",
                                "cpe": "cpe:/o:linux:linux_kernel:3.16",
                            },
                        },
                        {
                            "@name": "ASUS RT-N56U WAP (Linux 3.4)",
                            "@accuracy": "85",
                            "@line": "8344",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "Asus",
                                    "@osfamily": "embedded",
                                    "@accuracy": "85",
                                    "cpe": "cpe:/h:asus:rt-n56u",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "85",
                                    "cpe": "cpe:/o:linux:linux_kernel:3.4",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.1",
                            "@accuracy": "85",
                            "@line": "62708",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "85",
                                "cpe": "cpe:/o:linux:linux_kernel:3.1",
                            },
                        },
                        {
                            "@name": "Linux 3.2",
                            "@accuracy": "85",
                            "@line": "64455",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "85",
                                "cpe": "cpe:/o:linux:linux_kernel:3.2",
                            },
                        },
                    ],
                },
                "uptime": {"@seconds": "25", "@lastboot": "Tue Sep  3 02:49:46 2024"},
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "263",
                    "@difficulty": "Good luck!",
                    "@values": "D744A627,32893A3A,C5C4FA3E,DD452348,53DAA625,3EE0D5E9",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "other",
                    "@values": "59B983A5,59B9840A,59B98470,59B984DB,59B98540,D7C09305",
                },
                "times": {"@srtt": "6321", "@rttvar": "1952", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.46", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "443",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "59",
                        },
                        "service": {
                            "@name": "https",
                            "@servicefp": 'SF-Port443-TCP:V=7.80%T=SSL%I=7%D=9/3%Time=66D678F1%P=x86_64-pc-linux-gnu%r(GetRequest,22F,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x20e4ae671b-8776-4164-a35a-03d73dc323a7\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x206c148040-f3c0-441d-b504-8b0fc8f59f39\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x20a5829ebc-76d9-4991-9c79-d27a2b6293e9\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:17\\x20GMT\\r\\nContent-Length:\\x20185\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20get\\x20path\\x20\\\\\\"/\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n")%r(HTTPOptions,233,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x2023f4da24-3344-4e53-9aea-d541fd356148\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x206c148040-f3c0-441d-b504-8b0fc8f59f39\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x20a5829ebc-76d9-4991-9c79-d27a2b6293e9\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:17\\x20GMT\\r\\nContent-Length:\\x20189\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20options\\x20path\\x20\\\\\\"/\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n")%r(FourOhFourRequest,24A,"HTTP/1\\.0\\x20403\\x20Forbidden\\r\\nAudit-Id:\\x208103c945-6d5a-4160-9ccc-293810f7dd2a\\r\\nCache-Control:\\x20no-cache,\\x20private\\r\\nContent-Type:\\x20application/json\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Kubernetes-Pf-Flowschema-Uid:\\x206c148040-f3c0-441d-b504-8b0fc8f59f39\\r\\nX-Kubernetes-Pf-Prioritylevel-Uid:\\x20a5829ebc-76d9-4991-9c79-d27a2b6293e9\\r\\nDate:\\x20Tue,\\x2003\\x20Sep\\x202024\\x2002:48:17\\x20GMT\\r\\nContent-Length:\\x20212\\r\\n\\r\\n{\\"kind\\":\\"Status\\",\\"apiVersion\\":\\"v1\\",\\"metadata\\":{},\\"status\\":\\"Failure\\",\\"message\\":\\"forbidden:\\x20User\\x20\\\\\\"system:anonymous\\\\\\"\\x20cannot\\x20get\\x20path\\x20\\\\\\"/nice\\x20ports,/Trinity\\.txt\\.bak\\\\\\"\\",\\"reason\\":\\"Forbidden\\",\\"details\\":{},\\"code\\":403}\\n");',
                            "@tunnel": "ssl",
                            "@method": "probed",
                            "@conf": "10",
                        },
                        "script": {
                            "@id": "fingerprint-strings",
                            "@output": '\n  FourOhFourRequest: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: 8103c945-6d5a-4160-9ccc-293810f7dd2a\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 6c148040-f3c0-441d-b504-8b0fc8f59f39\n    X-Kubernetes-Pf-Prioritylevel-Uid: a5829ebc-76d9-4991-9c79-d27a2b6293e9\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 212\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}\n  GetRequest: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: e4ae671b-8776-4164-a35a-03d73dc323a7\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 6c148040-f3c0-441d-b504-8b0fc8f59f39\n    X-Kubernetes-Pf-Prioritylevel-Uid: a5829ebc-76d9-4991-9c79-d27a2b6293e9\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 185\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}\n  HTTPOptions: \n    HTTP/1.0 403 Forbidden\n    Audit-Id: 23f4da24-3344-4e53-9aea-d541fd356148\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 6c148040-f3c0-441d-b504-8b0fc8f59f39\n    X-Kubernetes-Pf-Prioritylevel-Uid: a5829ebc-76d9-4991-9c79-d27a2b6293e9\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 189\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}',
                            "elem": [
                                {
                                    "@key": "FourOhFourRequest",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: 8103c945-6d5a-4160-9ccc-293810f7dd2a\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 6c148040-f3c0-441d-b504-8b0fc8f59f39\n    X-Kubernetes-Pf-Prioritylevel-Uid: a5829ebc-76d9-4991-9c79-d27a2b6293e9\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 212\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}',
                                },
                                {
                                    "@key": "GetRequest",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: e4ae671b-8776-4164-a35a-03d73dc323a7\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 6c148040-f3c0-441d-b504-8b0fc8f59f39\n    X-Kubernetes-Pf-Prioritylevel-Uid: a5829ebc-76d9-4991-9c79-d27a2b6293e9\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 185\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}',
                                },
                                {
                                    "@key": "HTTPOptions",
                                    "#text": 'HTTP/1.0 403 Forbidden\n    Audit-Id: 23f4da24-3344-4e53-9aea-d541fd356148\n    Cache-Control: no-cache, private\n    Content-Type: application/json\n    X-Content-Type-Options: nosniff\n    X-Kubernetes-Pf-Flowschema-Uid: 6c148040-f3c0-441d-b504-8b0fc8f59f39\n    X-Kubernetes-Pf-Prioritylevel-Uid: a5829ebc-76d9-4991-9c79-d27a2b6293e9\n    Date: Tue, 03 Sep 2024 02:48:17 GMT\n    Content-Length: 189\n    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}',
                                },
                            ],
                        },
                    },
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "443"},
                        {"@state": "closed", "@proto": "udp", "@portid": "36014"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "92",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "89",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "89",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "85",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                    ],
                },
                "uptime": {"@seconds": "25", "@lastboot": "Tue Sep  3 02:49:46 2024"},
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "250",
                    "@difficulty": "Good luck!",
                    "@values": "2200644D,6E81C431,A2DB8163,8190938D,B10A513F,E959AD2D",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "other",
                    "@values": "1EC8D151,1EC8D1B7,1EC8D21C,742F06DE,20869194,208691F3",
                },
                "times": {"@srtt": "9496", "@rttvar": "4152", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331784",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "113",
                },
                "address": {"@addr": "35.198.136.54", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65536",
                        "extrareasons": {"@reason": "no-responses", "@count": "65536"},
                    }
                },
                "os": {
                    "portused": {
                        "@state": "closed",
                        "@proto": "udp",
                        "@portid": "41492",
                    },
                    "osmatch": [
                        {
                            "@name": "Brother HL-2070N printer",
                            "@accuracy": "100",
                            "@line": "11104",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Brother",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:brother:hl-2070n",
                            },
                        },
                        {
                            "@name": "Brother HL-5070N printer",
                            "@accuracy": "100",
                            "@line": "11284",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Brother",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:brother:hl-5070n",
                            },
                        },
                        {
                            "@name": "Brother MFC-420CN printer",
                            "@accuracy": "100",
                            "@line": "11503",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Brother",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:brother:mfc-420cn",
                            },
                        },
                        {
                            "@name": "Brother MFC-7820N printer",
                            "@accuracy": "100",
                            "@line": "11652",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Brother",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:brother:mfc-7820n",
                            },
                        },
                        {
                            "@name": "Elk ELK-M1EXP Ethernet-to-serial bridge",
                            "@accuracy": "100",
                            "@line": "23982",
                            "osclass": {
                                "@type": "bridge",
                                "@vendor": "Elk",
                                "@osfamily": "embedded",
                                "@accuracy": "100",
                                "cpe": "cpe:/h:elk:elk-m1exp",
                            },
                        },
                        {
                            "@name": "Novatel MiFi 2200 3G WAP or iDirect Evolution X1 satellite router",
                            "@accuracy": "100",
                            "@line": "39944",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "iDirect",
                                    "@osfamily": "embedded",
                                    "@accuracy": "100",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Novatel",
                                    "@osfamily": "embedded",
                                    "@accuracy": "100",
                                    "cpe": "cpe:/h:novatel:mifi_2200_3g",
                                },
                            ],
                        },
                    ],
                },
                "distance": {"@value": "6"},
                "times": {"@srtt": "11315", "@rttvar": "10062", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.56", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65534",
                        "extrareasons": {"@reason": "no-responses", "@count": "65534"},
                    },
                    "port": [
                        {
                            "@protocol": "tcp",
                            "@portid": "22",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "ssh",
                                "@product": "OpenSSH",
                                "@version": "7.6p1 Ubuntu 4ubuntu0.5",
                                "@extrainfo": "Ubuntu Linux; protocol 2.0",
                                "@ostype": "Linux",
                                "@method": "probed",
                                "@conf": "10",
                                "cpe": [
                                    "cpe:/a:openbsd:openssh:7.6p1",
                                    "cpe:/o:linux:linux_kernel",
                                ],
                            },
                            "script": {
                                "@id": "banner",
                                "@output": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "3389",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "ms-wbt-server",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                    ],
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "22"},
                        {"@state": "closed", "@proto": "tcp", "@portid": "3389"},
                    ],
                    "osmatch": [
                        {
                            "@name": "HP P2000 G3 NAS device",
                            "@accuracy": "91",
                            "@line": "34647",
                            "osclass": {
                                "@type": "storage-misc",
                                "@vendor": "HP",
                                "@osfamily": "embedded",
                                "@accuracy": "91",
                                "cpe": "cpe:/h:hp:p2000_g3",
                            },
                        },
                        {
                            "@name": "Infomir MAG-250 set-top box",
                            "@accuracy": "90",
                            "@line": "59437",
                            "osclass": [
                                {
                                    "@type": "media device",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "media device",
                                    "@vendor": "Infomir",
                                    "@osfamily": "embedded",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/h:infomir:mag-250",
                                },
                            ],
                        },
                        {
                            "@name": "Ubiquiti AirMax NanoStation WAP (Linux 2.6.32)",
                            "@accuracy": "90",
                            "@line": "61488",
                            "osclass": [
                                {
                                    "@type": "WAP",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                                },
                                {
                                    "@type": "WAP",
                                    "@vendor": "Ubiquiti",
                                    "@osfamily": "embedded",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/h:ubnt:airmax_nanostation",
                                },
                            ],
                        },
                        {
                            "@name": "Netgear RAIDiator 4.2.21 (Linux 2.6.37)",
                            "@accuracy": "90",
                            "@line": "87985",
                            "osclass": [
                                {
                                    "@type": "storage-misc",
                                    "@vendor": "Netgear",
                                    "@osfamily": "RAIDiator",
                                    "@osgen": "4.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:netgear:raidiator:4.2.21",
                                },
                                {
                                    "@type": "storage-misc",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "90",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6.37",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 2.6.32 - 3.13",
                            "@accuracy": "89",
                            "@line": "56411",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "2.6.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:2.6",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.3",
                            "@accuracy": "89",
                            "@line": "65197",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3.3",
                            },
                        },
                        {
                            "@name": "Linux 2.6.32",
                            "@accuracy": "89",
                            "@line": "55078",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "2.6.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:2.6.32",
                            },
                        },
                        {
                            "@name": "Linux 3.7",
                            "@accuracy": "89",
                            "@line": "65676",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3.7",
                            },
                        },
                        {
                            "@name": "Ubiquiti AirOS 5.5.9",
                            "@accuracy": "89",
                            "@line": "102769",
                            "osclass": {
                                "@type": "WAP",
                                "@vendor": "Ubiquiti",
                                "@osfamily": "AirOS",
                                "@osgen": "5.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:ubnt:airos:5.5.9",
                            },
                        },
                        {
                            "@name": "Ubiquiti Pico Station WAP (AirOS 5.2.6)",
                            "@accuracy": "88",
                            "@line": "102825",
                            "osclass": {
                                "@type": "WAP",
                                "@vendor": "Ubiquiti",
                                "@osfamily": "AirOS",
                                "@osgen": "5.X",
                                "@accuracy": "88",
                                "cpe": "cpe:/o:ubnt:airos:5.2.6",
                            },
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "439947",
                    "@lastboot": "Thu Aug 29 00:37:44 2024",
                },
                "tcpsequence": {
                    "@index": "254",
                    "@difficulty": "Good luck!",
                    "@values": "51430116,FA22FA66,85419790,EA0B9B99,95B36CB1,5A846236",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "1A38AF66,1A38AFCC,1A38B031,1A38B09D,1A38B102,1A38B160",
                },
                "times": {"@srtt": "8271", "@rttvar": "3350", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331788",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.57", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65536",
                        "extrareasons": {"@reason": "no-responses", "@count": "65536"},
                    }
                },
                "os": None,
                "times": {"@srtt": "12284", "@rttvar": "4663", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "113",
                },
                "address": {"@addr": "35.198.136.58", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65535",
                        "extrareasons": {"@reason": "no-responses", "@count": "65535"},
                    },
                    "port": {
                        "@protocol": "tcp",
                        "@portid": "3307",
                        "state": {
                            "@state": "open",
                            "@reason": "syn-ack",
                            "@reason_ttl": "58",
                        },
                        "service": {
                            "@name": "opsession-prxy",
                            "@tunnel": "ssl",
                            "@method": "table",
                            "@conf": "3",
                        },
                    },
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "3307"},
                        {"@state": "closed", "@proto": "udp", "@portid": "30519"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "92",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "92",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Vodavi XTS-IP PBX",
                            "@accuracy": "90",
                            "@line": "104007",
                            "osclass": {
                                "@type": "PBX",
                                "@vendor": "Vodavi",
                                "@osfamily": "embedded",
                                "@accuracy": "90",
                                "cpe": "cpe:/h:vodavi:xts-ip",
                            },
                        },
                        {
                            "@name": "Epson Stylus Pro 400 printer",
                            "@accuracy": "89",
                            "@line": "24598",
                            "osclass": {
                                "@type": "printer",
                                "@vendor": "Epson",
                                "@osfamily": "embedded",
                                "@accuracy": "89",
                                "cpe": "cpe:/h:epson:stylus_pro_400",
                            },
                        },
                        {
                            "@name": "Nintendo Wii game console",
                            "@accuracy": "85",
                            "@line": "88600",
                            "osclass": {
                                "@type": "game console",
                                "@vendor": "Nintendo",
                                "@osfamily": "embedded",
                                "@accuracy": "85",
                                "cpe": "cpe:/h:nintendo:wii",
                            },
                        },
                    ],
                },
                "uptime": {
                    "@seconds": "1379596",
                    "@lastboot": "Sun Aug 18 03:36:55 2024",
                },
                "distance": {"@value": "6"},
                "tcpsequence": {
                    "@index": "257",
                    "@difficulty": "Good luck!",
                    "@values": "7EDA90D6,A385E13D,F8BF575B,412BCB29,E93BA48,1B58AC71",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "1000HZ",
                    "@values": "523A97FA,523A9860,523A98C5,523A9925,523A9989,523A99F4",
                },
                "times": {"@srtt": "10313", "@rttvar": "1991", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331788",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "59",
                },
                "address": {"@addr": "35.198.136.61", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65536",
                        "extrareasons": {"@reason": "no-responses", "@count": "65536"},
                    }
                },
                "os": {
                    "portused": {
                        "@state": "closed",
                        "@proto": "udp",
                        "@portid": "40691",
                    }
                },
                "distance": {"@value": "6"},
                "times": {"@srtt": "6122", "@rttvar": "3965", "@to": "100000"},
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "58",
                },
                "address": {"@addr": "35.198.136.62", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "65533",
                        "extrareasons": {"@reason": "no-responses", "@count": "65533"},
                    },
                    "port": [
                        {
                            "@protocol": "tcp",
                            "@portid": "22",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "ssh",
                                "@product": "OpenSSH",
                                "@version": "7.4p1 Debian 10+deb9u5",
                                "@extrainfo": "protocol 2.0",
                                "@ostype": "Linux",
                                "@method": "probed",
                                "@conf": "10",
                                "cpe": [
                                    "cpe:/a:openbsd:openssh:7.4p1",
                                    "cpe:/o:linux:linux_kernel",
                                ],
                            },
                            "script": {
                                "@id": "banner",
                                "@output": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u5",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "3128",
                            "state": {
                                "@state": "open",
                                "@reason": "syn-ack",
                                "@reason_ttl": "58",
                            },
                            "service": {
                                "@name": "http-proxy",
                                "@product": "Squid http proxy",
                                "@version": "3.5.23",
                                "@method": "probed",
                                "@conf": "10",
                                "cpe": "cpe:/a:squid-cache:squid:3.5.23",
                            },
                            "script": {
                                "@id": "http-server-header",
                                "@output": "squid/3.5.23",
                                "elem": "squid/3.5.23",
                            },
                        },
                        {
                            "@protocol": "tcp",
                            "@portid": "3389",
                            "state": {
                                "@state": "closed",
                                "@reason": "reset",
                                "@reason_ttl": "59",
                            },
                            "service": {
                                "@name": "ms-wbt-server",
                                "@method": "table",
                                "@conf": "3",
                            },
                        },
                    ],
                },
                "os": {
                    "portused": [
                        {"@state": "open", "@proto": "tcp", "@portid": "22"},
                        {"@state": "closed", "@proto": "tcp", "@portid": "3389"},
                    ],
                    "osmatch": [
                        {
                            "@name": "Linux 3.16",
                            "@accuracy": "94",
                            "@line": "64070",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "94",
                                "cpe": "cpe:/o:linux:linux_kernel:3.16",
                            },
                        },
                        {
                            "@name": "Linux 3.2 - 3.8",
                            "@accuracy": "90",
                            "@line": "65058",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "90",
                                "cpe": "cpe:/o:linux:linux_kernel:3",
                            },
                        },
                        {
                            "@name": "Crestron XPanel control system",
                            "@accuracy": "89",
                            "@line": "19544",
                            "osclass": {
                                "@type": "specialized",
                                "@vendor": "Crestron",
                                "@osfamily": "2-Series",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:crestron:2_series",
                            },
                        },
                        {
                            "@name": "Linux 3.10 - 4.11",
                            "@accuracy": "89",
                            "@line": "63230",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:3",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "4.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:4",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.12",
                            "@accuracy": "89",
                            "@line": "63456",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3.12",
                            },
                        },
                        {
                            "@name": "Linux 3.13",
                            "@accuracy": "89",
                            "@line": "63698",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3.13",
                            },
                        },
                        {
                            "@name": "Linux 3.13 or 4.2",
                            "@accuracy": "89",
                            "@line": "63776",
                            "osclass": [
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "3.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:3.13",
                                },
                                {
                                    "@type": "general purpose",
                                    "@vendor": "Linux",
                                    "@osfamily": "Linux",
                                    "@osgen": "4.X",
                                    "@accuracy": "89",
                                    "cpe": "cpe:/o:linux:linux_kernel:4.2",
                                },
                            ],
                        },
                        {
                            "@name": "Linux 3.2 - 3.5",
                            "@accuracy": "89",
                            "@line": "64985",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "3.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:3",
                            },
                        },
                        {
                            "@name": "Linux 4.2",
                            "@accuracy": "89",
                            "@line": "67075",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "4.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:4.2",
                            },
                        },
                        {
                            "@name": "Linux 4.4",
                            "@accuracy": "89",
                            "@line": "67129",
                            "osclass": {
                                "@type": "general purpose",
                                "@vendor": "Linux",
                                "@osfamily": "Linux",
                                "@osgen": "4.X",
                                "@accuracy": "89",
                                "cpe": "cpe:/o:linux:linux_kernel:4.4",
                            },
                        },
                    ],
                },
                "uptime": {"@seconds": "6094", "@lastboot": "Tue Sep  3 01:08:37 2024"},
                "tcpsequence": {
                    "@index": "248",
                    "@difficulty": "Good luck!",
                    "@values": "1B6C3345,DE8DAB48,3690D29D,EBD048E3,281BC2EF,7A89400F",
                },
                "ipidsequence": {"@class": "All zeros", "@values": "0,0,0,0,0,0"},
                "tcptssequence": {
                    "@class": "other",
                    "@values": "170F8D,170FA6,170FC0,170FD8,170FF1,17100B",
                },
                "times": {"@srtt": "11352", "@rttvar": "3287", "@to": "100000"},
            },
        ],
        "runstats": {
            "finished": {
                "@time": "1725331811",
                "@timestr": "Tue Sep  3 02:50:11 2024",
                "@elapsed": "2580.44",
                "@summary": "Nmap done at Tue Sep  3 02:50:11 2024; 64 IP addresses (25 hosts up) scanned in 2580.44 seconds",
                "@exit": "success",
            },
            "hosts": {"@up": "25", "@down": "39", "@total": "64"},
        },
    }
}


def testAgentNmapOptions_whsssssenServiceHasNoProduct_reportsFingerprintzzz(
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
        return_value=(scan_results, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    # assert any("fingerprint" in msg.selector for msg in agent_mock) is False