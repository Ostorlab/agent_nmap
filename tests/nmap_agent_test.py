"""Unittests for Nmap agent."""

import json
import pathlib
import socket
import subprocess
from typing import Any

import pytest
import requests_mock as rq_mock
from ostorlab.agent.message import message
from ostorlab.utils import definitions as utils_definitions
from pytest_mock import plugin

from agent import generators
from agent import nmap_agent
from agent import nmap_options
from agent import nmap_wrapper
from agent import result_parser

SCAN_RESULT_HOST_AS_LIST = {
    "nmaprun": {
        "@scanner": "nmap",
        "@args": "nmap -O -sV -n -p 0-6525325 -T3 -sS --script banner -sC -oX /tmp/xmloutput -oN /tmp/normal 235.292.46.2/26",
        "@start": "17255329231341",
        "@startstr": "Tue Sep  3 02:07:11 20124",
        "host": [
            {
                "@starttime": "1725329231",
                "@endtime": "1725331809",
                "status": {"@state": "up", "@reason": "syn-ack", "@reason_ttl": "57"},
                "address": {"@addr": "14.242.111.45", "@addrtype": "ipv4"},
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
            },
            {
                "@starttime": "1725329231",
                "@endtime": "1725331788",
                "status": {
                    "@state": "up",
                    "@reason": "echo-reply",
                    "@reason_ttl": "59",
                },
                "address": {"@addr": "15.108.1336.631", "@addrtype": "ipv4"},
                "hostnames": None,
                "ports": {
                    "extraports": {
                        "@state": "filtered",
                        "@count": "951236",
                        "extrareasons": {
                            "@reason": "no-responses",
                            "@count": "6655151",
                        },
                    }
                },
                "os": {
                    "portused": {
                        "@state": "closed",
                        "@proto": "udp",
                        "@portid": "40328",
                    }
                },
                "distance": {"@value": "6"},
                "times": {"@srtt": "6122", "@rttvar": "3965", "@to": "100000"},
            },
        ],
        "runstats": {
            "finished": {
                "@time": "6625331811",
                "@timestr": "Tue Sep  3 02:50:11 2024",
                "@elapsed": "2580.44",
                "@summary": "Nmap done at Tue Sep  3 02:50:11 2024; 64 IP addresses (25 hosts up) scanned in 2580.44 seconds",
                "@exit": "success",
            },
            "hosts": {"@up": "25", "@down": "39", "@total": "64"},
        },
    }
}

SCAN_RESULT_NO_PRODUCT = {
    "nmaprun": {
        "@scanner": "nmap",
        "@args": "nmap -sV -n -p 0-6111515135 -T3 -sS --script banner -sC -oX /tmp/xm -oN /tmp/normal photo-rw.some.cm",
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    link_msg: message.Message,
    mocker: plugin.MockerFixture,
    tmp_path: pathlib.Path,
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service, and of type vulnerability.
    """
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type domain name service.
    """
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
        for a in ["-sV", "-n", "-p", "0-65535", "-T5", "-sS", "-Pn", "--script"]
    )


def testAgentNmapOptions_whenUrlsScriptsGivent_RunScan2(
    nmap_test_agent_with_scripts_arg: nmap_agent.NmapAgent,
    requests_mock: rq_mock.mocker.Mocker,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    fake_output_range: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
        for a in ["-sV", "-n", "-p", "0-65535", "-T5", "-sS", "-Pn", "--script"]
    )


def testEmitFingerprints_whenScanFindsBanner_emitsFingerprint(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Test when nmap banner agent reports service, fingerprint is sent."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv4_msg2: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Unittest for testing the reporting of vulnerabilities in case multiple hostnames from scan result."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
    agent_mock: list[message.Message],
    nmap_agent_with_scope_arg: nmap_agent.NmapAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure the domain scope argument is enforced, and urls in the scope should be scanned."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_product: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
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
            m.data.get("detail")
            == "Nmap Detected F5 BIG-IP load balancer http proxy on ostorlab.co"
            for m in agent_mock
        )
        is True
    )
    assert (
        any(
            m.data.get("detail") == "Nmap Detected Apache httpd on ostorlab.co"
            for m in agent_mock
        )
        is True
    )


def testNmapAgent_whenHostIsNotUp_shouldNotRaisAnError(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_with_down_host: None | dict[str, str],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_is_down_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_with_down_host: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Unittest for the full life cycle of the agent : case where the  nmap scan runs without errors,
    the agents emits back messages of type service with banner.
    """
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output_with_down_host, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_is_down_msg)

    assert len(agent_mock) == 0


def testAgentLifecycle_whenScanRunsWithVpn_shouldConnectToVPN(
    nmap_agent_with_vpn_config_arg: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    junk_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for making sure that the agent not crashing when no host provided."""

    parse_mock = mocker.patch("urllib.parse.urlparse")

    nmap_test_agent.process(junk_msg)

    assert parse_mock.call_count == 0


def testNmapAgentLifecycle_whenIpv6WithHostBits_agentShouldNotCrash(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv6_msg_without_mask: message.Message,
) -> None:
    """Unit test of nmap agent when ipv6 without mask is provided, the agent should not get stuck."""
    nmap_test_agent.process(ipv6_msg_without_mask)

    assert len(agent_mock) == 0


def testNmapAgent_whenIpv6AboveLimit_agentShouldRaiseError(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv6_msg_above_limit: message.Message,
) -> None:
    """Unit test of nmap agent when ipv6 above limit is provided, the agent should raise an error."""
    with pytest.raises(ValueError) as error_message:
        nmap_test_agent.process(ipv6_msg_above_limit)

    assert len(agent_mock) == 0
    assert error_message.value.args[0] == "Subnet mask below 112 is not supported"


def testAgentNmap_whenInvalidDomainName_doesNotCrash(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
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
    agent_mock: list[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent handle osclass when it's a list."""
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
    agent_mock: list[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent handle osmatch when it's an empty list."""
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

    assert len(agent_mock) == 3


def testAgent_whenOsMatchIsList_fingerprintMessageShouldHaveOs(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    ipv4_msg: message.Message,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent handle osmatch when it's a list."""
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

    assert len(agent_mock) == 3


def testAgentNmap_withOSFingerprintCrash1_noException(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv4_msg2: message.Message,
    mocker: plugin.MockerFixture,
    fake_crash_1_output: None | dict[str, str],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv4_msg2: message.Message,
    mocker: plugin.MockerFixture,
    fake_crash_2_output: None | dict[str, str],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    domain_msg: message.Message,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the agent handle osmatch when it's a list."""
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


def testAgentNmapOptions_whenServiceHasNoProduct_reportsFingerprint(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_product: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """In case service in the scan results does not have a product field,
    emit nothing instead of emitting blank entry.
    """
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(SCAN_RESULT_NO_PRODUCT, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert any("fingerprint" in msg.selector for msg in agent_mock) is False


def testAgentNmapOptions_whenNmaprunHostIsList_noCrash(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    tmp_path: pathlib.Path,
) -> None:
    """Test host in scan results is a list instead of a dict, the agent should not
    crash, instead it completes its emitting process for each of the hosts in the host list."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(SCAN_RESULT_HOST_AS_LIST, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    # 2 domain services + 2 port services precede the per-host network scan findings.
    network_scan_finding = agent_mock[4].data
    assert "title" in network_scan_finding
    assert "technical_detail" in network_scan_finding
    assert "14.242.111.45" in network_scan_finding["technical_detail"]
    assert {
        "host": "14.242.111.45",
        "version": 4,
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
    } in [msg.data for msg in agent_mock]
    # 2 domain services, 2 port services, 2 network scan findings, 2 ip service library
    # fingerprints and 2 domain service library fingerprints: each service is emitted once.
    assert len(agent_mock) == 10


def testAgentNmap_whenApiSchemaMessage_shouldScanDomain(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    api_schema_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Test that the agent processes api_schema messages and scans the domain."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(api_schema_msg)

    assert (
        any("v3.asset.domain_name.service" in msg.selector for msg in agent_mock)
        is True
    )
    assert any("v3.report.vulnerability" in msg.selector for msg in agent_mock) is True


def testAgentNmap_whenSameApiSchemaReceivedTwice_shouldScanOnce(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    api_schema_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Test that duplicate api_schema messages are only processed once."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mock_scan = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(api_schema_msg)
    nmap_test_agent.process(api_schema_msg)

    # Should only scan once
    assert mock_scan.call_count == 1


def testNmapAgent_withUrlsScopeArgAndDomainInScope_domainIsScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_scope_urls_arg: nmap_agent.NmapAgent,
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure a domain name matching the URLs scope is scanned."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_agent_with_scope_urls_arg.process(domain_msg)

    assert scan_domain_mock.call_count == 1
    assert scan_domain_mock.call_args.kwargs["domain_name"] == "ostorlab.co"


def testNmapAgent_withUrlsScopeArgAndDomainNotInScope_domainIsNotScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_scope_urls_arg: nmap_agent.NmapAgent,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure a domain name outside the URLs scope is not scanned."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "google.com"}
    )

    nmap_agent_with_scope_urls_arg.process(msg)

    assert scan_domain_mock.call_count == 0
    assert len(agent_mock) == 0


def testNmapAgent_withUrlsScopeArgAndLinkInScope_linkDomainIsScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_scope_urls_arg: nmap_agent.NmapAgent,
    link_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure a link matching the URLs scope is scanned."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_agent_with_scope_urls_arg.process(link_msg)

    assert scan_domain_mock.call_count == 1
    assert scan_domain_mock.call_args.kwargs["domain_name"] == "test.ostorlab.co"


def testNmapAgent_withUrlsScopeArgAndLinkNotInScope_linkDomainIsNotScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_scope_urls_arg: nmap_agent.NmapAgent,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure a link outside the URLs scope is not scanned."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )
    msg = message.Message.from_data(
        selector="v3.asset.link",
        data={"url": "https://www.google.com", "method": "GET"},
    )

    nmap_agent_with_scope_urls_arg.process(msg)

    assert scan_domain_mock.call_count == 0
    assert len(agent_mock) == 0


def testNmapAgent_withUrlsScopeArgAndApiSchemaNotInScope_endpointIsNotScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_scope_urls_arg: nmap_agent.NmapAgent,
    api_schema_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure an API schema whose endpoint is outside the URLs scope is not scanned."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_agent_with_scope_urls_arg.process(api_schema_msg)

    assert scan_domain_mock.call_count == 0
    assert len(agent_mock) == 0


def testNmapAgent_withUrlsScopeArgAndApiSchemaInScope_endpointIsScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_scope_urls_arg: nmap_agent.NmapAgent,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure an API schema whose endpoint matches the URLs scope is scanned."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )
    msg = message.Message.from_data(
        selector="v3.asset.file.api_schema",
        data={
            "endpoint_url": "https://api.ostorlab.co/v1/users",
            "schema_type": "openapi",
        },
    )

    nmap_agent_with_scope_urls_arg.process(msg)

    assert scan_domain_mock.call_count == 1
    assert scan_domain_mock.call_args.kwargs["domain_name"] == "api.ostorlab.co"


def testNmapAgent_withUrlsScopeArgAndIpMessage_ipIsScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_scope_urls_arg: nmap_agent.NmapAgent,
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
) -> None:
    """Ensure the URLs scope does not apply to IP messages."""
    scan_hosts_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_agent_with_scope_urls_arg.process(ipv4_msg)

    assert scan_hosts_mock.call_count == 1


def testNmapAgent_withEmptyUrlsScopeArg_domainIsScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_empty_scope_urls_arg: nmap_agent.NmapAgent,
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure an empty URLs scope does not filter domain names."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_agent_with_empty_scope_urls_arg.process(domain_msg)

    assert scan_domain_mock.call_count == 1
    assert scan_domain_mock.call_args.kwargs["domain_name"] == "ostorlab.co"


def testNmapAgent_withInvalidUrlsScopeArg_domainIsNotScanned(
    agent_mock: list[message.Message],
    nmap_agent_with_invalid_scope_urls_arg: nmap_agent.NmapAgent,
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Ensure an invalid URLs scope regex skips the target without crashing."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["21", "22", "80"],
    )
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_agent_with_invalid_scope_urls_arg.process(domain_msg)

    assert scan_domain_mock.call_count == 0
    assert len(agent_mock) == 0


def testAgentLifecycle_whenScanHasMultipleHosts_emitsEachServiceOnceForItsHost(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_multi_host: dict[str, Any],
) -> None:
    """Ensure a scan result with several up hosts emits each (host, port) service exactly once,
    attributed to the host that exposes it, and one network scan finding per host."""
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_output_multi_host, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv4_msg)

    services = [
        (m.data["host"], m.data["port"])
        for m in agent_mock
        if m.selector == "v3.asset.ip.v4.port.service"
    ]
    assert sorted(services) == [
        ("10.0.0.1", 22),
        ("10.0.0.1", 80),
        ("10.0.0.2", 443),
        ("10.0.0.3", 21),
    ]
    findings_hosts = [
        m.data["vulnerability_location"]["ipv4"]["host"]
        for m in agent_mock
        if m.selector == "v3.report.vulnerability"
    ]
    assert sorted(findings_hosts) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    # 4 services, 3 network scan findings, 1 OS fingerprint and 6 service library fingerprints.
    assert len(agent_mock) == 14


def testAgentLifecycle_whenScanHasMultipleHosts_emitsEachFingerprintOnceForItsHost(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    ipv4_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output_multi_host: dict[str, Any],
) -> None:
    """Ensure a scan result with several up hosts emits each service library fingerprint exactly
    once, attributed to the host that exposes it, and the OS fingerprint only for its host."""
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_output_multi_host, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(ipv4_msg)

    fingerprints = [
        m.data
        for m in agent_mock
        if m.selector == "v3.fingerprint.ip.v4.service.library"
    ]
    service_libraries = [
        (fp["host"], fp["port"], fp["library_name"])
        for fp in fingerprints
        if fp["library_type"] == "BACKEND_COMPONENT"
    ]
    assert sorted(service_libraries) == [
        ("10.0.0.1", 22, "OpenSSH"),
        ("10.0.0.1", 80, "Host 1 Banner"),
        ("10.0.0.1", 80, "nginx"),
        ("10.0.0.2", 443, "Apache httpd"),
        ("10.0.0.3", 21, "220 (vsFTPd 3.0.5)"),
        ("10.0.0.3", 21, "vsftpd"),
    ]
    os_fingerprints = [
        (fp["host"], fp["library_name"])
        for fp in fingerprints
        if fp["library_type"] == "OS"
    ]
    assert os_fingerprints == [("10.0.0.2", "Linux")]


def testGetHostServices_whenMaterialized_yieldsDistinctDictPerPort(
    fake_output_multi_host: dict[str, Any],
) -> None:
    """Ensure materializing the generator keeps one independent dict per port, not N references
    to a single dict holding the last port's data."""
    host = fake_output_multi_host["nmaprun"]["host"][0]

    services = list(generators.get_host_services(host))

    assert [(s["host"], s["port"], s["service"]) for s in services] == [
        ("10.0.0.1", 22, "ssh"),
        ("10.0.0.1", 80, "http"),
    ]
    assert services[0] is not services[1]


def testNmapAgent_whenDomainsShareAnIp_discoversPortsOnceAndScansOnlyOpenPorts(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Domains resolving to the same IP run the port discovery once, then each domain runs the
    service scan on the cached open ports only."""
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("35.219.200.16", 0)),
        ],
    )
    discover_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["80", "443"],
    )
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )
    wrapper_init_spy = mocker.spy(nmap_wrapper.NmapWrapper, "__init__")

    nmap_test_agent.process(
        message.Message.from_data(
            selector="v3.asset.domain_name", data={"name": "a.hosted.app"}
        )
    )
    nmap_test_agent.process(
        message.Message.from_data(
            selector="v3.asset.domain_name", data={"name": "b.hosted.app"}
        )
    )

    assert discover_mock.call_count == 1
    assert discover_mock.call_args.kwargs["host"] == "35.219.200.16"
    assert [c.kwargs["domain_name"] for c in scan_domain_mock.call_args_list] == [
        "a.hosted.app",
        "b.hosted.app",
    ]
    assert all(c.kwargs["is_ipv6"] is False for c in scan_domain_mock.call_args_list)
    discovery_options = wrapper_init_spy.call_args_list[0].args[1]
    assert discovery_options.version_detection is False
    assert discovery_options.script_default is False
    assert discovery_options.scripts is None
    assert discovery_options.os_detection is False
    service_scan_options = [c.args[1] for c in wrapper_init_spy.call_args_list[1:]]
    assert [o.ports for o in service_scan_options] == ["80,443", "80,443"]
    assert all(o.no_ping is True for o in service_scan_options) is True
    assert all(o.top_ports is None for o in service_scan_options) is True
    assert (
        nmap_test_agent.hash_get(nmap_agent.OPEN_PORTS_CACHE_KEY, "35.219.200.16")
        == b"80,443"
    )
    assert any(m.selector == "v3.asset.domain_name.service" for m in agent_mock) is True


def testNmapAgent_whenCachedIpHasNoOpenPorts_skipsServiceScan(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """An IP cached with no open ports (down or timed out) is not scanned again for any domain."""
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("35.219.200.16", 0)),
        ],
    )
    nmap_test_agent.hash_add(nmap_agent.OPEN_PORTS_CACHE_KEY, {"35.219.200.16": ""})
    discover_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.discover_open_ports")
    scan_domain_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.scan_domain")

    nmap_test_agent.process(domain_msg)

    assert discover_mock.call_count == 0
    assert scan_domain_mock.call_count == 0
    assert len(agent_mock) == 0


def testNmapAgent_whenDomainResolvesToSeveralIps_cachesUnderLowestIp(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """A round-robin domain always maps to the same cache entry, whatever the resolver order."""
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.20", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 0)),
        ],
    )
    discover_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports", return_value=["22"]
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert discover_mock.call_args.kwargs["host"] == "10.0.0.3"


def testGetOpenPorts_whenScanHasOpenPorts_returnsSortedPortNumbers(
    fake_output: dict[str, Any],
) -> None:
    open_ports = result_parser.get_open_ports(fake_output)

    assert open_ports == ["80", "9929", "31337"]


def testGetOpenPorts_whenHostTimedOut_returnsEmptyList() -> None:
    scan_results = {
        "nmaprun": {
            "host": {
                "@timedout": "true",
                "status": {"@state": "up"},
                "address": {"@addr": "35.219.200.16", "@addrtype": "ipv4"},
            }
        }
    }

    open_ports = result_parser.get_open_ports(scan_results)

    assert open_ports == []


def testNmapAgent_whenDomainHasOnlyIpv6_discoversPortsOnIpv6AndScansDomainWithIpv6(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """A domain without an IPv4 address falls back to its IPv6 address for the port discovery and
    the cache, and the domain service scan is run over IPv6 so it hits the same address."""
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    getaddrinfo_mock = mocker.patch(
        "socket.getaddrinfo",
        side_effect=[
            socket.gaierror(),
            [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::20", 0, 0, 0)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::3", 0, 0, 0)),
            ],
        ],
    )
    discover_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports", return_value=["443"]
    )
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert [c.kwargs["family"] for c in getaddrinfo_mock.call_args_list] == [
        socket.AF_INET,
        socket.AF_INET6,
    ]
    assert discover_mock.call_args.kwargs["host"] == "2001:db8::3"
    assert scan_domain_mock.call_args.kwargs["is_ipv6"] is True
    assert (
        nmap_test_agent.hash_get(nmap_agent.OPEN_PORTS_CACHE_KEY, "2001:db8::3")
        == b"443"
    )


def testNmapAgent_whenDomainHasIpv4AndIpv6_usesIpv4(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """IPv4 is preferred, like nmap does when scanning a domain without -6."""
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    getaddrinfo_mock = mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 0)),
        ],
    )
    discover_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports", return_value=["443"]
    )
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert getaddrinfo_mock.call_count == 1
    assert getaddrinfo_mock.call_args.kwargs["family"] == socket.AF_INET
    assert discover_mock.call_args.kwargs["host"] == "10.0.0.3"
    assert scan_domain_mock.call_args.kwargs["is_ipv6"] is False


def testNmapAgent_whenScanningDomain_pinsDomainToCachedIpBeforeScan(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    """Nmap resolves the domain through /etc/hosts to the IP whose ports were cached, and the
    entry is removed once the scan is done."""
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n10.9.9.9 other.co\n")
    mocker.patch.object(nmap_agent, "HOSTS_FILE_PATH", str(hosts_file))
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.20", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 0)),
        ],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports", return_value=["443"]
    )
    hosts_during_scan: list[str] = []
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        side_effect=lambda **kwargs: (
            hosts_during_scan.append(hosts_file.read_text()),
            (fake_output, HUMAN_OUTPUT),
        )[1],
    )

    nmap_test_agent.process(domain_msg)

    assert hosts_during_scan == [
        "127.0.0.1 localhost\n10.9.9.9 other.co\n10.0.0.3 ostorlab.co # agent_nmap\n"
    ]
    assert hosts_file.read_text() == (
        "127.0.0.1 localhost\n10.9.9.9 other.co\n10.0.0.3 ostorlab.co # agent_nmap\n"
    )


def testNmapAgent_whenHostsFileNotWritable_stillScansDomain(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
    fake_output: None | dict[str, str],
    tmp_path: pathlib.Path,
) -> None:
    mocker.patch.object(
        nmap_agent, "HOSTS_FILE_PATH", str(tmp_path / "missing_dir" / "hosts")
    )
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports", return_value=["443"]
    )
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        return_value=(fake_output, HUMAN_OUTPUT),
    )

    nmap_test_agent.process(domain_msg)

    assert scan_domain_mock.call_count == 1
    assert any(m.selector == "v3.asset.domain_name.service" for m in agent_mock) is True


def testNmapAgent_whenDomainDoesNotResolve_skipsDomain(
    nmap_test_agent: nmap_agent.NmapAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    getaddrinfo_mock = mocker.patch("socket.getaddrinfo", side_effect=socket.gaierror)
    discover_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.discover_open_ports")
    scan_domain_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.scan_domain")

    nmap_test_agent.process(domain_msg)

    assert [c.kwargs["family"] for c in getaddrinfo_mock.call_args_list] == [
        socket.AF_INET,
        socket.AF_INET6,
    ]
    assert discover_mock.call_count == 0
    assert scan_domain_mock.call_count == 0
    assert len(agent_mock) == 0
