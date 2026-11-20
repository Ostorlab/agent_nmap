"""Pytest fixture for the nmap agent."""

import json
import os
import pathlib
import socket
from typing import Any
from unittest import mock

import pytest
import xmltodict
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import definitions as utils_definitions
from pytest_mock import plugin

from agent import nmap_agent

VPN_CONFIG = """[Interface]
# Bouncing = 
# NetShield = 
# NAT modéré = 
# NAT-PMP (transfert de port) =
# VPN Accelerator = 
PrivateKey = 
Address = 
DNS = \n
[Peer]

PublicKey =
AllowedIPs = 
Endpoint = 
"""

DNS_CONFIG = """
nameserver 127.0.0.11
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 8.8.4.4
"""


@pytest.fixture
def fake_output() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def fake_crash_1_output() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output_crash_1.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def fake_crash_2_output() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output_crash_2.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def fake_output_with_down_host() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output_with_down_host.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def fake_output_range() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output_range.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def fake_output_multi_host() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output_multi_host.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def fake_output_product() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "nmap_product_output.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def fake_output_domain_addresses() -> Any:
    """Scan of a domain name resolving to two IPv4 and one IPv6 address, each serving http and http over TLS."""
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output_domain_addresses.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def scan_of_each_domain_address(
    mocker: plugin.MockerFixture,
    tmp_path: pathlib.Path,
    fake_output_domain_addresses: dict[str, Any],
) -> mock.MagicMock:
    """Resolves the domain name to the addresses of the fake output, and makes the nmap scan of each
    address return its own host. Returns the mock of the nmap domain scan."""
    hosts = fake_output_domain_addresses["nmaprun"]["host"]
    addresses = [host["address"] for host in hosts]
    mocker.patch("agent.domain_scan.HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mocker.patch(
        "socket.getaddrinfo",
        side_effect=[
            [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (a["@addr"], 0))
                for a in addresses
                if a["@addrtype"] == "ipv4"
            ],
            [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (a["@addr"], 0, 0, 0))
                for a in addresses
                if a["@addrtype"] == "ipv6"
            ],
        ],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        return_value=["80", "443"],
    )
    scan_domain_mock: mock.MagicMock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain",
        side_effect=[
            ({"nmaprun": {"host": host}}, f"Nmap scan report for {address['@addr']}")
            for host, address in zip(hosts, addresses)
        ],
    )
    return scan_domain_mock


@pytest.fixture
def no_host_domain_scan_xml() -> str:
    """Nmap XML output of a domain name scan run that found no host up."""
    return (
        '<nmaprun scanner="nmap" args="nmap -sV -n -p 443 -Pn example.com" '
        'version="7.94" xmloutputversion="1.05">'
        '<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>'
        '<verbose level="0"/><debugging level="0"/>'
        '<runstats><finished elapsed="0.05" exit="success" '
        'summary="0 IP addresses (0 hosts up) scanned in 0.05 seconds"/>'
        '<hosts up="0" down="0" total="0"/></runstats></nmaprun>'
    )


@pytest.fixture
def ipv4_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.ip.v4",
        data={"version": 4, "host": "127.0.0.1", "mask": "32"},
    )


@pytest.fixture
def ipv4_msg2() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.ip.v4",
        data={"version": 4, "host": "192.168.0.0", "mask": "30"},
    )


@pytest.fixture
def ipv4_msg_with_mask() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 with a mask for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.ip.v4",
        data={"version": 4, "host": "10.10.10.0", "mask": "24"},
    )


@pytest.fixture
def link_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.link for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.link",
        data={"url": "https://test.ostorlab.co", "method": "GET"},
    )


@pytest.fixture
def domain_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
    )


@pytest.fixture
def api_schema_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.file.api_schema for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.file.api_schema",
        data={
            "endpoint_url": "https://api.example.com/v1/users",
            "schema_type": "openapi",
        },
    )


@pytest.fixture
def domain_is_down_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
    )


@pytest.fixture(scope="function", name="nmap_test_agent")
def fixture_agent(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Fixture of the Nmap Agent to be used for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nmap_agent",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = nmap_agent.NmapAgent(definition, settings)
        return agent


@pytest.fixture(scope="function")
def nmap_test_agent_with_scripts_arg(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Fixture of the Nmap Agent to be used for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nmap_agent",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="scripts",
                    type="array",
                    value=json.dumps(
                        [
                            "https://raw.githubusercontent.com/nmap-scripts/main/test1",
                            "https://raw.githubusercontent.com/nmap-scripts/main/test2",
                        ]
                    ).encode(),
                )
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = nmap_agent.NmapAgent(definition, settings)
        return agent


@pytest.fixture(scope="function")
def nmap_agent_with_scope_arg(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Nmap Agent fixture with  domain scope argument for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key="nmap",
            redis_url="redis://redis",
            args=[
                utils_definitions.Arg(
                    name="scope_domain_regex",
                    type="string",
                    value=json.dumps(".*ostorlab.co").encode(),
                ),
            ],
        )
        return nmap_agent.NmapAgent(agent_definition, agent_settings)


@pytest.fixture(scope="function")
def nmap_agent_with_scope_urls_arg(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Nmap Agent fixture with URLs scope argument for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key="nmap",
            redis_url="redis://redis",
            args=[
                utils_definitions.Arg(
                    name="scope_urls_regex",
                    type="string",
                    value=json.dumps(
                        r"https?://([a-z0-9-]+\.)*ostorlab\.co(/.*)?$"
                    ).encode(),
                ),
            ],
        )
        return nmap_agent.NmapAgent(agent_definition, agent_settings)


def _build_nmap_agent_with_scope_urls_regex(
    scope_urls_regex: str,
) -> nmap_agent.NmapAgent:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key="nmap",
            redis_url="redis://redis",
            args=[
                utils_definitions.Arg(
                    name="scope_urls_regex",
                    type="string",
                    value=json.dumps(scope_urls_regex).encode(),
                ),
            ],
        )
        return nmap_agent.NmapAgent(agent_definition, agent_settings)


@pytest.fixture(scope="function")
def nmap_agent_with_empty_scope_urls_arg(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Nmap Agent fixture with an empty URLs scope argument."""
    del agent_persist_mock
    return _build_nmap_agent_with_scope_urls_regex("")


@pytest.fixture(scope="function")
def nmap_agent_with_invalid_scope_urls_arg(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Nmap Agent fixture with an invalid URLs scope regular expression."""
    del agent_persist_mock
    return _build_nmap_agent_with_scope_urls_regex("(")


@pytest.fixture(scope="function")
def nmap_agent_with_vpn_config_arg(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Nmap Agent fixture with  domain scope argument for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key="nmap",
            redis_url="redis://redis",
            args=[
                utils_definitions.Arg(
                    name="vpn_config",
                    type="string",
                    value=json.dumps(VPN_CONFIG).encode(),
                ),
                utils_definitions.Arg(
                    name="dns_config",
                    type="string",
                    value=json.dumps(DNS_CONFIG).encode(),
                ),
            ],
        )
        return nmap_agent.NmapAgent(agent_definition, agent_settings)


@pytest.fixture
def junk_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.ip",
        data={"version": 4, "host": "0.0.0.0"},
    )


@pytest.fixture
def ipv6_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v6 for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.ip.v6",
        data={
            "version": 6,
            "host": "2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f",
            "mask": "112",
        },
    )


@pytest.fixture
def ipv6_msg_without_mask() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v6 for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.ip.v6",
        data={
            "version": 6,
            "host": "2001:470:1:18:1000::46",
        },
    )


@pytest.fixture
def ipv6_msg_above_limit() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v6 for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.ip.v6",
        data={
            "version": 6,
            "host": "2600:3c01:224a:6e00:f03c:91ff:fe18:bb2f",
            "mask": "64",
        },
    )


@pytest.fixture(scope="function")
def nmap_agent_fast_mode(
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Fixture of the Nmap Agent to be used for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nmap_agent",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="fast_mode",
                    type="boolean",
                    value=json.dumps(True).encode(),
                )
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = nmap_agent.NmapAgent(definition, settings)
        return agent


@pytest.fixture(scope="function")
def nmap_agent_top_ports(
    request: Any,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Fixture of the Nmap Agent to be used for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nmap_agent",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="fast_mode",
                    type="boolean",
                    value=json.dumps(False).encode(),
                ),
                utils_definitions.Arg(
                    name="top_ports",
                    type="number",
                    value=json.dumps("420").encode(),
                ),
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = nmap_agent.NmapAgent(definition, settings)
        return agent


@pytest.fixture(scope="function")
def nmap_agent_all_ports(
    request: Any,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> nmap_agent.NmapAgent:
    """Fixture of the Nmap Agent to be used for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/nmap_agent",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="fast_mode",
                    type="boolean",
                    value=json.dumps(False).encode(),
                )
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = nmap_agent.NmapAgent(definition, settings)
        return agent


@pytest.fixture
def invalid_domain_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "-ostorlab.co"}
    )
