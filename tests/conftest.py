"""Pytest fixture for the nmap agent."""

import os
import pathlib
import json
from typing import Any, Dict, Union, List

import pytest
import xmltodict
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message
from ostorlab.utils import defintions as utils_definitions

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
def fake_output_product() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "nmap_product_output.xml"),
        "r",
        encoding="utf-8",
    ) as o:
        return xmltodict.parse(o.read())


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
def domain_is_down_msg() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name for testing purposes."""
    return message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "ostorlab.co"}
    )


@pytest.fixture(scope="function", name="nmap_test_agent")
def fixture_agent(
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
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
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
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
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
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
def nmap_agent_with_vpn_config_arg(
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
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
def invalid_ipv6_msg() -> message.Message:
    """Creates an invalid IPv6 message for testing error handling."""
    return message.Message.from_data(
        selector="v3.asset.ip.v6",
        data={
            "version": 6,
            "host": "invalid_ipv6",
            "mask": "112",
        },
    )


@pytest.fixture
def large_subnet_ipv6_msg() -> message.Message:
    """Creates a message with a large IPv6 subnet."""
    return message.Message.from_data(
        selector="v3.asset.ip.v6",
        data={
            "version": 6,
            "host": "2600:3c01:224a:6e00::",
            "mask": "112",
        },
    )


@pytest.fixture
def ipv6_msg_above_limit() -> message.Message:
    """Creates a message with an IPv6 subnet above the allowed limit (below mask 112)."""
    return message.Message.from_data(
        selector="v3.asset.ip.v6",
        data={
            "version": 6,
            "host": "2600:3c01:224a:6e00::",
            "mask": "96",  # Below IPV6_CIDR_LIMIT of 112
        },
    )


@pytest.fixture(scope="function")
def nmap_agent_fast_mode(
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
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
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
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
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
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
