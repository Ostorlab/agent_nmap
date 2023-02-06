"""Pytest fixture for the nmap agent."""
import os
import pathlib
from typing import Any, Dict, Union

import pytest
import xmltodict
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message
from ostorlab.utils import defintions as utils_definitions

from agent import nmap_agent


@pytest.fixture
def fake_output() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output.xml"),
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


@pytest.fixture(scope="function", name="nmap_test_agent")
def fixture_agent(
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]]
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
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]]
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
