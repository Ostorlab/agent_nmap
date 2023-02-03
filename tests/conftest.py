"""Pytest fixture for the nmap agent."""
import os
import pathlib
import json
from typing import Any, Union, Dict

import xmltodict
import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions

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
def fake_output_2() -> Any:
    with open(
        os.path.join(os.path.dirname(__file__), "fake_output_2.xml"),
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


@pytest.fixture(scope="function")
def nmap_agent_with_scope_arg(
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]]
) -> nmap_agent.NmapAgent:
    """Nmap Agent fixture with  domain scope argument for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key="nmap",
            redis_url="redis://redis",
            args=[
                defintions.Arg(
                    name="scope_domain_regex",
                    type="string",
                    value=json.dumps(".*ostorlab.co").encode(),
                ),
            ],
        )
        return nmap_agent.NmapAgent(agent_definition, agent_settings)
