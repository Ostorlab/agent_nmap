"""Pytest fixture for the nmap agent."""
import os
import pytest
import pathlib

from ostorlab.agent import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import nmap_agent as agent

import xmltodict
import json
import random


@pytest.fixture
def fake_output():
    with open(os.path.join(os.path.dirname(__file__), 'fake_output.xml'), 'r', encoding='utf-8') as o:
        return xmltodict.parse(o.read())


@pytest.fixture
def scan_message():
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '209.235.136.112',
        'mask': '32',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def nmap_agent_args():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/agent_nmap',
            bus_url='NM',
            bus_exchange_topic='NM',
            args=[
                utils_definitions.Arg(
                    name='scripts',
                    type='array',
                    value=json.dumps(['https://raw.githubusercontent.com/pyzcool/nmap-scripts/main/test1',
                                      'https://raw.githubusercontent.com/pyzcool/nmap-scripts/main/test2']).encode())],
            healthcheck_port=random.randint(5000, 6000),
            redis_url='redis://guest:guest@localhost:6379')

        agent_object = agent.NmapAgent(definition, settings)
        return agent_object
