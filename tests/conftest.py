"""Pytest fixture for the nmap agent."""
import os
import pytest

import xmltodict



@pytest.fixture
def fake_output():
    with open(os.path.join(os.path.dirname(__file__), 'fake_output.xml'), 'r', encoding='utf-8') as o:
        return xmltodict.parse(o.read())

