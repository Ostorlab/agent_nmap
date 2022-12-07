"""Pytest fixture for the nmap agent."""
import os
import pytest
from typing import Any

import xmltodict


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
