"""Fixtures for KB generator tests."""

import os


def pytest_configure() -> None:
    os.environ["OPENAI_API_KEY"] = "mocked_value"
