"""Nmap wrapper unit tests"""
import pytest

import agent.nmap_agent
from agent import nmap_options
from agent import nmap_wrapper


@pytest.mark.parametrize(
    "nmap_parametrized_agent",
    [["fast_mode.yaml"]],
    indirect=True,
)
def testNmapWrapper_whenFastMode_returnCommand(
    nmap_parametrized_agent: agent.nmap_agent.NmapAgent,
) -> None:
    args = nmap_parametrized_agent.args
    options = nmap_options.NmapOptions(
        dns_resolution=False,
        ports=args.get("ports"),
        top_ports=args.get("top_ports"),
        fast_mode=args.get("fast_mode", False),
        no_ping=args.get("no_ping", False),
        timing_template=nmap_options.TimingTemplate[args["timing_template"]],
        scripts=args.get("scripts"),
        script_default=args.get("script_default", False),
        version_detection=args.get("version_info", False),
    )
    client = nmap_wrapper.NmapWrapper(options)

    command = client.construct_command_host("127.0.0.1", 24)

    assert "-F" in command


@pytest.mark.parametrize(
    "nmap_parametrized_agent",
    [["top_ports.yaml"]],
    indirect=True,
)
def testNmapWrapper_whenTopPortsUsed_returnCommand(
    nmap_parametrized_agent: agent.nmap_agent.NmapAgent,
) -> None:
    args = nmap_parametrized_agent.args
    options = nmap_options.NmapOptions(
        dns_resolution=False,
        ports=args.get("ports"),
        top_ports=args.get("top_ports"),
        fast_mode=args.get("fast_mode", False),
        no_ping=args.get("no_ping", False),
        timing_template=nmap_options.TimingTemplate[args["timing_template"]],
        scripts=args.get("scripts"),
        script_default=args.get("script_default", False),
        version_detection=args.get("version_info", False),
    )
    client = nmap_wrapper.NmapWrapper(options)

    command = client.construct_command_host("127.0.0.1", 24)

    assert "--top-ports" in command
    assert "420" in command


@pytest.mark.parametrize(
    "nmap_parametrized_agent",
    [["all_ports.yaml"]],
    indirect=True,
)
def testNmapWrapper_whenAllTopPortsUsed_returnCommand(
    nmap_parametrized_agent: agent.nmap_agent.NmapAgent,
) -> None:
    args = nmap_parametrized_agent.args
    options = nmap_options.NmapOptions(
        dns_resolution=False,
        ports=args.get("ports"),
        top_ports=args.get("top_ports"),
        fast_mode=args.get("fast_mode", False),
        no_ping=args.get("no_ping", False),
        timing_template=nmap_options.TimingTemplate[args["timing_template"]],
        scripts=args.get("scripts"),
        script_default=args.get("script_default", False),
        version_detection=args.get("version_info", False),
    )
    client = nmap_wrapper.NmapWrapper(options)

    command = client.construct_command_host("127.0.0.1", 24)

    assert "-p" in command
    assert "0-65535" in command