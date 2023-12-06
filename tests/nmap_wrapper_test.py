"""Nmap wrapper unit tests"""

import agent.nmap_agent
from agent import nmap_options
from agent import nmap_wrapper


def testNmapWrapper_whenFastMode_returnCommand(
    nmap_agent_fast_mode: agent.nmap_agent.NmapAgent,
) -> None:
    args = nmap_agent_fast_mode.args
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

    assert command == [
        "nmap",
        "-sV",
        "-n",
        "-F",
        "-T3",
        "-sT",
        "--script",
        "banner",
        "-sC",
        "-oX",
        "/tmp/xmloutput",
        "-oN",
        "/tmp/normal",
        "127.0.0.1/24",
    ]


def testNmapWrapper_whenTopPortsUsed_returnCommand(
    nmap_agent_top_ports: agent.nmap_agent.NmapAgent,
) -> None:
    args = nmap_agent_top_ports.args
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

    assert command == [
        "nmap",
        "-sV",
        "-n",
        "--top-ports",
        "420",
        "-T3",
        "-sT",
        "--script",
        "banner",
        "-sC",
        "-oX",
        "/tmp/xmloutput",
        "-oN",
        "/tmp/normal",
        "127.0.0.1/24",
    ]


def testNmapWrapper_whenAllTopPortsUsed_returnCommand(
    nmap_agent_all_ports: agent.nmap_agent.NmapAgent,
) -> None:
    args = nmap_agent_all_ports.args
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

    assert command == [
        "nmap",
        "-sV",
        "-n",
        "-p",
        "0-65535",
        "-T3",
        "-sT",
        "--script",
        "banner",
        "-sC",
        "-oX",
        "/tmp/xmloutput",
        "-oN",
        "/tmp/normal",
        "127.0.0.1/24",
    ]
