"""Nmap wrapper unit tests"""

import xml
import pathlib

import pytest

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
        "-O",
        "-sV",
        "-n",
        "-F",
        "-T3",
        "-sS",
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
        "-O",
        "-sV",
        "-n",
        "--top-ports",
        "420",
        "-T3",
        "-sS",
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
        "-O",
        "-sV",
        "-n",
        "-p",
        "0-65535",
        "-T3",
        "-sS",
        "--script",
        "banner",
        "-sC",
        "-oX",
        "/tmp/xmloutput",
        "-oN",
        "/tmp/normal",
        "127.0.0.1/24",
    ]


def testNmapWrapperParseOutput_whenXmlIsInvalid_catchesAndReraisesError() -> None:
    """Tests parsing invalid XML output scan results. Should catch the error and re-raise it."""
    invalid_xml = (pathlib.Path(__file__).parent / "malformed_output.xml").read_text()
    parsed_output = None

    with pytest.raises(xml.parsers.expat.ExpatError):
        parsed_output = nmap_wrapper.parse_output(invalid_xml)

    assert parsed_output is None


def testNmapWrapperParseOutput_whenXmlIsValid_returnsParsedXml() -> None:
    """Checks that XML output scan results are correctly parsed to a dict."""
    valid_xml = (
        pathlib.Path(__file__).parent / "fake_output_with_down_host.xml"
    ).read_text()
    parsed_output = nmap_wrapper.parse_output(valid_xml)

    assert {
        "nmaprun": {
            "@scanner": "nmap",
            "@args": "nmap -sV -n -F -T5 -sT -sU -script banner -sC -oX /tmp/xmloutput -oN /tmp/normal des.zappos",
            "@start": "1675420948",
            "@startstr": "Fri Feb  3 11:42:28 2023",
            "@version": "7.80",
            "@xmloutputversion": "1.04",
            "scaninfo": [
                {
                    "@type": "connect",
                    "@protocol": "tcp",
                    "@numservices": "100",
                    "@services": "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,"
                    "427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,"
                    "1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,"
                    "5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,"
                    "8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157",
                },
                {
                    "@type": "udp",
                    "@protocol": "udp",
                    "@numservices": "100",
                    "@services": "7,9,17,19,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,"
                    "514-515,518,520,593,623,626,631,996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,"
                    "1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,3283,3456,3703,4444,4500,5000,5060,"
                    "5353,5632,9200,10000,17185,20031,30718,31337,32768-32769,32771,32815,33281,"
                    "49152-49154,49156,49181-49182,49185-49186,49188,49190-49194,49200-49201,65024",
                },
            ],
            "verbose": {"@level": "0"},
            "debugging": {"@level": "0"},
            "runstats": {
                "finished": {
                    "@time": "1675420948",
                    "@timestr": "Fri Feb  3 11:42:28 2023",
                    "@elapsed": "0.37",
                    "@summary": "Nmap done at Fri Feb  3 11:42:28 2023; 0 IP addresses (0 hosts up) scanned in 0.37 "
                    "seconds",
                    "@exit": "success",
                },
                "hosts": {"@up": "0", "@down": "0", "@total": "0"},
            },
        }
    } == parsed_output
