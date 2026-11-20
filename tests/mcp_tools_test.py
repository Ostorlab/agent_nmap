"""Unittests for the MCP scan tool and runner."""

import pathlib
import socket
from typing import Any

import fastmcp
import pytest
from click import testing
from pytest_mock import plugin

from agent import domain_scan
from agent import nmap_wrapper
from agent.mcp import runner as mcp_runner
from agent.mcp import server as mcp_server
from agent.mcp import tools as mcp_tools


def testScan_whenDomainsShareAnIp_discoversPortsOnceAndScansOnlyOpenPorts(
    mocker: plugin.MockerFixture,
    agent_persist_mock: dict[str | bytes, Any],
    fake_output: dict[str, Any],
    tmp_path: pathlib.Path,
) -> None:
    scan = mcp_tools.NmapTools(redis_url="redis://localhost:6379").scan
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")
    mocker.patch.object(domain_scan, "HOSTS_FILE_PATH", str(hosts_file))
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 0))],
    )
    discover_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports", return_value=["80", "443"]
    )
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain", return_value=(fake_output, "")
    )
    wrapper_init_spy = mocker.spy(nmap_wrapper.NmapWrapper, "__init__")

    scan("a.example.com")
    services = scan("b.example.com")

    assert discover_mock.call_count == 1
    assert discover_mock.call_args.kwargs["host"] == "10.0.0.3"
    assert agent_persist_mock[domain_scan.OPEN_PORTS_CACHE_KEY] == {
        "10.0.0.3": b"80,443"
    }
    discovery_options = wrapper_init_spy.call_args_list[1].kwargs["options"]
    assert discovery_options.version_detection is False
    assert discovery_options.script_default is False
    assert discovery_options.scripts is None
    assert discovery_options.ports == "0-65535"
    assert scan_domain_mock.call_count == 2
    assert [c.kwargs["domain_name"] for c in scan_domain_mock.call_args_list] == [
        "a.example.com",
        "b.example.com",
    ]
    assert scan_domain_mock.call_args.kwargs["is_ipv6"] is False
    service_options = wrapper_init_spy.call_args_list[-1].kwargs["options"]
    assert service_options.ports == "80,443"
    assert service_options.version_detection is True
    assert service_options.no_ping is True
    assert len(services) > 0
    assert hosts_file.read_text() == "127.0.0.1 localhost\n"


def testScan_whenIpCachedWithNoOpenPorts_returnsNoServicesWithoutScanning(
    mocker: plugin.MockerFixture,
    agent_persist_mock: dict[str | bytes, Any],
) -> None:
    scan = mcp_tools.NmapTools(redis_url="redis://localhost:6379").scan
    agent_persist_mock[domain_scan.OPEN_PORTS_CACHE_KEY] = {"10.0.0.3": b""}
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 0))],
    )
    discover_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.discover_open_ports")
    scan_domain_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.scan_domain")

    services = scan("a.example.com")

    assert services == []
    assert discover_mock.call_count == 0
    assert scan_domain_mock.call_count == 0


def testScan_whenDomainDoesNotResolve_returnsNoServices(
    mocker: plugin.MockerFixture,
    agent_persist_mock: dict[str | bytes, Any],
) -> None:
    scan = mcp_tools.NmapTools(redis_url="redis://localhost:6379").scan
    mocker.patch("socket.getaddrinfo", side_effect=socket.gaierror("no such host"))
    discover_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.discover_open_ports")
    scan_domain_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.scan_domain")

    services = scan("missing.example.com")

    assert services == []
    assert discover_mock.call_count == 0
    assert scan_domain_mock.call_count == 0


def testScan_whenDomainHasOnlyIpv6_scansDomainWithIpv6(
    mocker: plugin.MockerFixture,
    agent_persist_mock: dict[str | bytes, Any],
    tmp_path: pathlib.Path,
) -> None:
    scan = mcp_tools.NmapTools(redis_url="redis://localhost:6379").scan
    mocker.patch.object(domain_scan, "HOSTS_FILE_PATH", str(tmp_path / "hosts"))
    mocker.patch(
        "socket.getaddrinfo",
        side_effect=[
            socket.gaierror("no ipv4"),
            [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::10", 0, 0, 0))],
        ],
    )
    discover_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports", return_value=["443"]
    )
    scan_domain_mock = mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_domain", return_value=({}, "")
    )

    scan("v6.example.com")

    assert discover_mock.call_args.kwargs["host"] == "fd00::10"
    assert scan_domain_mock.call_args.kwargs["is_ipv6"] is True


def testScan_whenDiscoveryOutputCannotBeParsed_raisesAndDoesNotCacheIp(
    mocker: plugin.MockerFixture,
    agent_persist_mock: dict[str | bytes, Any],
) -> None:
    scan = mcp_tools.NmapTools(redis_url="redis://localhost:6379").scan
    mocker.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 0))],
    )
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.discover_open_ports",
        side_effect=nmap_wrapper.OutputParsingError("truncated xml"),
    )
    scan_domain_mock = mocker.patch("agent.nmap_wrapper.NmapWrapper.scan_domain")

    with pytest.raises(mcp_tools.CalledToolError):
        scan("a.example.com")

    assert domain_scan.OPEN_PORTS_CACHE_KEY not in agent_persist_mock
    assert scan_domain_mock.call_count == 0


def testRun_whenRedisUrlGiven_startsServerAsModuleFromAppDirectory(
    mocker: plugin.MockerFixture,
) -> None:
    """Running server.py as a script would let agent/mcp/mcp_types.py shadow fastmcp's mcp_types."""
    popen_mock = mocker.patch("subprocess.Popen")

    mcp_runner.run(redis_url="redis://guest:guest@localhost:6379")

    assert popen_mock.call_args.args[0] == [
        "python3.14",
        "-m",
        "agent.mcp.server",
        "--redis-url",
        "redis://guest:guest@localhost:6379",
    ]
    assert popen_mock.call_args.kwargs["cwd"] == "/app"


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def testScan_whenCalledThroughMcpServer_returnsIpVersionsAsStrings(
    mocker: plugin.MockerFixture,
    agent_persist_mock: dict[str | bytes, Any],
    fake_output_multi_host: dict[str, Any],
) -> None:
    """fastmcp validates the tool output against its schema, where every version is a string."""
    mocker.patch(
        "agent.nmap_wrapper.NmapWrapper.scan_hosts",
        return_value=(fake_output_multi_host, ""),
    )
    server = fastmcp.FastMCP(
        name="nmap",
        tools=[mcp_tools.NmapTools(redis_url="redis://localhost:6379").scan],
    )

    async with fastmcp.Client(server) as client:
        result = await client.call_tool("scan", {"target": "10.0.0.0/24"})

    assert result.structured_content is not None
    services = result.structured_content["result"]
    assert len(services) > 0
    assert {service["version"] for service in services} == {"4"}
    fingerprints = [fp for service in services for fp in service["fingerprints"]]
    assert {fp["version"] for fp in fingerprints if fp["library_type"] != "OS"} == {"4"}
    assert {fp["version"] for fp in fingerprints if fp["library_type"] == "OS"} == {
        "ipv4"
    }


def testMain_whenRedisUrlOptionGiven_buildsToolsWithIt(
    mocker: plugin.MockerFixture,
) -> None:
    nmap_tools_init_spy = mocker.spy(mcp_tools.NmapTools, "__init__")
    mcp_run_mock = mocker.patch("fastmcp.FastMCP.run")

    result = testing.CliRunner().invoke(
        mcp_server.main, ["--redis-url", "redis://guest:guest@localhost:6379"]
    )

    assert result.exit_code == 0
    assert (
        nmap_tools_init_spy.call_args.kwargs["redis_url"]
        == "redis://guest:guest@localhost:6379"
    )
    assert mcp_run_mock.call_count == 1


def testMain_whenRedisUrlOptionMissing_exitsWithError(
    mocker: plugin.MockerFixture,
) -> None:
    mcp_run_mock = mocker.patch("fastmcp.FastMCP.run")

    result = testing.CliRunner().invoke(mcp_server.main, [])

    assert result.exit_code == 2
    assert "--redis-url" in result.output
    assert mcp_run_mock.call_count == 0
