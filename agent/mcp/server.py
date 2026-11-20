"""MCP server main entrypoint module."""

import logging

import click
import fastmcp

from agent.mcp import tools as mcp_tools

logger = logging.getLogger(__name__)

MCP_SERVER_NAME = "nmap"
MCP_SERVER_HOST = "0.0.0.0"
MCP_SERVER_PORT = 50051


def run(redis_url: str) -> None:
    """Start the MCP server with the streamable-http transport."""
    mcp: fastmcp.FastMCP = fastmcp.FastMCP(
        name=MCP_SERVER_NAME,
        tools=[mcp_tools.NmapTools(redis_url=redis_url).scan],
    )
    logger.info("Starting MCP server with transport: streamable-http")
    mcp.run(
        transport="streamable-http",
        host=MCP_SERVER_HOST,
        port=MCP_SERVER_PORT,
    )


@click.command()
@click.option(
    "--redis-url",
    required=True,
    help="Redis URL of the scan, where the open ports of scanned IPs are cached.",
)
def main(redis_url: str) -> None:
    """Entry point for the Nmap MCP server."""
    run(redis_url=redis_url)


if __name__ == "__main__":
    main()
