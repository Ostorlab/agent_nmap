"""MCP server main entrypoint module."""

import logging

import fastmcp

from agent.mcp import tools as mcp_tools


logger = logging.getLogger(__name__)

MCP_SERVER_NAME = "nmap"
MCP_SERVER_HOST = "0.0.0.0"
MCP_SERVER_PORT = 50051

mcp: fastmcp.FastMCP = fastmcp.FastMCP(
    name=MCP_SERVER_NAME,
    host=MCP_SERVER_HOST,
    port=MCP_SERVER_PORT,
    tools=[mcp_tools.scan_ip, mcp_tools.scan_domain],
)


def run() -> None:
    """Start the MCP server with the streamable-http transport."""
    logger.info("Starting MCP server with transport: streamable-http")
    mcp.run(transport="streamable-http")


def main() -> None:
    """Entry point for the Nmap MCP server."""
    run()


if __name__ == "__main__":
    main()
