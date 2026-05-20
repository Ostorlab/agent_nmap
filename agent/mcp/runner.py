import logging
import subprocess

logger = logging.getLogger(__name__)

RUN_SERVER_PATH = "/app/agent/mcp/server.py"
RUN_SERVER_PATH_COMPILED = "/app/mcp_server/server.bin"


def run(is_compiled: bool = False) -> None:
    """Start the MCP server with the streamable-http transport."""
    logger.info("Starting MCP server.")
    subprocess.Popen(
        [
            RUN_SERVER_PATH if is_compiled is False else RUN_SERVER_PATH_COMPILED,
        ]
    )
