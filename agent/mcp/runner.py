import logging
import subprocess

logger = logging.getLogger(__name__)

RUN_SERVER_PATH = "/app/agent/mcp/server.py"


def run() -> None:
    """Start the MCP server with the streamable-http transport."""
    logger.info("Starting MCP server.")
    subprocess.Popen(
        [
            "python3.11",
            RUN_SERVER_PATH,
        ]
    )
