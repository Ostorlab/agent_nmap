import logging
import subprocess

logger = logging.getLogger(__name__)

# Run the server as a module from the app directory: running agent/mcp/server.py as a script puts
# agent/mcp/ first on the import path, where agent/mcp/mcp_types.py shadows the mcp_types package
# that fastmcp imports.
RUN_SERVER_MODULE = "agent.mcp.server"
APP_PATH = "/app"


def run(redis_url: str) -> None:
    """Start the MCP server with the streamable-http transport."""
    logger.info("Starting MCP server.")
    subprocess.Popen(
        [
            "python3.14",
            "-m",
            RUN_SERVER_MODULE,
            "--redis-url",
            redis_url,
        ],
        cwd=APP_PATH,
    )
