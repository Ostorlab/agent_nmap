"""Types used in MCP tools."""

import dataclasses


@dataclasses.dataclass
class ServiceResult:
    """Service information from port scan.

    Attributes:
        host: The IP address of the host.
        port: The port number.
        protocol: The protocol (tcp, udp).
        state: The port state (open, closed, filtered).
        service: The service name.
        banner: The banner information.
        version: The IP version (4 or 6).
    """

    host: str
    port: int
    protocol: str
    state: str
    service: str
    banner: str
    version: str


@dataclasses.dataclass
class FingerprintResult:
    """Fingerprint information (OS or backend component).

    Attributes:
        host: The IP address of the host.
        version: The IP version (4 or 6).
        library_type: The type of library (OS or BACKEND_COMPONENT).
        service: The service name if applicable.
        port: The port number if applicable.
        protocol: The protocol if applicable.
        library_name: The OS family or product name.
        library_version: The OS generation or product version.
        detail: Detailed information about the OS or product.
        mask: Network mask (default 32 for IPv4, 128 for IPv6).
    """

    host: str
    version: str
    library_type: str
    service: str | None
    port: int | None
    protocol: str | None
    library_name: str
    library_version: str | None
    detail: str
    mask: int = 32
