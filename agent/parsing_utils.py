from typing import Any
from typing_extensions import TypedDict

from agent import generators


class DomainNameService(TypedDict):
    name: str
    port: int | str | None
    schema: str | None
    state: str | None


class PortService(TypedDict):
    host: str | None
    version: str | None
    port: int | str | None
    protocol: str | None
    state: str | None
    service: str | None
    banner: str | None
    address: str | None
    addr_version: str | None


class OSFingerprint(TypedDict):
    host: str | None
    version: str | None
    library_type: str
    library_name: str | None
    library_version: str | None
    detail: str | None


class ServiceLibraryFingerprint(TypedDict):
    host: str | None
    mask: str
    version: str | None
    library_type: str
    library_version: str | None
    service: str | None
    port: int | str | None
    protocol: str | None
    library_name: str
    detail: str
    addr_version: str | None


class DomainNameServiceLibraryFingerprint(TypedDict):
    name: str
    port: int | str | None
    schema: str | None
    library_name: str
    library_version: str | None
    library_type: str
    detail: str


BLACKLISTED_SERVICES = ["tcpwrapped"]


def get_domain_name_services(
    scan_results: dict[str, Any], domain_name: str
) -> list[DomainNameService]:
    domain_name_services = []
    if scan_results is not None and scan_results.get("nmaprun") is not None:
        for data in generators.get_services(scan_results):
            if data.get("service") in BLACKLISTED_SERVICES:
                continue
            domain_name_service: DomainNameService = {
                "name": domain_name,
                "port": data.get("port"),
                "schema": data.get("service"),
                "state": data.get("state"),
            }
            domain_name_services.append(domain_name_service)
    return domain_name_services


def get_port_services(scan_results: dict[str, Any]) -> list[PortService]:
    port_services = []
    if scan_results is not None and scan_results.get("nmaprun") is not None:
        up_hosts = scan_results["nmaprun"].get("host", [])
        if isinstance(up_hosts, dict):
            up_hosts = [up_hosts]

        for host in up_hosts:
            version = host.get("address", {}).get("@addrtype")
            address = host.get("address", {}).get("@addr")
            for data in generators.get_services(scan_results):
                if data.get("service") in BLACKLISTED_SERVICES:
                    continue
                service: PortService = {
                    "host": data.get("host"),
                    "version": data.get("version"),
                    "port": data.get("port"),
                    "protocol": data.get("protocol"),
                    "state": data.get("state"),
                    "service": data.get("service"),
                    "banner": data.get("banner"),
                    "address": address,
                    "addr_version": version,
                }
                port_services.append(service)
    return port_services


def get_os_fingerprints(scan_results: dict[str, Any]) -> list[OSFingerprint]:
    os_fingerprints = []
    if (
        scan_results is not None
        and scan_results.get("nmaprun") is not None
        and scan_results["nmaprun"].get("host") is not None
    ):
        up_hosts = scan_results["nmaprun"].get("host", [])
        if isinstance(up_hosts, dict):
            up_hosts = [up_hosts]

        for host in up_hosts:
            if (
                host.get("os", {}) is not None
                and host.get("os", {}).get("osmatch") is not None
            ):
                os_match = host.get("os").get("osmatch")
                if isinstance(os_match, list):
                    if len(os_match) > 0:
                        os_match_highest = os_match[0]
                        if isinstance(os_match_highest, dict):
                            pass
                        elif (
                            isinstance(os_match_highest, list)
                            and len(os_match_highest) > 0
                        ):
                            os_match_highest = os_match_highest[0]
                        else:
                            continue
                    else:
                        continue
                elif isinstance(os_match, dict):
                    os_match_highest = os_match
                else:
                    continue

                os_class = os_match_highest.get("osclass", {})

                if isinstance(os_class, list) and len(os_class) > 0:
                    os_class = os_class[0]
                elif os_class == []:
                    continue

                fingerprint: OSFingerprint = {
                    "host": host.get("address", {}).get("@addr"),
                    "version": host.get("address", {}).get("@addrtype"),
                    "library_type": "OS",
                    "library_name": os_class.get("@osfamily"),
                    "library_version": os_class.get("@osgen"),
                    "detail": os_match_highest.get("@name"),
                }
                os_fingerprints.append(fingerprint)
    return os_fingerprints


def get_service_libraries(
    scan_results: dict[str, Any],
) -> list[ServiceLibraryFingerprint]:
    libraries = []
    if (
        scan_results is not None
        and scan_results.get("nmaprun") is not None
        and scan_results["nmaprun"].get("host") is not None
    ):
        up_hosts = scan_results["nmaprun"].get("host", [])
        if isinstance(up_hosts, dict):
            up_hosts = [up_hosts]

        for host in up_hosts:
            version = host.get("address", {}).get("@addrtype")
            default_mask: str
            if version == "ipv4":
                default_mask = "32"
            elif version == "ipv6":
                default_mask = "128"
            else:
                raise ValueError(f"Incorrect ip version {version}")

            for data in generators.get_services(scan_results):
                if data.get("service") in BLACKLISTED_SERVICES:
                    continue
                data_product = data.get("product")
                data_banner = data.get("banner")
                if data_product is not None and data_product != "":
                    fingerprint: ServiceLibraryFingerprint = {
                        "host": data.get("host"),
                        "mask": data.get("mask") or default_mask,
                        "version": data.get("version"),
                        "library_type": "BACKEND_COMPONENT",
                        "service": data.get("service"),
                        "port": data.get("port"),
                        "protocol": data.get("protocol"),
                        "library_name": data_product,
                        "library_version": data.get("product_version"),
                        "detail": data_product,
                        "addr_version": version,
                    }
                    libraries.append(fingerprint)
                if data_banner is not None and data_banner != "":
                    fingerprint = {
                        "host": data.get("host"),
                        "mask": data.get("mask") or default_mask,
                        "version": data.get("version"),
                        "library_type": "BACKEND_COMPONENT",
                        "service": data.get("service"),
                        "port": data.get("port"),
                        "protocol": data.get("protocol"),
                        "library_name": data_banner,
                        "detail": data_banner,
                        "addr_version": version,
                        "library_version": None,
                    }
                    libraries.append(fingerprint)
    return libraries


def get_domain_name_service_library_fingerprints(
    scan_results: dict[str, Any], domain_name: str
) -> list[DomainNameServiceLibraryFingerprint]:
    fingerprints = []
    if (
        scan_results is not None
        and scan_results.get("nmaprun") is not None
        and scan_results["nmaprun"].get("host") is not None
    ):
        up_hosts = scan_results["nmaprun"].get("host", [])
        if isinstance(up_hosts, dict):
            up_hosts = [up_hosts]

        for data in generators.get_services(scan_results):
            if data.get("service") in BLACKLISTED_SERVICES:
                continue
            data_product = data.get("product")
            data_banner = data.get("banner")
            if data_product is not None and data_product != "":
                fp: DomainNameServiceLibraryFingerprint = {
                    "name": domain_name,
                    "port": data.get("port"),
                    "schema": data.get("service"),
                    "library_name": data_product,
                    "library_version": data.get("product_version"),
                    "library_type": "BACKEND_COMPONENT",
                    "detail": f"Nmap Detected {data_product} on {domain_name}",
                }
                fingerprints.append(fp)
            if data_banner is not None and data_banner != "":
                fp = {
                    "name": domain_name,
                    "port": data.get("port"),
                    "schema": data.get("service"),
                    "library_name": data_banner,
                    "library_version": None,
                    "library_type": "BACKEND_COMPONENT",
                    "detail": f"Nmap Detected {data_banner} on {domain_name}",
                }
                fingerprints.append(fp)
    return fingerprints
