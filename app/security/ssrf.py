import ipaddress
import socket
import urllib.parse
from typing import Union

from app.config import settings

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "instance-data",
}

FORBIDDEN_EXACT_IPS = {
    "169.254.169.254",  # AWS / GCP / Azure link-local metadata
    "fd00:ec2::254",    # AWS EC2 IPv6 metadata
    "100.100.100.200",  # Alibaba Cloud metadata
}


def is_forbidden_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Checks whether an IP address is private, loopback, link-local, reserved, or cloud metadata."""
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    if str(ip) in FORBIDDEN_EXACT_IPS:
        return True
    return False


def validate_upstream_url(url_str: str) -> str:
    """
    Validates upstream_base_url to prevent SSRF and unencrypted credential transmission:
    1. Must be a valid URL with http or https (https strictly required in production).
    2. Hostname cannot be empty or a forbidden internal/cloud metadata hostname.
    3. Hostname cannot be a private, loopback, link-local, multicast, or cloud metadata IP
       (including integer, hex, or IPv6 representations).
    4. DNS-resolved addresses must not resolve to forbidden IP ranges.
    """
    if not url_str or not isinstance(url_str, str):
        raise ValueError("upstream_base_url must be a non-empty string")

    url_str = url_str.strip()
    try:
        parsed = urllib.parse.urlparse(url_str)
    except Exception as e:
        raise ValueError(f"Invalid URL structure: {e}")

    scheme = parsed.scheme.lower()
    if settings.ENV == "production":
        if scheme != "https":
            raise ValueError("In production, upstream_base_url must use HTTPS")
    else:
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme '{scheme}'. Must be http or https")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid upstream URL: missing hostname")

    hostname_lower = hostname.lower()
    if hostname_lower in FORBIDDEN_HOSTNAMES:
        raise ValueError(f"Forbidden upstream host: '{hostname}' is a reserved internal hostname")

    # Check if hostname is an integer or hex representation of an IP (e.g. 2852039166 or 0x7f000001)
    try:
        if hostname_lower.startswith(("0x", "0X")):
            numeric_ip = int(hostname_lower, 16)
            ip_obj = ipaddress.ip_address(numeric_ip)
            if is_forbidden_ip(ip_obj):
                raise ValueError(
                    f"Forbidden upstream host: '{hostname}' represents a restricted IP address ({ip_obj})"
                )
        elif hostname_lower.isdigit():
            numeric_ip = int(hostname_lower)
            ip_obj = ipaddress.ip_address(numeric_ip)
            if is_forbidden_ip(ip_obj):
                raise ValueError(
                    f"Forbidden upstream host: '{hostname}' represents a restricted IP address ({ip_obj})"
                )
    except ValueError as e:
        if "Forbidden upstream host" in str(e):
            raise

    # Check if hostname is an IP address literal
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_forbidden_ip(ip_obj):
            raise ValueError(
                f"Forbidden upstream host: '{hostname}' is in a restricted IP range (metadata/private/loopback)"
            )
    except ValueError as e:
        if "Forbidden upstream host" in str(e):
            raise
        # Not a raw IP literal, it is a domain name

    # Resolve hostname via DNS to prevent DNS rebinding / internal resolutions
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
        for entry in addr_infos:
            sockaddr = entry[4]
            resolved_ip_str = sockaddr[0]
            try:
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
                if is_forbidden_ip(resolved_ip):
                    raise ValueError(
                        f"Forbidden upstream host: '{hostname}' resolves to restricted IP '{resolved_ip_str}'"
                    )
            except ValueError as e:
                if "Forbidden upstream host" in str(e):
                    raise
    except socket.gaierror:
        # Host could not be resolved (e.g. offline tests or mock services)
        pass

    return url_str
