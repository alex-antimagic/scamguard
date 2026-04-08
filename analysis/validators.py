import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def is_safe_url(url: str) -> bool:
    """Validate that a URL does not point to internal/private resources."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False

    if parsed.scheme not in ('http', 'https', ''):
        return False

    try:
        for info in socket.getaddrinfo(hostname, None):
            addr = ipaddress.ip_address(info[4][0])
            for network in BLOCKED_IP_RANGES:
                if addr in network:
                    return False
    except (socket.gaierror, ValueError):
        pass

    return True
