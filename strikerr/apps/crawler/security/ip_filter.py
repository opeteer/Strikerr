# strikerr/apps/crawler/security/ip_filter.py
import ipaddress
from typing import Union

# Comprehensive Blacklist covering RFC 1918, Loopback, Link-Local, Cloud Metadata, and Multicast
BLOCKED_IP_NETWORKS = [
    # IPv4 Loopback & Non-routable
    ipaddress.ip_network('127.0.0.0/8'),        # Loopback
    ipaddress.ip_network('0.0.0.0/8'),          # Current network (source-only)
    ipaddress.ip_network('100.64.0.0/10'),      # Shared Address Space / CGNAT (RFC 6598)
    
    # RFC 1918 Private Subnets
    ipaddress.ip_network('10.0.0.0/8'),         # Private-Use
    ipaddress.ip_network('172.16.0.0/12'),      # Private-Use
    ipaddress.ip_network('192.168.0.0/16'),     # Private-Use
    
    # Link-Local & Cloud Provider Metadata
    ipaddress.ip_network('169.254.0.0/16'),     # Link-Local (AWS, GCP, Azure, DO, Alibaba Metadata)
    
    # Broadcast, Multicast & Reserved
    ipaddress.ip_network('192.0.0.0/24'),       # IETF Protocol Assignments
    ipaddress.ip_network('192.0.2.0/24'),       # Documentation (TEST-NET-1)
    ipaddress.ip_network('198.51.100.0/24'),    # Documentation (TEST-NET-2)
    ipaddress.ip_network('203.0.113.0/24'),     # Documentation (TEST-NET-3)
    ipaddress.ip_network('224.0.0.0/4'),        # Multicast
    ipaddress.ip_network('240.0.0.0/4'),        # Reserved for Future Use
    ipaddress.ip_network('255.255.255.255/32'), # Limited Broadcast
    
    # IPv6 Loopback, Link-Local, Private & Metadata
    ipaddress.ip_network('::1/128'),            # IPv6 Loopback
    ipaddress.ip_network('::/128'),             # IPv6 Unspecified
    ipaddress.ip_network('::ffff:0:0/96'),      # IPv4-mapped IPv6 base
    ipaddress.ip_network('64:ff9b::/96'),       # IPv4/IPv6 translation
    ipaddress.ip_network('fc00::/7'),           # Unique Local Address (ULA)
    ipaddress.ip_network('fe80::/10'),          # Link-Local Unicast
    ipaddress.ip_network('ff00::/8'),           # Multicast
    ipaddress.ip_network('fd00:ec2::254/128'),  # AWS IPv6 Metadata Endpoint
]

def is_ip_blocked(ip_addr: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Verifies whether an IP address falls into any forbidden, private, or metadata range."""
    if isinstance(ip_addr, str):
        ip_addr = ip_addr.strip()
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
            # Handle IPv4-mapped IPv6 formats (e.g. ::ffff:169.254.169.254 or ::ffff:127.0.0.1)
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                ip_obj = ip_obj.ipv4_mapped
        except ValueError:
            # Unparseable IP representations are blocked by default
            return True
    else:
        ip_obj = ip_addr

    return any(ip_obj in network for network in BLOCKED_IP_NETWORKS)
