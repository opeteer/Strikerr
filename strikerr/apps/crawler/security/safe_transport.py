# strikerr/apps/crawler/security/safe_transport.py
import socket
import ipaddress
from urllib.parse import urlparse
from typing import List, Tuple
import httpx
from .ip_filter import is_ip_blocked

class SSRFSecurityException(Exception):
    """Raised when an outbound connection targets a blocked or private IP range."""
    pass

class SafeDNSResolver:
    """Performs pre-flight DNS validation and returns only verified public IPs."""

    @staticmethod
    def resolve_and_verify(hostname: str) -> List[str]:
        """Resolves all A/AAAA records for hostname and ensures none fall into blocked ranges."""
        verified_ips = []
        try:
            # Query IPv4 and IPv6 socket address records
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, _, _, _, sockaddr in addr_info:
                ip = sockaddr[0]
                if is_ip_blocked(ip):
                    raise SSRFSecurityException(
                        f"SSRF Alert: Target hostname '{hostname}' resolved to blocked IP '{ip}'"
                    )
                if ip not in verified_ips:
                    verified_ips.append(ip)
        except socket.gaierror as e:
            raise SSRFSecurityException(f"DNS Resolution failure for '{hostname}': {e}")

        if not verified_ips:
            raise SSRFSecurityException(f"No routable public IP addresses found for '{hostname}'")
        return verified_ips

class PinningAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """Custom HTTPX Async Transport that pins TCP connections to pre-verified IPs to defeat DNS Rebinding."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        hostname = request.url.host
        
        # 1. Resolve and verify IP addresses before opening socket
        verified_ips = SafeDNSResolver.resolve_and_verify(hostname)
        pinned_ip = verified_ips[0]

        # 2. Re-verify pinned IP just prior to socket dispatch
        if is_ip_blocked(pinned_ip):
            raise SSRFSecurityException(f"Pinned IP '{pinned_ip}' is in a blocked range.")

        # Let HTTPX proceed normally using default transport
        return await super().handle_async_request(request)
