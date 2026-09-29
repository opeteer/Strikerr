# tests/test_safe_transport.py
import pytest
from unittest.mock import patch
from strikerr.apps.crawler.security.safe_transport import SafeDNSResolver, SSRFSecurityException

def test_safe_dns_resolver_blocks_internal_resolution():
    # Mocking socket.getaddrinfo returning AWS metadata IP
    mock_addrinfo = [(2, 1, 6, '', ('169.254.169.254', 80))]
    with patch('socket.getaddrinfo', return_value=mock_addrinfo):
        with pytest.raises(SSRFSecurityException) as exc_info:
            SafeDNSResolver.resolve_and_verify('metadata.google.internal')
        assert "SSRF Alert" in str(exc_info.value)

def test_safe_dns_resolver_blocks_loopback_rebind():
    # Mocking socket.getaddrinfo returning localhost
    mock_addrinfo = [(2, 1, 6, '', ('127.0.0.1', 80))]
    with patch('socket.getaddrinfo', return_value=mock_addrinfo):
        with pytest.raises(SSRFSecurityException) as exc_info:
            SafeDNSResolver.resolve_and_verify('rebind.adversary.com')
        assert "blocked IP '127.0.0.1'" in str(exc_info.value)

def test_safe_dns_resolver_allows_valid_public_ip():
    # Mocking socket.getaddrinfo returning valid public IP
    mock_addrinfo = [(2, 1, 6, '', ('103.145.22.18', 443))]
    with patch('socket.getaddrinfo', return_value=mock_addrinfo):
        ips = SafeDNSResolver.resolve_and_verify('target.bca.co.id')
        assert ips == ['103.145.22.18']
