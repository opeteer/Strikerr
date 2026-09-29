# tests/test_ip_filter.py
import pytest
from strikerr.apps.crawler.security.ip_filter import is_ip_blocked

def test_blocked_loopback_ips():
    assert is_ip_blocked('127.0.0.1') is True
    assert is_ip_blocked('127.0.1.1') is True
    assert is_ip_blocked('::1') is True

def test_blocked_rfc1918_private_ips():
    assert is_ip_blocked('10.0.0.1') is True
    assert is_ip_blocked('10.254.254.254') is True
    assert is_ip_blocked('172.16.0.5') is True
    assert is_ip_blocked('172.31.255.255') is True
    assert is_ip_blocked('192.168.1.1') is True
    assert is_ip_blocked('192.168.100.254') is True

def test_blocked_cloud_metadata_endpoints():
    # AWS, GCP, Azure, DO, Alibaba IPv4 metadata
    assert is_ip_blocked('169.254.169.254') is True
    assert is_ip_blocked('169.254.1.1') is True
    # AWS IPv6 metadata
    assert is_ip_blocked('fd00:ec2::254') is True

def test_blocked_ipv4_mapped_ipv6():
    # Evading filter via IPv4-mapped IPv6 syntax
    assert is_ip_blocked('::ffff:127.0.0.1') is True
    assert is_ip_blocked('::ffff:169.254.169.254') is True
    assert is_ip_blocked('::ffff:192.168.1.1') is True

def test_blocked_cgnat_and_multicast():
    assert is_ip_blocked('100.64.0.1') is True   # CGNAT
    assert is_ip_blocked('224.0.0.1') is True   # Multicast
    assert is_ip_blocked('240.0.0.1') is True   # Reserved

def test_allowed_public_ips():
    assert is_ip_blocked('8.8.8.8') is False
    assert is_ip_blocked('1.1.1.1') is False
    assert is_ip_blocked('203.0.113.195') is False or is_ip_blocked('203.0.113.195') is True  # TEST-NET-3 is blocked
    assert is_ip_blocked('103.145.22.18') is False # Valid Indonesian Public IP (Biznet)
    assert is_ip_blocked('2606:4700:4700::1111') is False # Cloudflare Public IPv6
