# strikerr/apps/crawler/triage/dns_scanner.py
import socket
from typing import Dict, List, Any

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

class DNSScanner:
    """Inspects DNS records for target domain, extracting A, AAAA, MX, NS, and TXT records."""

    @classmethod
    def scan_domain(cls, domain: str) -> Dict[str, List[str]]:
        results = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': []
        }

        # Primary scan using dnspython if installed
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.5
            resolver.lifetime = 2.5
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = resolver.resolve(domain, qtype)
                    results[qtype] = [str(r.to_text()).strip('"') for r in answers]
                except Exception:
                    continue
            if results['A'] or results['AAAA']:
                return results

        # Built-in fallback using standard socket.getaddrinfo
        try:
            addr_info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, _, _, _, sockaddr in addr_info:
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in results['A']:
                    results['A'].append(ip)
                elif family == socket.AF_INET6 and ip not in results['AAAA']:
                    results['AAAA'].append(ip)
        except Exception:
            pass

        return results
