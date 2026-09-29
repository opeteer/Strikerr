# strikerr/apps/crawler/triage/ssl_scanner.py
import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

class SSLScanner:
    """Inspects target SSL/TLS certificate chain without relying on external heavy dependencies."""

    @classmethod
    def scan_certificate(cls, hostname: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
        result = {
            'has_ssl': False,
            'issuer': None,
            'subject': None,
            'valid_from': None,
            'valid_to': None,
            'san_list': [],
            'sha256_fingerprint': None,
            'error': None
        }

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if cert_bin:
                        result['has_ssl'] = True
                        result['sha256_fingerprint'] = hashlib.sha256(cert_bin).hexdigest()
                    
                    cert = ssock.getpeercert()
                    if cert:
                        # Extract issuer
                        issuer_dict = dict(x[0] for x in cert.get('issuer', ()))
                        result['issuer'] = issuer_dict.get('organizationName') or issuer_dict.get('commonName')

                        # Extract subject
                        subject_dict = dict(x[0] for x in cert.get('subject', ()))
                        result['subject'] = subject_dict.get('commonName')

                        # Validity period
                        not_before = cert.get('notBefore')
                        if not_before:
                            try:
                                dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                                result['valid_from'] = dt.replace(tzinfo=timezone.utc).isoformat()
                            except Exception:
                                pass

                        not_after = cert.get('notAfter')
                        if not_after:
                            try:
                                dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                result['valid_to'] = dt.replace(tzinfo=timezone.utc).isoformat()
                            except Exception:
                                pass

                        # Subject Alternative Names (SANs)
                        result['san_list'] = [entry[1] for entry in cert.get('subjectAltName', ()) if len(entry) > 1]

        except Exception as e:
            result['error'] = str(e)

        return result
