# strikerr/apps/crawler/triage/triage_engine.py
import re
import hashlib
from urllib.parse import urlparse
from typing import Dict, Any, Tuple
import httpx
from strikerr.apps.crawler.security.safe_transport import SafeDNSResolver, PinningAsyncHTTPTransport, SSRFSecurityException
from strikerr.apps.crawler.security.stream_guard import SafeStreamReader, DecompressionBombException
from strikerr.apps.crawler.triage.dns_scanner import DNSScanner
from strikerr.apps.crawler.triage.ssl_scanner import SSLScanner

try:
    from curl_cffi.requests import AsyncSession
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False

class FastTriageEngine:
    """Layer 1 Fast Triage: Inspects DNS, SSL, and HTTP without spinning up a headless browser."""

    # Dynamic hydration and client-side rendering indicators
    SPA_SIGNATURES = [
        re.compile(r'<div[^>]+id=["\'](?:app|root|__next|__nuxt)["\']', re.I),
        re.compile(r'react-root', re.I),
        re.compile(r'<script[^>]+src=["\'][^"\']*(?:chunk|bundle|main|app)\.[a-f0-9]+\.js["\']', re.I),
        re.compile(r'<meta[^>]+http-equiv=["\']refresh["\']', re.I),
        re.compile(r'window\.location\.(?:href|replace)\s*=', re.I),
    ]

    # Indonesian gambling keywords triggering immediate browser escalation
    HIGH_PRIORITY_TRIGGERS = [
        "slot", "gacor", "maxwin", "rtp", "pragmatic", "zeus", "scatter",
        "login", "masuk", "rekening", "undian", "hadiah"
    ]

    @classmethod
    async def triage_url(cls, raw_url: str, timeout: float = 8.0) -> Dict[str, Any]:
        parsed = urlparse(raw_url)
        hostname = parsed.hostname
        if not hostname:
            return {'status': 'ERROR', 'error': 'Invalid URL hostname'}

        result = {
            'status': 'SUCCESS',
            'raw_url': raw_url,
            'hostname': hostname,
            'dns_records': {},
            'ssl_info': {},
            'http_status': None,
            'final_url': raw_url,
            'redirect_chain': [],
            'headers': {},
            'dom_html': '',
            'dom_sha256': '',
            'should_escalate_to_headless': False,
            'escalation_reasons': [],
            'error': None
        }

        # 1. Pre-flight DNS & SSRF Validation
        try:
            verified_ips = SafeDNSResolver.resolve_and_verify(hostname)
            result['resolved_ip'] = verified_ips[0]
            result['dns_records'] = DNSScanner.scan_domain(hostname)
        except SSRFSecurityException as e:
            result['status'] = 'BLOCKED_SSRF'
            result['error'] = str(e)
            return result
        except Exception as e:
            result['status'] = 'DNS_FAILED'
            result['error'] = str(e)
            return result

        # 2. SSL/TLS Certificate Inspection (if HTTPS)
        if parsed.scheme == 'https':
            port = parsed.port or 443
            result['ssl_info'] = SSLScanner.scan_certificate(hostname, port=port)

        # 3. Fast HTTP Probe using Pinning Async Client
        transport = PinningAsyncHTTPTransport()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36',
            'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Upgrade-Insecure-Requests': '1',
        }

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=timeout,
                follow_redirects=True,
                headers=headers,
                verify=False
            ) as client:
                async with client.stream("GET", raw_url) as resp:
                    result['http_status'] = resp.status_code
                    result['final_url'] = str(resp.url)
                    result['headers'] = dict(resp.headers)
                    if hasattr(resp, 'history') and resp.history:
                        result['redirect_chain'] = [str(r.url) for r in resp.history]

                    # Read body with decompression bomb protection
                    body_bytes = await SafeStreamReader.read_bounded_content(resp)
                    html_text = body_bytes.decode('utf-8', errors='replace')
                    result['dom_html'] = html_text
                    result['dom_sha256'] = hashlib.sha256(body_bytes).hexdigest()

        except DecompressionBombException as e:
            result['status'] = 'BOMB_ABORTED'
            result['error'] = str(e)
            return result
        except Exception as e:
            result['status'] = 'HTTP_FAILED'
            result['error'] = str(e)
            return result

        # 4. Evaluate Escalation to Headless Browser
        cls._evaluate_escalation(result)
        return result

    @classmethod
    def _evaluate_escalation(cls, result: Dict[str, Any]):
        reasons = []
        html = result.get('dom_html', '').lower()
        hostname = result.get('hostname', '').lower()

        # Rule 1: Always escalate .go.id or .ac.id domains for visual proof of defacement
        if hostname.endswith('.go.id') or hostname.endswith('.ac.id'):
            reasons.append("Sovereign ccTLD (.go.id/.ac.id) requires visual verification")

        # Rule 2: Dynamic JavaScript Hydration / SPA detected
        for sig in cls.SPA_SIGNATURES:
            if sig.search(html):
                reasons.append("Dynamic JS Hydration / SPA / Meta-Refresh detected")
                break

        # Rule 3: High priority Judol / Phishing keywords found in static payload
        matched_triggers = [kw for kw in cls.HIGH_PRIORITY_TRIGGERS if kw in html]
        if matched_triggers:
            reasons.append(f"High-priority threat triggers matched: {matched_triggers[:3]}")

        # Rule 4: If page body is very small (< 1KB) but returned 200 OK (likely JS redirect bridge)
        if 0 < len(html) < 1024 and result.get('http_status') == 200:
            reasons.append("Suspiciously small HTML payload (<1KB) with HTTP 200 OK")

        if reasons:
            result['should_escalate_to_headless'] = True
            result['escalation_reasons'] = reasons
