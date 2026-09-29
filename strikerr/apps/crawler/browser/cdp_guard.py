# strikerr/apps/crawler/browser/cdp_guard.py
from urllib.parse import urlparse
from typing import Set
from strikerr.apps.crawler.security.safe_transport import SafeDNSResolver, SSRFSecurityException

class CDPGuard:
    """Enforces Chrome DevTools Protocol security policies and intercepts dangerous payloads."""

    BLOCKED_FILE_EXTENSIONS: Set[str] = {
        '.apk', '.exe', '.sh', '.bat', '.msi', '.vbs', '.scr', '.pif',
        '.cmd', '.ps1', '.jar', '.bin', '.iso', '.dmg'
    }

    BLOCKED_MIME_PREFIXES: Set[str] = {
        'application/vnd.android.package-archive',
        'application/x-msdownload',
        'application/x-sh',
        'application/x-executable',
        'application/octet-stream',
    }

    @classmethod
    async def apply_security_lock(cls, page):
        """Applies download denial and installs route-level interception."""
        # 1. Deny downloads via CDP
        try:
            cdp_session = await page.context.new_cdp_session(page)
            await cdp_session.send('Page.setDownloadBehavior', {'behavior': 'deny'})
        except Exception:
            pass

        # 2. Intercept and abort dangerous downloads and SSRF routes
        async def route_interceptor(route):
            req = route.request
            url = req.url
            parsed = urlparse(url)

            # Allow safe protocol schemes
            if parsed.scheme in ('data', 'blob'):
                await route.continue_()
                return

            if parsed.scheme not in ('http', 'https'):
                await route.abort('blockedbyclient')
                return

            # Terminate dangerous file downloads
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in cls.BLOCKED_FILE_EXTENSIONS):
                await route.abort('blockedbyclient')
                return

            # SSRF check for every sub-resource request
            hostname = parsed.hostname
            if hostname:
                try:
                    SafeDNSResolver.resolve_and_verify(hostname)
                except SSRFSecurityException:
                    await route.abort('accessdenied')
                    return

            await route.continue_()

        await page.route('**/*', route_interceptor)
