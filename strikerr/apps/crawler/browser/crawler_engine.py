# strikerr/apps/crawler/browser/crawler_engine.py
import hashlib
from typing import Dict, Any, Optional
from strikerr.apps.crawler.browser.browser_factory import StealthBrowserFactory
from strikerr.apps.crawler.browser.cdp_guard import CDPGuard
from strikerr.apps.crawler.browser.navigation_guard import NavigationLoopGuard, install_dom_depth_guard

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

class HeadlessCrawlerEngine:
    """Layer 2 Headless Crawler: Executes sandboxed Playwright with anti-cloaking & OpSec locks."""

    @classmethod
    async def crawl_url(
        cls, 
        target_url: str, 
        proxy_url: Optional[str] = None,
        timeout_ms: int = 12000
    ) -> Dict[str, Any]:
        result = {
            'status': 'SUCCESS',
            'target_url': target_url,
            'final_url': target_url,
            'dom_html': '',
            'dom_sha256': '',
            'screenshot_bytes': None,
            'screenshot_sha256': '',
            'network_requests': [],
            'error': None
        }

        if not HAS_PLAYWRIGHT:
            result['status'] = 'PLAYWRIGHT_NOT_INSTALLED'
            result['error'] = 'Playwright is not installed in the current environment'
            return result

        async with async_playwright() as pw:
            browser = await StealthBrowserFactory.create_browser(pw)
            try:
                context = await StealthBrowserFactory.create_stealth_context(browser, proxy_url=proxy_url)
                page = await context.new_page()

                # Track network requests
                requests_log = []
                page.on("request", lambda req: requests_log.append({
                    'url': req.url,
                    'method': req.method,
                    'resource_type': req.resource_type,
                    'headers': dict(req.headers)
                }))

                # Apply CDP Security Lock & DOM Depth Guard
                await CDPGuard.apply_security_lock(page)
                await install_dom_depth_guard(page)

                # Execute Navigation with Timeout
                try:
                    response = await page.goto(
                        target_url, 
                        wait_until='domcontentloaded', 
                        timeout=timeout_ms
                    )
                    # Allow brief hydration window for dynamic content / SPA
                    await page.wait_for_timeout(1500)
                except Exception as nav_err:
                    result['status'] = 'NAVIGATION_TIMEOUT_OR_FAILED'
                    result['error'] = str(nav_err)

                result['final_url'] = page.url
                result['network_requests'] = requests_log[:100]  # Cap to first 100 requests

                # Extract post-hydration DOM
                try:
                    dom_html = await page.content()
                    result['dom_html'] = dom_html
                    result['dom_sha256'] = hashlib.sha256(dom_html.encode('utf-8')).hexdigest()
                except Exception as dom_err:
                    result['dom_html'] = ''
                    result['error'] = f"DOM extraction error: {dom_err}"

                # Capture full-page screenshot
                try:
                    screenshot = await page.screenshot(full_page=True, type='png')
                    result['screenshot_bytes'] = screenshot
                    result['screenshot_sha256'] = hashlib.sha256(screenshot).hexdigest()
                except Exception as ss_err:
                    # Fallback to viewport screenshot if full-page capture fails on huge heights
                    try:
                        screenshot = await page.screenshot(full_page=False, type='png')
                        result['screenshot_bytes'] = screenshot
                        result['screenshot_sha256'] = hashlib.sha256(screenshot).hexdigest()
                    except Exception:
                        pass

                await context.close()
            finally:
                await browser.close()

        return result
