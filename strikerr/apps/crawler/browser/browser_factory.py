# strikerr/apps/crawler/browser/browser_factory.py
import random
from typing import Dict, Any, Optional

try:
    from playwright.async_api import Playwright, Browser, BrowserContext
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# Indonesian Mobile Device Footprints (Samsung Galaxy & Oppo)
ID_MOBILE_PROFILES = [
    {
        'user_agent': 'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36',
        'viewport': {'width': 412, 'height': 915},
        'device_scale_factor': 3.5,
        'is_mobile': True,
        'has_touch': True,
    },
    {
        'user_agent': 'Mozilla/5.0 (Linux; Android 13; CPH2451) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36',
        'viewport': {'width': 393, 'height': 873},
        'device_scale_factor': 2.75,
        'is_mobile': True,
        'has_touch': True,
    },
    {
        'user_agent': 'Mozilla/5.0 (Linux; Android 14; 23127PN0CG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.103 Mobile Safari/537.36',
        'viewport': {'width': 393, 'height': 852},
        'device_scale_factor': 3.0,
        'is_mobile': True,
        'has_touch': True,
    }
]

class StealthBrowserFactory:
    """Spawns sandboxed, anti-detect Chromium contexts with Indonesian localized mobile environments."""

    @classmethod
    async def create_browser(cls, playwright: 'Playwright') -> 'Browser':
        return await playwright.chromium.launch(
            headless=True,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                '--disable-gpu',
                '--disable-extensions',
                '--disable-background-networking',
                '--disable-default-apps',
                '--disable-sync',
                '--no-first-run',
                '--disk-cache-size=1',
                '--media-cache-size=1',
                '--js-flags="--max-old-space-size=512"',
            ]
        )

    @classmethod
    async def create_stealth_context(
        cls, 
        browser: 'Browser', 
        proxy_url: Optional[str] = None
    ) -> 'BrowserContext':
        profile = random.choice(ID_MOBILE_PROFILES)
        
        proxy_config = None
        if proxy_url:
            proxy_config = {'server': proxy_url}

        context = await browser.new_context(
            **profile,
            proxy=proxy_config,
            locale='id-ID',
            timezone_id='Asia/Jakarta',
            extra_http_headers={
                'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
                'Sec-Ch-Ua-Platform': '"Android"',
                'Sec-Ch-Ua-Mobile': '?1',
                'Upgrade-Insecure-Requests': '1',
            }
        )

        # Cloak webdriver properties to evade anti-bot checks (Cloudflare Turnstile, Datadome)
        await context.add_init_script("""
            // Overwrite navigator.webdriver
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });

            // Mock window.chrome runtime
            window.navigator.chrome = {
                runtime: {},
                loadTimes: function() {},
                csi: function() {},
                app: {}
            };

            // Mock standard Android touch plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5]
            });
        """)

        return context
