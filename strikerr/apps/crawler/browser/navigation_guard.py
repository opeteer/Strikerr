# strikerr/apps/crawler/browser/navigation_guard.py
from typing import Set

class NavigationLoopGuard:
    """Detects and terminates redirect cycles and excessive hop chains."""

    MAX_HOPS = 5

    def __init__(self, max_hops: int = 5):
        self.max_hops = max_hops
        self.visited_urls: Set[str] = set()
        self.hop_count = 0

    def evaluate_hop(self, incoming_url: str) -> bool:
        """Returns True if navigation is permitted, False if loop or limit exceeded."""
        normalized = incoming_url.strip().lower()
        self.hop_count += 1

        if self.hop_count > self.max_hops:
            return False

        if normalized in self.visited_urls:
            return False  # Circular redirect detected

        self.visited_urls.add(normalized)
        return True

async def install_dom_depth_guard(page, max_nodes: int = 25000, max_depth: int = 64):
    """Enforces DOM node count and nesting depth limits inside the Chromium process."""
    await page.add_init_script(f"""
        (function() {{
            const MAX_NODES = {max_nodes};
            const MAX_DEPTH = {max_depth};

            function checkDepth(node) {{
                let depth = 0;
                let current = node;
                while (current.parentNode) {{
                    depth++;
                    current = current.parentNode;
                    if (depth > MAX_DEPTH) return depth;
                }}
                return depth;
            }}

            const observer = new MutationObserver((mutations) => {{
                const allElements = document.getElementsByTagName('*');
                if (allElements.length > MAX_NODES) {{
                    window.stop();
                    observer.disconnect();
                    console.error('[STRIKERR_DOM_GUARD] Aborted render: Node limit exceeded.');
                }}
            }});

            if (document.documentElement) {{
                observer.observe(document.documentElement, {{ childList: true, subtree: true }});
            }} else {{
                document.addEventListener('DOMContentLoaded', () => {{
                    observer.observe(document.documentElement, {{ childList: true, subtree: true }});
                }});
            }}
        }})();
    """)
