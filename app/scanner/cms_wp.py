import asyncio
from typing import Dict, List, Optional
import aiohttp
import os
import re


async def detect_wordpress(session: aiohttp.ClientSession, base_url: str) -> Dict:
    data: Dict = {"detected": False, "version": None, "plugins": [], "theme": None}
    try:
        # Check generator meta via homepage fetch (caller provides)
        # Try wp-json
        async with session.get(base_url.rstrip('/') + '/wp-json', timeout=5) as r:
            if r.status == 200:
                js = await r.json(content_type=None)
                data["detected"] = True
                v = js.get("generator") or js.get("name")
                if isinstance(v, str):
                    data["version"] = v
    except Exception:
        pass

    # Lightweight plugin/theme hints
    # Only if explicitly enabled by env
    if os.getenv("ALLOW_ACTIVE_CHECKS", "false").lower() == "true":
        endpoints = [
            '/wp-content/plugins/',
            '/wp-content/themes/',
        ]
        for ep in endpoints:
            try:
                async with session.get(base_url.rstrip('/') + ep, timeout=5) as r:
                    if r.status == 200:
                        text = await r.text()
                        if 'plugins' in ep:
                            data["plugins"] = list(sorted(set(_extract_names(text))))
                        else:
                            themes = list(sorted(set(_extract_names(text))))
                            data["theme"] = themes[0] if themes else None
                        data["detected"] = True
            except Exception:
                pass

    return data


def _extract_names(html: str) -> List[str]:
    # crude directory listing name extractor
    return re.findall(r'>\s*([a-zA-Z0-9_-]+)/\s*<', html)

