import asyncio
import socket
from typing import List
from app.scanner.utils import hostname_from_url

try:
    import dns.resolver  # dnspython
except Exception:
    dns = None

CLOUD_CNAME_HINTS = {
    "cloudfront.net": "AWS CloudFront",
    "azureedge.net": "Azure CDN",
    "cdn.cloudflare.net": "Cloudflare",
    "fastly.net": "Fastly",
    "akamaiedge.net": "Akamai",
}

async def cloud_hints_from_dns(url: str) -> List[str]:
    hints = []
    host = hostname_from_url(url)
    if not host:
        return hints
    try:
        if dns:
            answers = dns.resolver.resolve(host, 'CNAME', lifetime=3.0)
            for r in answers:
                cname = str(r.target).lower()
                for suffix, label in CLOUD_CNAME_HINTS.items():
                    if cname.endswith(suffix):
                        hints.append(label)
        # A/AAAA lookup for IP (may reveal host range)
        socket.getaddrinfo(host, None)
    except Exception:
        pass
    return sorted(list(set(hints)))

