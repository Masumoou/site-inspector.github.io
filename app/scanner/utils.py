from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def hostname_from_url(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or ""

