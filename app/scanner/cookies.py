from typing import List, Dict

def parse_cookies(set_cookie_headers: List[str]) -> List[Dict]:
    cookies = []
    for raw in set_cookie_headers:
        parts = raw.split(";")
        if not parts:
            continue
        name_val = parts[0].strip()
        if "=" not in name_val:
            continue
        name, _ = name_val.split("=", 1)
        attrs = {p.strip().split("=", 1)[0].lower(): (p.strip().split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
        cookies.append({
            "name": name,
            "secure": bool(attrs.get("secure", False)),
            "httponly": bool(attrs.get("httponly", False)),
            "samesite": attrs.get("samesite", None),
        })
    return cookies

