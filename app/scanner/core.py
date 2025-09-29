import aiohttp
import asyncio
from datetime import datetime
from typing import Dict, List
from bs4 import BeautifulSoup
from app.scanner.utils import normalize_url, hostname_from_url
from app.scanner.headers import SEC_HEADER_ADVICE, CDN_WAF_HINTS, CLOUD_HINTS, FRAMEWORK_SIGNS
from app.scanner.cookies import parse_cookies
from app.scanner.dns_cloud import cloud_hints_from_dns
from app.scanner.cms_wp import detect_wordpress
from app.scanner.ports import run_port_scan

async def scan_target(url: str) -> Dict:
    url = normalize_url(url)
    started = datetime.utcnow().isoformat() + 'Z'
    
    # Data structure to store general information
    general: Dict = {
        "final_url": None,
        "status_code": None,
        "server": None,
        "x_powered_by": None,
        "techs": [],
        "cdn_waf": [],
        "cloud": []
    }
    
    sec_headers: List[Dict] = []
    cookies: List[Dict] = []
    wordpress: Dict = {"detected": False, "version": None, "plugins": [], "theme": None}
    notes: List[str] = []

    async with aiohttp.ClientSession(raise_for_status=False) as session:
        # Fetch homepage
        try:
            async with session.get(url, allow_redirects=True, timeout=10) as r:
                # Capture general info
                general["final_url"] = str(r.url)
                general["status_code"] = r.status
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                general["server"] = hdrs.get("server")
                general["x_powered_by"] = hdrs.get("x-powered-by")

                # Process security headers
                for name, advice in SEC_HEADER_ADVICE.items():
                    val = r.headers.get(name)
                    sec_headers.append({
                        "name": name,
                        "value": val,
                        "advice": advice if not val else None
                    })

                # Parse cookies
                set_cookie = r.headers.getall("Set-Cookie", []) if hasattr(r.headers, 'getall') else r.headers.get("set-cookie", "").split("\n")
                cookies = parse_cookies(set_cookie) if set_cookie else []

                # Detect technologies from headers
                techs = []
                if general["x_powered_by"]:
                    techs.append(general["x_powered_by"])
                if general["server"]:
                    techs.append(general["server"])

                # Detect CDN/WAF from headers
                cdn = []
                for key, label in CDN_WAF_HINTS:
                    for hname, hval in hdrs.items():
                        if key in hname or (hval and key in hval.lower()):
                            cdn.append(label)
                general["cdn_waf"] = sorted(list(set(cdn)))

                # Detect cloud service from headers
                cloud = []
                for key, label in CLOUD_HINTS:
                    for hname, hval in hdrs.items():
                        if (hname.startswith(key)) or (hval and key in hval.lower()):
                            cloud.append(label)
                general["cloud"] = sorted(list(set(cloud)))

                # HTML parse for meta generator & frameworks
                text = await r.text(errors="ignore")
                soup = BeautifulSoup(text, "html.parser")
                
                # Check for meta generator tag
                gen = soup.find("meta", attrs={"name": "generator"})
                if gen and gen.get("content"):
                    techs.append(gen.get("content"))

                body_html = str(soup)
                for fw, needles in FRAMEWORK_SIGNS:
                    if any(n in body_html for n in needles):
                        techs.append(fw)

                # Add jQuery detection
                if "jquery" in body_html.lower():
                    techs.append("jquery")

                general["techs"] = sorted(list(set([t.strip() for t in techs if t])))

                # Detect WordPress if it's a WordPress site
                wp = await detect_wordpress(session, general["final_url"])
                wordpress.update(wp)
        except Exception as e:
            notes.append(f"Fetch error: {e}")

    # DNS/CDN hints via CNAME
    try:
        general["cloud"] = sorted(list(set(general["cloud"] + (await cloud_hints_from_dns(url)))))
    except Exception:
        pass

    # Optional port scan
    host = hostname_from_url(url)
    ports = run_port_scan(host) if host else {"enabled": False, "results": {}}

    # Recommendations based on headers
    if not any(h for h in sec_headers if h["name"] == "Strict-Transport-Security" and h["value"]):
        notes.append("Enable HSTS for HTTPS sites.")
    if not any(h for h in sec_headers if h["name"] == "Content-Security-Policy" and h["value"]):
        notes.append("Add a Content-Security-Policy.")
    if not any(h for h in sec_headers if h["name"] == "X-Content-Type-Options" and h["value"]):
        notes.append("Add X-Content-Type-Options: nosniff.")

    finished = datetime.utcnow().isoformat() + 'Z'
    
    return {
        "started": started,
        "finished": finished,
        "general": general,
        "security": {"headers": sec_headers, "cookies": cookies},
        "wordpress": wordpress,
        "ports": ports,
        "notes": notes,
    }

