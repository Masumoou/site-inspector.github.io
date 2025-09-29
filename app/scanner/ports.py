import os
from typing import Dict, Any

HAS_NMAP = False
try:
    import nmap  # python-nmap; requires nmap installed on host
    HAS_NMAP = True
except Exception:
    HAS_NMAP = False

DEFAULT_PORTS = "80,443,8080,8443,22,25,53,110,143,465,587,993,995,3389,3306,5432,6379,9200"

def run_port_scan(hostname: str) -> Dict[str, Any]:
    if os.getenv("ENABLE_PORT_SCAN", "false").lower() != "true":
        return {"enabled": False, "results": {}}
    if not HAS_NMAP:
        return {"enabled": True, "error": "python-nmap or nmap binary not found"}
    nm = nmap.PortScanner()
    ports = os.getenv("PORTS", DEFAULT_PORTS)
    try:
        nm.scan(hosts=hostname, arguments=f"-Pn -T4 -p {ports}")
        results = {}
        for h in nm.all_hosts():
            results[h] = {}
            for proto in nm[h].all_protocols():
                lport = nm[h][proto].keys()
                for p in sorted(lport):
                    svc = nm[h][proto][p]
                    results[h][p] = {"state": svc.get('state'), "name": svc.get('name')}
        return {"enabled": True, "results": results}
    except Exception as e:
        return {"enabled": True, "error": str(e)}

