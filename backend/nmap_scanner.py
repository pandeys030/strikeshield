"""
StrikeShield - Nmap Scanner Module
Wraps python-nmap to perform reconnaissance scans.
"""

import nmap
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

_scan_history: list = []


def _build_result(nm: nmap.PortScanner, target: str, scan_type: str) -> dict:
    """Convert nmap scan result into a clean dict."""
    hosts = []
    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname() or "N/A",
            "state": nm[host].state(),
            "os": [],
            "ports": [],
        }

        # OS detection
        if "osmatch" in nm[host]:
            for os in nm[host]["osmatch"][:3]:
                host_data["os"].append({
                    "name": os.get("name", "Unknown"),
                    "accuracy": os.get("accuracy", "0"),
                })

        # Port enumeration
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                port_info = nm[host][proto][port]
                host_data["ports"].append({
                    "port": port,
                    "protocol": proto.upper(),
                    "state": port_info.get("state", "unknown"),
                    "service": port_info.get("name", "unknown"),
                    "version": port_info.get("version", ""),
                    "product": port_info.get("product", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                })

        hosts.append(host_data)

    result = {
        "id": len(_scan_history) + 1,
        "target": target,
        "scan_type": scan_type,
        "timestamp": datetime.now().isoformat(),
        "hosts_found": len(hosts),
        "hosts": hosts,
        "command": nm.command_line(),
        "scan_stats": nm.scanstats(),
    }
    _scan_history.append(result)
    return result


def quick_scan(target: str) -> dict:
    """Fast ping scan — discovers live hosts."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sn -T4")
        return _build_result(nm, target, "Quick Scan (Ping)")
    except Exception as e:
        logger.error(f"Quick scan failed: {e}")
        return {"error": str(e), "target": target}


def port_scan(target: str, ports: str = "1-1024") -> dict:
    """TCP SYN scan on specified port range."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports, arguments="-sS -T4 -Pn")
        return _build_result(nm, target, f"Port Scan ({ports})")
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
        return {"error": str(e), "target": target}


def service_version_scan(target: str) -> dict:
    """Service and version detection scan."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sV -T4 -Pn --version-intensity 5")
        return _build_result(nm, target, "Service Version Detection")
    except Exception as e:
        logger.error(f"Service scan failed: {e}")
        return {"error": str(e), "target": target}


def os_detection_scan(target: str) -> dict:
    """OS fingerprinting scan (requires root)."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-O -T4 -Pn")
        return _build_result(nm, target, "OS Detection")
    except Exception as e:
        logger.error(f"OS detection scan failed: {e}")
        return {"error": str(e), "target": target}


def aggressive_scan(target: str) -> dict:
    """Full aggressive scan: OS + version + scripts + traceroute."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-A -T4 -Pn")
        return _build_result(nm, target, "Aggressive Scan (-A)")
    except Exception as e:
        logger.error(f"Aggressive scan failed: {e}")
        return {"error": str(e), "target": target}


def vulnerability_scan(target: str) -> dict:
    """Run NSE vuln scripts on target."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="--script vuln -T4 -Pn")
        return _build_result(nm, target, "Vulnerability Scan (NSE)")
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        return {"error": str(e), "target": target}


def get_scan_history() -> list:
    return list(reversed(_scan_history))


SCAN_TYPES = {
    "quick": quick_scan,
    "port": port_scan,
    "service": service_version_scan,
    "os": os_detection_scan,
    "aggressive": aggressive_scan,
    "vuln": vulnerability_scan,
}


def run_scan(scan_type: str, target: str, **kwargs) -> dict:
    """Dispatch scan by type string."""
    fn = SCAN_TYPES.get(scan_type)
    if not fn:
        return {"error": f"Unknown scan type: {scan_type}"}
    return fn(target, **kwargs)