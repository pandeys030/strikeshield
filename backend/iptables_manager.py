"""
StrikeShield - iptables Manager
Handles IP blocking, unblocking, rate limiting via iptables.
Requires root/sudo privileges to run iptables commands.
"""

import subprocess
import logging
import re
from datetime import datetime
from threading import Lock

logger = logging.getLogger(__name__)

_blocked_ips: dict = {}  # ip -> {blocked_at, reason, rule_id}
_lock = Lock()

# Demo mode: if True, simulates iptables commands without actually running them
DEMO_MODE = True  # Set to False on a real Linux system with root

def set_demo_mode(enabled: bool):
    global DEMO_MODE
    DEMO_MODE = enabled
    logger.info(f"iptables_manager DEMO_MODE set to {DEMO_MODE}")


def _run(cmd: list[str]) -> tuple[bool, str]:
    """Run a shell command, return (success, output)."""
    if DEMO_MODE:
        logger.info(f"[DEMO] Would run: {' '.join(cmd)}")
        return True, "[demo output]"
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            logger.error(f"Command failed: {result.stderr}")
            return False, result.stderr
        return True, result.stdout
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except PermissionError:
        return False, "Permission denied — run as root"
    except FileNotFoundError:
        return False, "iptables not found on this system"


def _is_valid_ip(ip: str) -> bool:
    pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if not pattern.match(ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


def block_ip(ip: str, reason: str = "DDoS Attack Detected") -> dict:
    """Block an IP address using iptables DROP rule."""
    if not _is_valid_ip(ip):
        return {"success": False, "error": f"Invalid IP: {ip}"}

    with _lock:
        if ip in _blocked_ips:
            return {"success": False, "error": f"{ip} is already blocked"}

    if DEMO_MODE:
        logger.info(f"[DEMO] Simulating block for {ip}")
    else:
        # Drop all incoming packets from this IP
        ok, out = _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        if not ok:
            return {"success": False, "error": out}

        # Also drop forwarded packets
        _run(["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"])

    timestamp = datetime.now().isoformat()
    entry = {
        "ip": ip,
        "blocked_at": timestamp,
        "reason": reason,
        "status": "blocked",
    }

    with _lock:
        _blocked_ips[ip] = entry

    logger.info(f"Blocked IP: {ip} | Reason: {reason}")
    return {
        "success": True, 
        "data": {
            "ip": ip,
            "reason": reason,
            "timestamp": timestamp
        }
    }


def unblock_ip(ip: str) -> dict:
    """Remove iptables DROP rule for an IP."""
    if not _is_valid_ip(ip):
        return {"success": False, "error": f"Invalid IP: {ip}"}

    with _lock:
        if ip not in _blocked_ips:
            return {"success": False, "error": f"{ip} is not in the block list"}

    ok, out = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    if not ok:
        return {"success": False, "error": out}

    _run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])

    with _lock:
        removed = _blocked_ips.pop(ip, None)

    logger.info(f"Unblocked IP: {ip}")
    return {"success": True, "data": {"ip": ip, "unblocked_at": datetime.now().isoformat()}}


def rate_limit_ip(ip: str, limit: str = "10/min") -> dict:
    """Apply rate limiting to an IP instead of outright blocking."""
    if not _is_valid_ip(ip):
        return {"success": False, "error": f"Invalid IP: {ip}"}

    # Allow only `limit` packets per minute, drop the rest
    ok1, _ = _run([
        "iptables", "-A", "INPUT", "-s", ip,
        "-m", "limit", "--limit", limit, "--limit-burst", "5",
        "-j", "ACCEPT"
    ])
    ok2, _ = _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

    if ok1 and ok2:
        return {"success": True, "data": {"ip": ip, "rate_limit": limit}}
    return {"success": False, "error": "Failed to apply rate limit rules"}


def apply_syn_flood_protection() -> dict:
    """Apply global SYN flood protection rules."""
    cmds = [
        # Limit SYN packets globally
        ["iptables", "-A", "INPUT", "-p", "tcp", "--syn",
         "-m", "limit", "--limit", "1/s", "--limit-burst", "3", "-j", "ACCEPT"],
        ["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-j", "DROP"],
        # Enable SYN cookies (kernel-level)
        ["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
        # Limit ICMP flood
        ["iptables", "-A", "INPUT", "-p", "icmp",
         "-m", "limit", "--limit", "1/s", "--limit-burst", "5", "-j", "ACCEPT"],
        ["iptables", "-A", "INPUT", "-p", "icmp", "-j", "DROP"],
    ]
    results = []
    for cmd in cmds:
        ok, out = _run(cmd)
        results.append({"cmd": " ".join(cmd), "success": ok})

    return {"success": True, "rules_applied": results}


def flush_all_rules() -> dict:
    """Flush ALL iptables INPUT rules. Use with caution."""
    ok, out = _run(["iptables", "-F", "INPUT"])
    if ok:
        with _lock:
            _blocked_ips.clear()
        return {"success": True, "message": "All INPUT rules flushed"}
    return {"success": False, "error": out}


def get_blocked_ips() -> list:
    with _lock:
        return list(_blocked_ips.values())


def get_current_rules() -> dict:
    """Return current iptables rules as text."""
    ok, out = _run(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
    return {"success": ok, "rules": out}


def save_rules() -> dict:
    """Persist rules so they survive reboot."""
    ok, out = _run(["iptables-save"])
    if ok:
        try:
            if not DEMO_MODE:
                with open("/etc/iptables/rules.v4", "w") as f:
                    f.write(out)
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": ok, "message": "Rules saved" if ok else out}