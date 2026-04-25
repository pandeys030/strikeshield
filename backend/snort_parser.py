"""
StrikeShield - Snort Alert Parser
Reads and parses Snort alert logs in real-time.
"""

import re
import os
import time
import threading
from datetime import datetime
from collections import defaultdict

# Path to Snort alert file (update if needed)
SNORT_ALERT_FILE = "/var/log/snort/alert"

# Global SocketIO and App instances
_socketio = None
_app = None

def init(socketio, app):
    global _socketio, _app
    _socketio = socketio
    _app = app

# In-memory alert store (for demo/fallback when Snort is not running)
_alerts = []
_alert_lock = threading.Lock()
_alert_id_counter = 0

# Traffic stats per source IP
_ip_packet_counts = defaultdict(int)
_ip_alert_counts = defaultdict(int)

import iptables_manager
import logging
logger = logging.getLogger(__name__)

def process_alert(alert: dict):
    """Centralized function to process all alerts (real or simulated)."""
    with _alert_lock:
        if "id" not in alert:
            alert["id"] = _next_id()
        _alerts.append(alert)
        _ip_alert_counts[alert["src_ip"]] += 1
    
    src_ip = alert.get("src_ip")
    if src_ip and src_ip != "N/A":
        # Automatically block the IP
        block_result = iptables_manager.block_ip(src_ip, f"Auto-blocked: {alert.get('attack_type', 'Unknown Attack')} detected")
        
        if _socketio and _app:
            with _app.app_context():
                _socketio.emit("new_alert", alert)
                if block_result.get("success"):
                    _socketio.emit("ip_blocked", block_result.get("data"))
                    logger.info(f"Alert processed and IP {src_ip} blocked.")
                elif "already blocked" not in block_result.get("error", ""):
                    logger.warning(f"Failed to auto-block {src_ip}: {block_result.get('error')}")

def _next_id():
    global _alert_id_counter
    _alert_id_counter += 1
    return _alert_id_counter


def parse_snort_line(raw_block: str) -> dict | None:
    try:
        # ===== SIMPLE FORMAT SUPPORT (YOUR CASE) =====
        if "detected from" in raw_block:
            parts = raw_block.strip().split()
            src_ip = parts[-1]

            return {
                "id": _next_id(),
                "timestamp": datetime.now().isoformat(),
                "raw_timestamp": datetime.now().isoformat(),
                "message": raw_block.strip(),
                "classification": "DoS",
                "priority": 2,
                "src_ip": src_ip,
                "src_port": None,
                "dst_ip": "N/A",
                "dst_port": None,
                "protocol": "TCP",
                "attack_type": _classify_attack(raw_block),
                "severity": "high",
            }

        # ===== ORIGINAL SNORT PARSER =====
        msg_match = re.search(r'\[\*\*\]\s+\[[\d:]+\]\s+(.+?)\s+\[\*\*\]', raw_block)
        if not msg_match:
            return None

        message = msg_match.group(1).strip()

        class_match = re.search(r'\[Classification:\s*(.+?)\]', raw_block)
        prio_match = re.search(r'\[Priority:\s*(\d+)\]', raw_block)
        classification = class_match.group(1).strip() if class_match else "Unknown"
        priority = int(prio_match.group(1)) if prio_match else 3

        ip_match = re.search(
            r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
            r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s+->\s+'
            r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?',
            raw_block
        )
        if not ip_match:
            return None

        ts_raw, src_ip, src_port, dst_ip, dst_port = ip_match.groups()

        protocol = "TCP"
        if "UDP" in raw_block:
            protocol = "UDP"
        elif "ICMP" in raw_block:
            protocol = "ICMP"

        attack_type = _classify_attack(message)

        return {
            "id": _next_id(),
            "timestamp": datetime.now().isoformat(),
            "raw_timestamp": ts_raw,
            "message": message,
            "classification": classification,
            "priority": priority,
            "src_ip": src_ip,
            "src_port": int(src_port) if src_port else None,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port) if dst_port else None,
            "protocol": protocol,
            "attack_type": attack_type,
            "severity": _priority_to_severity(priority),
        }

    except Exception as e:
        print("Parse error:", e)
        return None


def _classify_attack(message: str) -> str:
    msg = message.upper()
    if "SYN FLOOD" in msg:
        return "SYN Flood"
    elif "UDP FLOOD" in msg:
        return "UDP Flood"
    elif "ICMP FLOOD" in msg:
        return "ICMP Flood"
    elif "HTTP FLOOD" in msg:
        return "HTTP Flood"
    elif "DNS AMPLIFICATION" in msg:
        return "DNS Amplification"
    elif "PORT SCAN" in msg:
        return "Port Scan"
    elif "HPING3" in msg:
        return "Hping3 Attack"
    elif "LOIC" in msg:
        return "LOIC Attack"
    else:
        return "Unknown Attack"


def _priority_to_severity(priority: int) -> str:
    return {1: "critical", 2: "high", 3: "medium"}.get(priority, "low")


def get_all_alerts() -> list:
    with _alert_lock:
        return list(reversed(_alerts[-200:]))  # Return latest 200


def get_alert_stats() -> dict:
    with _alert_lock:
        total = len(_alerts)
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        by_ip = defaultdict(int)
        for a in _alerts:
            by_type[a["attack_type"]] += 1
            by_severity[a["severity"]] += 1
            by_ip[a["src_ip"]] += 1

        top_attackers = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_alerts": total,
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "top_attackers": [{"ip": ip, "count": c} for ip, c in top_attackers],
        }


def add_simulated_alert(alert: dict):
    """Inject a simulated alert (for demo/testing)."""
    process_alert(alert)


def tail_snort_log(socketio, app):
    if not os.path.exists(SNORT_ALERT_FILE):
        app.logger.warning(f"Snort alert file not found: {SNORT_ALERT_FILE}. Running in demo mode.")
        return

    with open(SNORT_ALERT_FILE, "r") as f:
        f.seek(0, 2)  # go to end

        while True:
            line = f.readline()

            if line:
                line = line.strip()

                if not line:
                    continue

                alert = parse_snort_line(line)

                if alert:
                    process_alert(alert)

            else:
                time.sleep(0.5)