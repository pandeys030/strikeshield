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

# In-memory alert store (for demo/fallback when Snort is not running)
_alerts = []
_alert_lock = threading.Lock()
_alert_id_counter = 0

# Traffic stats per source IP
_ip_packet_counts = defaultdict(int)
_ip_alert_counts = defaultdict(int)


def _next_id():
    global _alert_id_counter
    _alert_id_counter += 1
    return _alert_id_counter


def parse_snort_line(raw_block: str) -> dict | None:
    """
    Parse a single Snort alert block into a structured dict.
    Snort alert format:
        [**] [1:1000001:1] STRIKESHIELD SYN Flood Detected [**]
        [Classification: Attempted Denial of Service] [Priority: 1]
        01/15-14:23:45.123456 192.168.1.50:4444 -> 192.168.1.10:80
        TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:40
        ******S* Seq: 0x1A2B3C4D  Ack: 0x0  Win: 0x200  TcpLen: 20
    """
    try:
        msg_match = re.search(r'\[\*\*\]\s+\[[\d:]+\]\s+(.+?)\s+\[\*\*\]', raw_block)
        if not msg_match:
            return None

        message = msg_match.group(1).strip()

        # Classification and priority
        class_match = re.search(r'\[Classification:\s*(.+?)\]', raw_block)
        prio_match = re.search(r'\[Priority:\s*(\d+)\]', raw_block)
        classification = class_match.group(1).strip() if class_match else "Unknown"
        priority = int(prio_match.group(1)) if prio_match else 3

        # Timestamp and IPs
        ip_match = re.search(
            r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
            r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s+->\s+'
            r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?',
            raw_block
        )
        if not ip_match:
            return None

        ts_raw, src_ip, src_port, dst_ip, dst_port = ip_match.groups()

        # Determine protocol
        protocol = "TCP"
        if "UDP" in raw_block:
            protocol = "UDP"
        elif "ICMP" in raw_block:
            protocol = "ICMP"

        # Determine attack type from message
        attack_type = _classify_attack(message)

        # Track per-IP counts
        _ip_packet_counts[src_ip] += 1
        _ip_alert_counts[src_ip] += 1

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
    except Exception:
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
    with _alert_lock:
        alert["id"] = _next_id()
        _alerts.append(alert)
        _ip_alert_counts[alert["src_ip"]] += 1


def tail_snort_log(socketio, app):
    """
    Background thread: tails the Snort alert file and emits alerts via SocketIO.
    Falls back gracefully if file doesn't exist.
    """
    if not os.path.exists(SNORT_ALERT_FILE):
        app.logger.warning(f"Snort alert file not found: {SNORT_ALERT_FILE}. Running in demo mode.")
        return

    with open(SNORT_ALERT_FILE, "r") as f:
        f.seek(0, 2)  # Seek to end of file
        buffer = []
        while True:
            line = f.readline()
            if line:
                if line.strip() == "":
                    if buffer:
                        block = "\n".join(buffer)
                        alert = parse_snort_line(block)
                        if alert:
                            with _alert_lock:
                                _alerts.append(alert)
                            with app.app_context():
                                socketio.emit("new_alert", alert)
                        buffer = []
                else:
                    buffer.append(line.rstrip())
            else:
                time.sleep(0.5)