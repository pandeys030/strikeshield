"""
StrikeShield - Flask API Server
Real-time DDoS detection and defense dashboard backend.
"""

import threading
import random
import time
import logging
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

import snort_parser
import iptables_manager
import nmap_scanner
import attack_simulator

# ── App setup ──────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = "strikeshield-secret-2024"

CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
)

# ── Live traffic simulation (for demo dashboard) ────────────────────────────
_traffic_history = []


def _traffic_simulator():
    """Emit fake real-time traffic data every second for the dashboard chart."""
    base_pps = 500
    attack_active = False
    attack_burst = 0

    while True:
        time.sleep(1)
        active = attack_simulator.get_active_attacks()
        if active:
            attack_active = True
            attack_burst = random.randint(20000, 80000)
        else:
            attack_active = False
            attack_burst = 0

        if attack_active:
            pps = attack_burst + random.randint(-2000, 2000)
            mbps = round(pps * 0.008 + random.uniform(-5, 5), 2)
        else:
            pps = base_pps + random.randint(-100, 300)
            mbps = round(pps * 0.004 + random.uniform(-0.5, 0.5), 2)

        point = {
            "timestamp": datetime.now().isoformat(),
            "pps": max(0, pps),
            "mbps": max(0, mbps),
            "attack_active": attack_active,
        }
        _traffic_history.append(point)
        if len(_traffic_history) > 300:
            _traffic_history.pop(0)

        socketio.emit("traffic_update", point)


# ── Routes: Health ──────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "StrikeShield",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
    })


# ── Routes: Dashboard Stats ─────────────────────────────────────────────────

@app.route("/api/stats")
def stats():
    alert_stats = snort_parser.get_alert_stats()
    blocked = iptables_manager.get_blocked_ips()
    active_attacks = attack_simulator.get_active_attacks()
    return jsonify({
        "alerts": alert_stats,
        "blocked_ips_count": len(blocked),
        "active_attacks": len(active_attacks),
        "traffic_points": len(_traffic_history),
        "uptime": "online",
    })


@app.route("/api/traffic/history")
def traffic_history():
    limit = request.args.get("limit", 60, type=int)
    return jsonify(_traffic_history[-limit:])


# ── Routes: Alerts ──────────────────────────────────────────────────────────

@app.route("/api/alerts")
def get_alerts():
    limit = request.args.get("limit", 50, type=int)
    severity = request.args.get("severity")
    alerts = snort_parser.get_all_alerts()
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    return jsonify(alerts[:limit])


@app.route("/api/alerts/stats")
def alert_stats():
    return jsonify(snort_parser.get_alert_stats())


# ── Routes: IP Blocking ─────────────────────────────────────────────────────

@app.route("/api/blocked-ips", methods=["GET"])
def get_blocked_ips():
    return jsonify(iptables_manager.get_blocked_ips())


@app.route("/api/blocked-ips/block", methods=["POST"])
def block_ip():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "Manual block")
    if not ip:
        return jsonify({"success": False, "error": "IP is required"}), 400
    result = iptables_manager.block_ip(ip, reason)
    if result["success"]:
        socketio.emit("ip_blocked", result["data"])
    return jsonify(result), 200 if result["success"] else 400


@app.route("/api/blocked-ips/unblock", methods=["POST"])
def unblock_ip():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP is required"}), 400
    result = iptables_manager.unblock_ip(ip)
    if result["success"]:
        socketio.emit("ip_unblocked", {"ip": ip})
    return jsonify(result), 200 if result["success"] else 400


@app.route("/api/blocked-ips/flush", methods=["POST"])
def flush_rules():
    result = iptables_manager.flush_all_rules()
    return jsonify(result)


@app.route("/api/blocked-ips/syn-protection", methods=["POST"])
def syn_protection():
    result = iptables_manager.apply_syn_flood_protection()
    return jsonify(result)


# ── Routes: Nmap Scanner ────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def run_scan():
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "quick")
    ports = data.get("ports", "1-1024")

    if not target:
        return jsonify({"error": "target is required"}), 400

    kwargs = {}
    if scan_type == "port":
        kwargs["ports"] = ports

    socketio.emit("scan_started", {"target": target, "scan_type": scan_type})

    def _do_scan():
        result = nmap_scanner.run_scan(scan_type, target, **kwargs)
        socketio.emit("scan_complete", result)

    threading.Thread(target=_do_scan, daemon=True).start()
    return jsonify({"status": "started", "target": target, "scan_type": scan_type})


@app.route("/api/scan/history")
def scan_history():
    return jsonify(nmap_scanner.get_scan_history())


# ── Routes: Attack Simulator ────────────────────────────────────────────────

@app.route("/api/attack/profiles")
def attack_profiles():
    return jsonify(attack_simulator.get_attack_profiles())


@app.route("/api/attack/start", methods=["POST"])
def start_attack():
    data = request.get_json(force=True)
    attack_type = data.get("attack_type")
    target = data.get("target", "127.0.0.1")
    port = data.get("port", 80)
    duration = min(data.get("duration", 30), 120)  # Cap at 2 minutes

    if not attack_type:
        return jsonify({"success": False, "error": "attack_type required"}), 400

    result = attack_simulator.start_attack(
        attack_type=attack_type,
        target=target,
        port=port,
        duration=duration,
        socketio=socketio,
        app=app,
    )
    return jsonify(result), 200 if result["success"] else 400


@app.route("/api/attack/stop", methods=["POST"])
def stop_attack():
    data = request.get_json(force=True)
    attack_id = data.get("attack_id")
    if not attack_id:
        return jsonify({"success": False, "error": "attack_id required"}), 400
    result = attack_simulator.stop_attack(attack_id)
    return jsonify(result)


@app.route("/api/attack/stop-all", methods=["POST"])
def stop_all():
    result = attack_simulator.stop_all_attacks()
    return jsonify(result)


@app.route("/api/attack/active")
def active_attacks():
    return jsonify(attack_simulator.get_active_attacks())


@app.route("/api/attack/history")
def attack_history():
    return jsonify(attack_simulator.get_attack_history())


# ── SocketIO events ─────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    logger.info(f"Client connected: {request.sid}")
    emit("connected", {"message": "StrikeShield connected", "sid": request.sid})


@socketio.on("disconnect")
def on_disconnect():
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on("ping_server")
def on_ping(data):
    emit("pong_server", {"ts": datetime.now().isoformat()})


# ── Startup ─────────────────────────────────────────────────────────────────

def start_background_services():
    # Start Snort log tailer
    snort_thread = threading.Thread(
        target=snort_parser.tail_snort_log,
        args=(socketio, app),
        daemon=True,
    )
    snort_thread.start()

    # Start traffic simulator
    traffic_thread = threading.Thread(target=_traffic_simulator, daemon=True)
    traffic_thread.start()

    logger.info("StrikeShield background services started.")


if __name__ == "__main__":
    start_background_services()
    logger.info("Starting StrikeShield on http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=False)