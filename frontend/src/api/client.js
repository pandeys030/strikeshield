import axios from "axios";
import { io } from "socket.io-client";

const BASE_URL = process.env.REACT_APP_API_URL || process.env.VITE_API_URL || "http://localhost:5000";

// ── Axios instance ──────────────────────────────────────────────────────────
export const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.response.use(
  (res) => res.data,
  (err) => {
    const msg = err.response?.data?.error || err.message || "Request failed";
    return Promise.reject(new Error(msg));
  }
);

// ── Socket.IO instance ──────────────────────────────────────────────────────
export const socket = io(BASE_URL, {
  transports: ["websocket", "polling"],
  reconnection: true,
  reconnectionAttempts: 10,
  reconnectionDelay: 2000,
});

// ── API helpers ─────────────────────────────────────────────────────────────

// Dashboard
export const fetchStats = () => api.get("/api/stats");
export const fetchTrafficHistory = (limit = 60) =>
  api.get(`/api/traffic/history?limit=${limit}`);

// Alerts
export const fetchAlerts = (limit = 100, severity) => {
  const params = new URLSearchParams({ limit });
  if (severity) params.set("severity", severity);
  return api.get(`/api/alerts?${params}`);
};
export const fetchAlertStats = () => api.get("/api/alerts/stats");

// Blocked IPs
export const fetchBlockedIPs = () => api.get("/api/blocked-ips");
export const blockIP = (ip, reason) =>
  api.post("/api/blocked-ips/block", { ip, reason });
export const unblockIP = (ip) =>
  api.post("/api/blocked-ips/unblock", { ip });
export const flushAllRules = () => api.post("/api/blocked-ips/flush");
export const applySynProtection = () =>
  api.post("/api/blocked-ips/syn-protection");

// Nmap
export const runScan = (target, scan_type, ports) =>
  api.post("/api/scan", { target, scan_type, ports });
export const fetchScanHistory = () => api.get("/api/scan/history");

// Attack Simulator
export const fetchAttackProfiles = () => api.get("/api/attack/profiles");
export const startAttack = (attack_type, target, port, duration) =>
  api.post("/api/attack/start", { attack_type, target, port, duration });
export const stopAttack = (attack_id) =>
  api.post("/api/attack/stop", { attack_id });
export const stopAllAttacks = () => api.post("/api/attack/stop-all");
export const fetchActiveAttacks = () => api.get("/api/attack/active");
export const fetchAttackHistory = () => api.get("/api/attack/history");