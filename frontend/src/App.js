import { useState, useEffect, useRef } from "react";
import { Shield, LayoutDashboard, AlertTriangle, Ban, Activity, Globe, Zap, Wifi, WifiOff } from "lucide-react";
import { socket } from "./api/client";
import Dashboard from "./components/Dashboard";
import AlertFeed from "./components/AlertFeed";
import BlockedIPs from "./components/BlockedIPs";
import TrafficChart from "./components/TrafficChart";
import NmapScanner from "./components/NmapScanner";
import AttackSimulator from "./components/AttackSimulator";
import "./App.css";

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "alerts", label: "Alert Feed", icon: AlertTriangle },
  { id: "traffic", label: "Traffic", icon: Activity },
  { id: "blocked", label: "Blocked IPs", icon: Ban },
  { id: "scanner", label: "Nmap Scanner", icon: Globe },
  { id: "simulator", label: "Attack Sim", icon: Zap },
];

export default function App() {
  const [view, setView] = useState("dashboard");
  const [connected, setConnected] = useState(false);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [liveTraffic, setLiveTraffic] = useState(null);
  const [liveBlockedIP, setLiveBlockedIP] = useState(null);
  const [activeAttacks, setActiveAttacks] = useState([]);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [scanResultHandler, setScanResultHandler] = useState(null);
  const alertCountRef = useRef(0);

  useEffect(() => {
    socket.on("connect", () => setConnected(true));
    socket.on("disconnect", () => setConnected(false));

    socket.on("new_alert", (alert) => {
      alertCountRef.current += 1;
      setLiveAlerts((prev) => [...prev.slice(-200), alert]);
    });

    socket.on("traffic_update", (point) => {
      setLiveTraffic(point);
    });

    socket.on("ip_blocked", (entry) => {
      setLiveBlockedIP(entry);
      setBlockedIPs((prev) => {
        if (prev.find((i) => i.ip === entry.ip)) return prev;
        return [entry, ...prev];
      });
    });

    socket.on("ip_unblocked", ({ ip }) => {
      setBlockedIPs((prev) => prev.filter((i) => i.ip !== ip));
    });

    socket.on("scan_complete", (result) => {
      if (scanResultHandler) scanResultHandler(result);
    });

    return () => socket.removeAllListeners();
  }, [scanResultHandler]);

  const criticalCount = liveAlerts.filter((a) => a.severity === "critical").length;

  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <Shield size={28} className="brand-icon" />
          <div>
            <div className="brand-name">StrikeShield</div>
            <div className="brand-ver">v1.0 · Lab Edition</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-item ${view === id ? "active" : ""}`}
              onClick={() => setView(id)}
            >
              <Icon size={17} />
              <span>{label}</span>
              {id === "alerts" && criticalCount > 0 && (
                <span className="nav-badge">{criticalCount}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className={`conn-status ${connected ? "ok" : "error"}`}>
            {connected ? <Wifi size={13} /> : <WifiOff size={13} />}
            <span>{connected ? "Connected" : "Disconnected"}</span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        {view === "dashboard" && (
          <Dashboard
            alerts={liveAlerts}
            blockedIPs={blockedIPs}
            activeAttacks={activeAttacks}
          />
        )}
        {view === "alerts" && <AlertFeed liveAlerts={liveAlerts} />}
        {view === "traffic" && <TrafficChart livePoint={liveTraffic} />}
        {view === "blocked" && (
          <BlockedIPs liveBlockedIP={liveBlockedIP} />
        )}
        {view === "scanner" && (
          <NmapScanner
            onScanComplete={(handler) => setScanResultHandler(() => handler)}
          />
        )}
        {view === "simulator" && <AttackSimulator />}
      </main>
    </div>
  );
}