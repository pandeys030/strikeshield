import { useState, useEffect } from "react";
import { Search, Server, Globe, ChevronDown, ChevronRight, Clock } from "lucide-react";
import { runScan, fetchScanHistory } from "../api/client";

const SCAN_TYPES = [
  { id: "quick", label: "Quick Scan", desc: "Ping sweep — discovers live hosts", icon: "🔍" },
  { id: "port", label: "Port Scan", desc: "TCP SYN scan on port range", icon: "🔌" },
  { id: "service", label: "Service Detection", desc: "Identifies running services + versions", icon: "⚙️" },
  { id: "os", label: "OS Detection", desc: "Fingerprints operating system (root required)", icon: "💻" },
  { id: "aggressive", label: "Aggressive (-A)", desc: "Full scan: OS + version + scripts", icon: "⚡" },
  { id: "vuln", label: "Vuln Scan", desc: "Runs Nmap NSE vuln scripts", icon: "🛡️" },
];

const STATE_COLOR = { open: "port-open", closed: "port-closed", filtered: "port-filtered" };

function PortRow({ p }) {
  return (
    <tr className="port-row">
      <td><span className={`port-num ${STATE_COLOR[p.state]}`}>{p.port}</span></td>
      <td><span className={`port-state ${STATE_COLOR[p.state]}`}>{p.state}</span></td>
      <td>{p.protocol}</td>
      <td>{p.service}</td>
      <td>{[p.product, p.version].filter(Boolean).join(" ") || "—"}</td>
    </tr>
  );
}

function HostCard({ host }) {
  const [expanded, setExpanded] = useState(true);
  const openPorts = host.ports.filter((p) => p.state === "open");
  return (
    <div className="host-card">
      <div className="host-header" onClick={() => setExpanded((v) => !v)}>
        <div className="host-info">
          <Server size={16} />
          <span className="host-ip">{host.ip}</span>
          {host.hostname !== "N/A" && <span className="host-name">({host.hostname})</span>}
          <span className={`host-state ${host.state === "up" ? "ok" : "danger"}`}>{host.state}</span>
        </div>
        <div className="host-meta">
          <span>{openPorts.length} open ports</span>
          {host.os?.[0] && <span className="host-os">{host.os[0].name} ({host.os[0].accuracy}%)</span>}
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>
      </div>
      {expanded && host.ports.length > 0 && (
        <div className="host-ports">
          <table className="port-table">
            <thead>
              <tr><th>Port</th><th>State</th><th>Proto</th><th>Service</th><th>Version</th></tr>
            </thead>
            <tbody>
              {host.ports.map((p) => <PortRow key={`${p.port}-${p.protocol}`} p={p} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function NmapScanner({ onScanComplete }) {
  const [target, setTarget] = useState("192.168.1.1");
  const [scanType, setScanType] = useState("port");
  const [ports, setPorts] = useState("1-1024");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchScanHistory().then(setHistory).catch(console.error);
  }, []);

  // Listen for scan_complete from socket (passed via prop or handled in App.jsx)
  useEffect(() => {
    if (onScanComplete) onScanComplete(handleScanResult);
  }, []);

  const handleScanResult = (data) => {
    setResult(data);
    setScanning(false);
    setHistory((prev) => [data, ...prev].slice(0, 20));
  };

  const handleScan = async () => {
    if (!target.trim()) return;
    setScanning(true);
    setError("");
    setResult(null);
    try {
      await runScan(target.trim(), scanType, ports);
      // Result will come via socket "scan_complete" event handled in App.jsx
    } catch (e) {
      setError(e.message);
      setScanning(false);
    }
  };

  return (
    <div className="panel nmap-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Globe size={18} />
          <span>Nmap Scanner</span>
        </div>
      </div>

      {/* Scan config */}
      <div className="scan-config">
        <div className="scan-type-grid">
          {SCAN_TYPES.map((s) => (
            <button
              key={s.id}
              className={`scan-type-btn ${scanType === s.id ? "active" : ""}`}
              onClick={() => setScanType(s.id)}
            >
              <span className="scan-icon">{s.icon}</span>
              <span className="scan-label">{s.label}</span>
              <span className="scan-desc">{s.desc}</span>
            </button>
          ))}
        </div>

        <div className="scan-inputs">
          <div className="input-group">
            <label>Target IP / Range</label>
            <input
              className="input-field"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.1.0/24 or 192.168.1.1"
            />
          </div>
          {scanType === "port" && (
            <div className="input-group">
              <label>Port Range</label>
              <input
                className="input-field"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder="1-1024"
              />
            </div>
          )}
          <button
            className={`btn-primary scan-btn ${scanning ? "scanning" : ""}`}
            onClick={handleScan}
            disabled={scanning}
          >
            {scanning ? (
              <>
                <span className="spinner" /> Scanning…
              </>
            ) : (
              <>
                <Search size={15} /> Run Scan
              </>
            )}
          </button>
        </div>

        {error && <div className="error-msg">{error}</div>}
      </div>

      {/* Results */}
      {result && (
        <div className="scan-results">
          <div className="scan-result-header">
            <span>Scan: <strong>{result.scan_type}</strong></span>
            <span>Target: <strong>{result.target}</strong></span>
            <span>Hosts found: <strong>{result.hosts_found}</strong></span>
            <span className="scan-cmd">{result.command}</span>
          </div>
          {result.error ? (
            <div className="error-msg">{result.error}</div>
          ) : result.hosts?.length === 0 ? (
            <div className="empty-msg">No hosts responded to the scan.</div>
          ) : (
            result.hosts?.map((h) => <HostCard key={h.ip} host={h} />)
          )}
        </div>
      )}

      {/* Scan history */}
      {history.length > 0 && !result && (
        <div className="scan-history">
          <h4><Clock size={14} /> Recent Scans</h4>
          {history.slice(0, 5).map((h) => (
            <div key={h.id} className="history-row" onClick={() => setResult(h)}>
              <span className="h-target">{h.target}</span>
              <span className="h-type">{h.scan_type}</span>
              <span className="h-hosts">{h.hosts_found} hosts</span>
              <span className="h-time">{new Date(h.timestamp).toLocaleTimeString()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}