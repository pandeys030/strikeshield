import { useState, useEffect, useRef } from "react";
import { AlertTriangle, ChevronDown, Filter, RefreshCw } from "lucide-react";
import { fetchAlerts } from "../api/client";
import { format } from "date-fns";

const SEVERITY_COLOR = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
};

const SEVERITY_LABEL = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
};

function AlertRow({ alert, isNew }) {
  return (
    <div className={`alert-row ${SEVERITY_COLOR[alert.severity]} ${isNew ? "alert-flash" : ""}`}>
      <div className="alert-meta">
        <span className={`sev-badge ${SEVERITY_COLOR[alert.severity]}`}>
          {SEVERITY_LABEL[alert.severity] ?? "UNK"}
        </span>
        <span className="alert-type">{alert.attack_type}</span>
        <span className="alert-proto">{alert.protocol}</span>
      </div>
      <div className="alert-ips">
        <span className="alert-src">{alert.src_ip}{alert.src_port ? `:${alert.src_port}` : ""}</span>
        <span className="alert-arrow">→</span>
        <span className="alert-dst">{alert.dst_ip}{alert.dst_port ? `:${alert.dst_port}` : ""}</span>
      </div>
      <div className="alert-msg">{alert.message}</div>
      <div className="alert-time">
        {format(new Date(alert.timestamp), "HH:mm:ss.SSS")}
      </div>
    </div>
  );
}

export default function AlertFeed({ liveAlerts = [] }) {
  const [alerts, setAlerts] = useState([]);
  const [filter, setFilter] = useState("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const [loading, setLoading] = useState(true);
  const [newIds, setNewIds] = useState(new Set());
  const listRef = useRef(null);

  // Initial load
  useEffect(() => {
    fetchAlerts(200)
      .then(setAlerts)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  // Merge live alerts
  useEffect(() => {
    if (!liveAlerts.length) return;
    const latest = liveAlerts[liveAlerts.length - 1];
    setAlerts((prev) => {
      const exists = prev.some((a) => a.id === latest.id);
      if (exists) return prev;
      return [latest, ...prev].slice(0, 500);
    });
    setNewIds((prev) => {
      const next = new Set(prev);
      next.add(latest.id);
      setTimeout(() => setNewIds((p) => { const n = new Set(p); n.delete(latest.id); return n; }), 2000);
      return next;
    });
  }, [liveAlerts]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && listRef.current) {
      listRef.current.scrollTop = 0;
    }
  }, [alerts, autoScroll]);

  const filtered = filter === "all" ? alerts : alerts.filter((a) => a.severity === filter);

  const counts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="panel alert-feed-panel">
      <div className="panel-header">
        <div className="panel-title">
          <AlertTriangle size={18} />
          <span>Alert Feed</span>
          <span className="badge-count">{alerts.length}</span>
        </div>
        <div className="panel-actions">
          <div className="filter-group">
            {["all", "critical", "high", "medium"].map((s) => (
              <button
                key={s}
                className={`filter-btn ${filter === s ? "active" : ""} ${s !== "all" ? SEVERITY_COLOR[s] : ""}`}
                onClick={() => setFilter(s)}
              >
                {s === "all" ? "All" : `${s.charAt(0).toUpperCase() + s.slice(1)} (${counts[s] || 0})`}
              </button>
            ))}
          </div>
          <button
            className={`icon-btn ${autoScroll ? "active" : ""}`}
            onClick={() => setAutoScroll((v) => !v)}
            title="Toggle auto-scroll"
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      <div className="alert-list" ref={listRef}>
        {loading ? (
          <div className="loading-msg">Loading alerts…</div>
        ) : filtered.length === 0 ? (
          <div className="empty-msg">No alerts detected yet. Start a simulation to see live data.</div>
        ) : (
          filtered.map((alert) => (
            <AlertRow key={alert.id} alert={alert} isNew={newIds.has(alert.id)} />
          ))
        )}
      </div>
    </div>
  );
}