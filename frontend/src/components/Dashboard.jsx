import { useEffect, useState } from "react";
import { Shield, AlertTriangle, Ban, Activity, Zap, Server } from "lucide-react";
import { fetchStats, fetchAlertStats } from "../api/client";

const StatCard = ({ icon: Icon, label, value, sub, color, pulse }) => (
  <div className={`stat-card ${color}`}>
    <div className="stat-icon-wrap">
      <Icon size={22} />
      {pulse && <span className="pulse-ring" />}
    </div>
    <div className="stat-body">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  </div>
);

export default function Dashboard({ alerts = [], blockedIPs = [], activeAttacks = [] }) {
  const [alertStats, setAlertStats] = useState(null);
  const [systemStats, setSystemStats] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [stats, aStats] = await Promise.all([fetchStats(), fetchAlertStats()]);
        setSystemStats(stats);
        setAlertStats(aStats);
      } catch (e) {
        console.error(e);
      }
    };
    load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);

  const critical = alerts.filter((a) => a.severity === "critical").length;
  const high = alerts.filter((a) => a.severity === "high").length;

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <div className="shield-badge">
          <Shield size={32} />
          <div>
            <h1>StrikeShield</h1>
            <span className="tagline">Real-Time DDoS Detection &amp; Defense</span>
          </div>
        </div>
        <div className="system-status">
          <span className={`status-dot ${activeAttacks.length > 0 ? "danger" : "ok"}`} />
          <span>{activeAttacks.length > 0 ? "ATTACK IN PROGRESS" : "SYSTEM SECURE"}</span>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard
          icon={AlertTriangle}
          label="Total Alerts"
          value={alertStats?.total_alerts ?? alerts.length}
          sub={`${critical} critical · ${high} high`}
          color={critical > 0 ? "card-danger" : "card-neutral"}
          pulse={critical > 0}
        />
        <StatCard
          icon={Ban}
          label="Blocked IPs"
          value={blockedIPs.length}
          sub="via iptables DROP rules"
          color="card-warning"
        />
        <StatCard
          icon={Zap}
          label="Active Attacks"
          value={activeAttacks.length}
          sub={activeAttacks.length > 0 ? "Simulation running" : "No simulation active"}
          color={activeAttacks.length > 0 ? "card-danger" : "card-ok"}
          pulse={activeAttacks.length > 0}
        />
        <StatCard
          icon={Activity}
          label="IDS Status"
          value="Online"
          sub="Snort + iptables active"
          color="card-ok"
        />
        <StatCard
          icon={Server}
          label="By Severity"
          value={`${critical} / ${high}`}
          sub="Critical / High alerts"
          color="card-neutral"
        />
        <StatCard
          icon={Shield}
          label="Top Attack"
          value={
            alertStats?.by_type
              ? Object.entries(alertStats.by_type).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "—"
              : "—"
          }
          sub="Most frequent type"
          color="card-neutral"
        />
      </div>

      {alertStats?.top_attackers?.length > 0 && (
        <div className="top-attackers">
          <h3>Top Attacker IPs</h3>
          <div className="attacker-list">
            {alertStats.top_attackers.slice(0, 5).map((a, i) => (
              <div key={a.ip} className="attacker-row">
                <span className="attacker-rank">#{i + 1}</span>
                <span className="attacker-ip">{a.ip}</span>
                <div className="attacker-bar-wrap">
                  <div
                    className="attacker-bar"
                    style={{
                      width: `${Math.min(100, (a.count / alertStats.top_attackers[0].count) * 100)}%`,
                    }}
                  />
                </div>
                <span className="attacker-count">{a.count} alerts</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}