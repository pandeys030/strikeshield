import { useState, useEffect } from "react";
import { Zap, StopCircle, AlertOctagon, Clock, Target } from "lucide-react";
import {
  fetchAttackProfiles, startAttack, stopAttack, stopAllAttacks,
  fetchActiveAttacks, fetchAttackHistory,
} from "../api/client";

const SEVERITY_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

function ProfileCard({ profile, selected, onClick }) {
  return (
    <div
      className={`profile-card ${selected ? "selected" : ""}`}
      onClick={() => onClick(profile)}
      style={{ "--accent": SEVERITY_COLOR[profile.severity] }}
    >
      <div className="profile-header">
        <span className="profile-name">{profile.name}</span>
        <span
          className="profile-sev"
          style={{ color: SEVERITY_COLOR[profile.severity] }}
        >
          {profile.severity.toUpperCase()}
        </span>
      </div>
      <div className="profile-desc">{profile.description}</div>
      <div className="profile-meta">
        <span className="profile-proto">{profile.protocol}</span>
      </div>
    </div>
  );
}

function ActiveAttackRow({ attack, onStop }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const start = new Date(attack.started_at).getTime();
    const iv = setInterval(() => {
      setElapsed(Math.floor((Date.now() - start) / 1000));
    }, 1000);
    return () => clearInterval(iv);
  }, [attack.started_at]);

  return (
    <div className="active-attack-row">
      <div className="aa-info">
        <span className="aa-type">{attack.attack_type}</span>
        <span className="aa-target">→ {attack.target}:{attack.port}</span>
        <span className="aa-elapsed">{elapsed}s / {attack.duration}s</span>
        <div
          className="aa-progress"
          style={{ width: `${Math.min(100, (elapsed / attack.duration) * 100)}%` }}
        />
      </div>
      <button className="btn-danger btn-sm" onClick={() => onStop(attack.id)}>
        <StopCircle size={13} /> Stop
      </button>
    </div>
  );
}

export default function AttackSimulator() {
  const [profiles, setProfiles] = useState([]);
  const [selected, setSelected] = useState(null);
  const [target, setTarget] = useState("127.0.0.1");
  const [port, setPort] = useState(80);
  const [duration, setDuration] = useState(30);
  const [active, setActive] = useState([]);
  const [history, setHistory] = useState([]);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState("");
  const [warning, setWarning] = useState(false);

  useEffect(() => {
    fetchAttackProfiles().then(setProfiles).catch(console.error);
    fetchActiveAttacks().then(setActive).catch(console.error);
    fetchAttackHistory().then(setHistory).catch(console.error);
    const iv = setInterval(() => {
      fetchActiveAttacks().then(setActive).catch(console.error);
    }, 2000);
    return () => clearInterval(iv);
  }, []);

  const handleLaunch = async () => {
    if (!selected || !warning) { setWarning(true); return; }
    setLaunching(true);
    setError("");
    try {
      await startAttack(selected.id, target, port, duration);
      const updated = await fetchActiveAttacks();
      setActive(updated);
      setWarning(false);
    } catch (e) {
      setError(e.message);
    } finally {
      setLaunching(false);
    }
  };

  const handleStop = async (id) => {
    await stopAttack(id);
    setActive((prev) => prev.filter((a) => a.id !== id));
    const h = await fetchAttackHistory();
    setHistory(h);
  };

  const handleStopAll = async () => {
    await stopAllAttacks();
    setActive([]);
  };

  return (
    <div className="panel simulator-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Zap size={18} />
          <span>Attack Simulator</span>
          <span className="demo-badge">DEMO / LAB ONLY</span>
        </div>
        {active.length > 0 && (
          <button className="btn-danger btn-sm" onClick={handleStopAll}>
            <StopCircle size={14} /> Stop All
          </button>
        )}
      </div>

      <div className="lab-warning">
        <AlertOctagon size={16} />
        <span>Only use in isolated lab environments. Never attack real networks.</span>
      </div>

      {/* Active attacks */}
      {active.length > 0 && (
        <div className="active-attacks">
          <h4>Running Simulations</h4>
          {active.map((a) => (
            <ActiveAttackRow key={a.id} attack={a} onStop={handleStop} />
          ))}
        </div>
      )}

      {/* Profile selection */}
      <div className="profile-grid">
        {profiles.map((p) => (
          <ProfileCard
            key={p.id}
            profile={p}
            selected={selected?.id === p.id}
            onClick={setSelected}
          />
        ))}
      </div>

      {/* Launch config */}
      {selected && (
        <div className="launch-config">
          <h4>Configure: {selected.name}</h4>
          <div className="launch-inputs">
            <div className="input-group">
              <label><Target size={12} /> Target IP</label>
              <input
                className="input-field"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="127.0.0.1"
              />
            </div>
            <div className="input-group">
              <label>Port</label>
              <input
                className="input-field"
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
              />
            </div>
            <div className="input-group">
              <label><Clock size={12} /> Duration (sec)</label>
              <input
                className="input-field"
                type="number"
                min={5}
                max={120}
                value={duration}
                onChange={(e) => setDuration(Number(e.target.value))}
              />
            </div>
          </div>

          {warning && (
            <div className="confirm-warning">
              ⚠ Are you sure? This will simulate a {selected.name} against {target}:{port}.
              Click Launch again to confirm.
            </div>
          )}

          {error && <div className="error-msg">{error}</div>}

          <button
            className={`btn-danger launch-btn ${warning ? "confirm-mode" : ""}`}
            onClick={handleLaunch}
            disabled={launching}
          >
            <Zap size={15} />
            {launching ? "Launching…" : warning ? "⚠ Confirm Launch" : "Launch Attack"}
          </button>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="attack-history">
          <h4>Attack History</h4>
          <div className="history-list">
            {history.slice(0, 8).map((a) => (
              <div key={a.id} className="history-item">
                <span className="h-type">{a.attack_type}</span>
                <span className="h-target">{a.target}:{a.port}</span>
                <span className={`h-status ${a.status}`}>{a.status}</span>
                <span className="h-time">{new Date(a.started_at).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}