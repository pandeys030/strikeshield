import { useState, useEffect } from "react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend, ReferenceLine,
} from "recharts";
import { Activity } from "lucide-react";
import { fetchTrafficHistory } from "../api/client";
import { format } from "date-fns";

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="tooltip-time">{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey} className="tooltip-row" style={{ color: p.color }}>
          <span>{p.name}:</span>
          <strong>{p.value?.toLocaleString()}</strong>
        </div>
      ))}
    </div>
  );
};

export default function TrafficChart({ livePoint }) {
  const [data, setData] = useState([]);
  const [metric, setMetric] = useState("pps"); // "pps" | "mbps"
  const [attackMarkers, setAttackMarkers] = useState([]);

  useEffect(() => {
    fetchTrafficHistory(120)
      .then((history) => {
        const formatted = history.map((p) => ({
          ...p,
          time: format(new Date(p.timestamp), "HH:mm:ss"),
        }));
        setData(formatted);
      })
      .catch(console.error);
  }, []);

  useEffect(() => {
    if (!livePoint) return;
    const point = {
      ...livePoint,
      time: format(new Date(livePoint.timestamp), "HH:mm:ss"),
    };
    setData((prev) => {
      const next = [...prev, point].slice(-120);
      return next;
    });
    if (livePoint.attack_active && !attackMarkers.includes(point.time)) {
      setAttackMarkers((prev) => [...prev, point.time].slice(-5));
    }
  }, [livePoint]);

  const peakPPS = data.length ? Math.max(...data.map((d) => d.pps || 0)) : 0;
  const avgPPS = data.length
    ? Math.round(data.reduce((s, d) => s + (d.pps || 0), 0) / data.length)
    : 0;
  const isUnderAttack = data.slice(-5).some((d) => d.attack_active);

  return (
    <div className="panel chart-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Activity size={18} />
          <span>Live Traffic Monitor</span>
          {isUnderAttack && <span className="attack-badge">UNDER ATTACK</span>}
        </div>
        <div className="panel-actions">
          <div className="metric-toggle">
            <button
              className={`toggle-btn ${metric === "pps" ? "active" : ""}`}
              onClick={() => setMetric("pps")}
            >
              Packets/s
            </button>
            <button
              className={`toggle-btn ${metric === "mbps" ? "active" : ""}`}
              onClick={() => setMetric("mbps")}
            >
              Mbps
            </button>
          </div>
        </div>
      </div>

      <div className="chart-stats-row">
        <div className="chart-stat">
          <span className="cs-label">Peak</span>
          <span className="cs-val">{peakPPS.toLocaleString()} pps</span>
        </div>
        <div className="chart-stat">
          <span className="cs-label">Average</span>
          <span className="cs-val">{avgPPS.toLocaleString()} pps</span>
        </div>
        <div className="chart-stat">
          <span className="cs-label">Status</span>
          <span className={`cs-val ${isUnderAttack ? "danger" : "ok"}`}>
            {isUnderAttack ? "⚠ Attack" : "✓ Normal"}
          </span>
        </div>
      </div>

      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="mbpsGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
            <XAxis
              dataKey="time"
              tick={{ fontSize: 11, fill: "rgba(255,255,255,0.4)" }}
              tickLine={false}
              interval="preserveStartEnd"
            />
            <YAxis
              tick={{ fontSize: 11, fill: "rgba(255,255,255,0.4)" }}
              tickLine={false}
              axisLine={false}
              tickFormatter={(v) => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v}
            />
            <Tooltip content={<CustomTooltip />} />
            {attackMarkers.map((t) => (
              <ReferenceLine key={t} x={t} stroke="#ef4444" strokeDasharray="4 4" opacity={0.6} />
            ))}
            {metric === "pps" ? (
              <Area
                type="monotone"
                dataKey="pps"
                name="Packets/sec"
                stroke="#ef4444"
                strokeWidth={2}
                fill="url(#ppsGrad)"
                dot={false}
                isAnimationActive={false}
              />
            ) : (
              <Area
                type="monotone"
                dataKey="mbps"
                name="Mbps"
                stroke="#3b82f6"
                strokeWidth={2}
                fill="url(#mbpsGrad)"
                dot={false}
                isAnimationActive={false}
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}