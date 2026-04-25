import { useState, useEffect } from "react";
import { Ban, ShieldOff, Plus, Trash2, ShieldCheck, AlertCircle } from "lucide-react";
import { fetchBlockedIPs, blockIP, unblockIP, flushAllRules, applySynProtection } from "../api/client";
import { format } from "date-fns";

export default function BlockedIPs({ liveBlockedIP }) {
  const [ips, setIps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newIP, setNewIP] = useState("");
  const [newReason, setNewReason] = useState("");
  const [toast, setToast] = useState(null);
  const [confirm, setConfirm] = useState(null);

  const load = async () => {
    try {
      const data = await fetchBlockedIPs();
      setIps(data);
    } catch (e) {
      showToast("Failed to load blocked IPs", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  // Live update from socket
  useEffect(() => {
    if (liveBlockedIP) {
      setIps((prev) => {
        const exists = prev.find((i) => i.ip === liveBlockedIP.ip);
        if (exists) return prev;
        return [liveBlockedIP, ...prev];
      });
    }
  }, [liveBlockedIP]);

  const showToast = (msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const handleBlock = async () => {
    if (!newIP.trim()) return;
    try {
      await blockIP(newIP.trim(), newReason || "Manual block");
      showToast(`Blocked ${newIP}`);
      setNewIP("");
      setNewReason("");
      load();
    } catch (e) {
      showToast(e.message, "error");
    }
  };

  const handleUnblock = async (ip) => {
    try {
      await unblockIP(ip);
      showToast(`Unblocked ${ip}`);
      setIps((prev) => prev.filter((i) => i.ip !== ip));
    } catch (e) {
      showToast(e.message, "error");
    }
    setConfirm(null);
  };

  const handleFlush = async () => {
    try {
      await flushAllRules();
      showToast("All rules flushed");
      setIps([]);
    } catch (e) {
      showToast(e.message, "error");
    }
    setConfirm(null);
  };

  const handleSynProtection = async () => {
    try {
      await applySynProtection();
      showToast("SYN flood protection applied");
    } catch (e) {
      showToast(e.message, "error");
    }
  };

  return (
    <div className="panel blocked-panel">
      {toast && (
        <div className={`toast toast-${toast.type}`}>
          {toast.type === "error" ? <AlertCircle size={14} /> : <ShieldCheck size={14} />}
          {toast.msg}
        </div>
      )}

      {confirm && (
        <div className="confirm-overlay">
          <div className="confirm-box">
            <p>{confirm.message}</p>
            <div className="confirm-actions">
              <button className="btn-danger" onClick={confirm.onConfirm}>Confirm</button>
              <button className="btn-ghost" onClick={() => setConfirm(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      <div className="panel-header">
        <div className="panel-title">
          <Ban size={18} />
          <span>Blocked IPs</span>
          <span className="badge-count">{ips.length}</span>
        </div>
        <div className="panel-actions">
          <button className="btn-secondary btn-sm" onClick={handleSynProtection}>
            <ShieldCheck size={14} /> SYN Protection
          </button>
          <button
            className="btn-danger btn-sm"
            onClick={() => setConfirm({ message: "Flush ALL iptables INPUT rules?", onConfirm: handleFlush })}
          >
            <Trash2 size={14} /> Flush All
          </button>
        </div>
      </div>

      {/* Manual block form */}
      <div className="block-form">
        <input
          className="input-field"
          placeholder="IP Address (e.g. 192.168.1.50)"
          value={newIP}
          onChange={(e) => setNewIP(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleBlock()}
        />
        <input
          className="input-field"
          placeholder="Reason (optional)"
          value={newReason}
          onChange={(e) => setNewReason(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleBlock()}
        />
        <button className="btn-primary btn-sm" onClick={handleBlock}>
          <Plus size={14} /> Block IP
        </button>
      </div>

      {/* IP table */}
      <div className="ip-table-wrap">
        {loading ? (
          <div className="loading-msg">Loading…</div>
        ) : ips.length === 0 ? (
          <div className="empty-msg">No IPs currently blocked.</div>
        ) : (
          <table className="ip-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Blocked At</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {ips.map((item) => (
                <tr key={item.ip} className="ip-row">
                  <td className="ip-addr">{item.ip}</td>
                  <td className="ip-reason">{item.reason}</td>
                  <td className="ip-time">
                    {item.blocked_at ? format(new Date(item.blocked_at), "MMM d, HH:mm:ss") : "—"}
                  </td>
                  <td>
                    <button
                      className="btn-ghost btn-sm unblock-btn"
                      onClick={() =>
                        setConfirm({
                          message: `Unblock ${item.ip}?`,
                          onConfirm: () => handleUnblock(item.ip),
                        })
                      }
                    >
                      <ShieldOff size={13} /> Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}