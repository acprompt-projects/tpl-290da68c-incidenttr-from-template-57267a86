import React, { useState, useEffect, useCallback } from "react";

const API = "http://localhost:8000/api/incidents";

const SEV_COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  info: "#6b7280",
};
const STATUS_LABELS = { new: "New", investigating: "Investigating", resolved: "Resolved", suppressed: "Suppressed" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(null);
  const [sevFilter, setSevFilter] = useState(null);
  const [statusFilter, setStatusFilter] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchIncidents = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (sevFilter) params.set("severity", sevFilter);
      if (statusFilter) params.set("status", statusFilter);
      const res = await fetch(`${API}?${params}`);
      const data = await res.json();
      setIncidents(data.items || data);
    } catch {
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  }, [sevFilter, statusFilter]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);
  useEffect(() => { const id = setInterval(fetchIncidents, 15000); return () => clearInterval(id); }, [fetchIncidents]);

  const updateStatus = async (id, status) => {
    await fetch(`${API}/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status }) });
    fetchIncidents();
    if (selected && selected.id === id) setSelected({ ...selected, status });
  };

  const s = (base, extra = {}) => ({ ...base, ...extra });
  const base = { fontFamily: "Inter, system-ui, sans-serif", color: "#1e293b", boxSizing: "border-box" };

  return (
    <div style={s(base, { maxWidth: 1200, margin: "0 auto", padding: 24 })}>
      <h1 style={{ margin: "0 0 8px", fontSize: 24 }}>Incident Triage Dashboard</h1>
      <p style={{ margin: "0 0 20px", color: "#64748b", fontSize: 13 }}>Auto-refreshes every 15s</p>

      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>Severity:</span>
        <button onClick={() => setSevFilter(null)} style={pill(!sevFilter)}>All</button>
        {SEV_ORDER.map(sev => (
          <button key={sev} onClick={() => setSevFilter(sevFilter === sev ? null : sev)}
            style={pill(sevFilter === sev, SEV_COLORS[sev])}>{sev}</button>
        ))}
        <span style={{ marginLeft: 16, fontSize: 13, fontWeight: 600 }}>Status:</span>
        {Object.entries(STATUS_LABELS).map(([k, v]) => (
          <button key={k} onClick={() => setStatusFilter(statusFilter === k ? null : k)} style={pill(statusFilter === k)}>{v}</button>
        ))}
      </div>

      {loading ? <p>Loading…</p> : incidents.length === 0 ? <p style={{ color: "#94a3b8" }}>No incidents found.</p> : (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
          <thead>
            <tr style={{ borderBottom: "2px solid #e2e8f0", textAlign: "left" }}>
              {["ID", "Title", "Severity", "Status", "Source", "Created", ""].map(h => (
                <th key={h} style={{ padding: "8px 10px", fontWeight: 600, color: "#475569", fontSize: 12, textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {incidents.map(inc => (
              <tr key={inc.id} style={{ borderBottom: "1px solid #f1f5f9", cursor: "pointer", background: selected?.id === inc.id ? "#f8fafc" : "transparent" }}
                onClick={() => setSelected(inc)}>
                <td style={{ padding: "10px", fontFamily: "monospace", fontSize: 12 }}>{inc.id.slice(0, 8)}</td>
                <td style={{ padding: "10px", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inc.title}</td>
                <td style={{ padding: "10px" }}><span style={sevBadge(inc.severity)}>{inc.severity}</span></td>
                <td style={{ padding: "10px" }}>{STATUS_LABELS[inc.status] || inc.status}</td>
                <td style={{ padding: "10px", fontSize: 12, color: "#64748b" }}>{inc.source || "—"}</td>
                <td style={{ padding: "10px", fontSize: 12, color: "#64748b" }}>{new Date(inc.created_at).toLocaleString()}</td>
                <td style={{ padding: "10px" }}>
                  {inc.status !== "resolved" && <button onClick={e => { e.stopPropagation(); updateStatus(inc.id, "resolved"); }}
                    style={{ fontSize: 11, padding: "3px 8px", borderRadius: 4, border: "1px solid #16a34a", background: "#fff", color: "#16a34a", cursor: "pointer" }}>Resolve</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {selected && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.3)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 50 }}
          onClick={() => setSelected(null)}>
          <div style={{ background: "#fff", borderRadius: 12, padding: 24, width: 560, maxHeight: "80vh", overflow: "auto", boxShadow: "0 20px 60px rgba(0,0,0,0.15)" }}
            onClick={e => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
              <h2 style={{ margin: 0, fontSize: 18 }}>{selected.title}</h2>
              <button onClick={() => setSelected(null)} style={{ border: "none", background: "none", fontSize: 20, cursor: "pointer", lineHeight: 1 }}>✕</button>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
              <field><label style={lblStyle}>Severity</label><span style={sevBadge(selected.severity)}>{selected.severity}</span></field>
              <field><label style={lblStyle}>Status</label><div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {Object.keys(STATUS_LABELS).map(st => (
                  <button key={st} onClick={() => updateStatus(selected.id, st)}
                    style={pill(selected.status === st, selected.status === st ? SEV_COLORS[selected.severity] : undefined, 11)}>{STATUS_LABELS[st]}</button>
                ))}
              </div></field>
              <field><label style={lblStyle}>Source</label><span>{selected.source || "—"}</span></field>
              <field><label style={lblStyle}>Created</label><span style={{ fontSize: 13 }}>{new Date(selected.created_at).toLocaleString()}</span></field>
            </div>
            {selected.description && <div style={{ marginBottom: 16 }}><label style={lblStyle}>Description</label><p style={{ margin: "4px 0", fontSize: 13, color: "#475569" }}>{selected.description}</p></div>}
            {selected.alerts && selected.alerts.length > 0 && <div><label style={lblStyle}>Correlated Alerts ({selected.alerts.length})</label>
              <ul style={{ margin: "4px 0", paddingLeft: 20, fontSize: 12, color: "#475569" }}>
                {selected.alerts.map((a, i) => <li key={i}>{typeof a === "string" ? a : a.message || a.id || JSON.stringify(a)}</li>)}
              </ul>
            </div>}
            {selected.notifications && selected.notifications.length > 0 && <div style={{ marginTop: 12 }}><label style={lblStyle}>Notifications Sent</label>
              <ul style={{ margin: "4px 0", paddingLeft: 20, fontSize: 12, color: "#475569" }}>
                {selected.notifications.map((n, i) => <li key={i}>{n.channel || n.type || JSON.stringify(n)}</li>)}
              </ul>
            </div>}
          </div>
        </div>
      )}
    </div>
  );
}

const lblStyle = { display: "block", fontSize: 11, fontWeight: 600, color: "#94a3b8", textTransform: "uppercase", marginBottom: 2, letterSpacing: 0.5 };
const pill = (active, color, fs = 12) => ({
  fontSize: fs, padding: "4px 10px", borderRadius: 6, border: `1px solid ${active ? (color || "#3b82f6") : "#e2e8f0"}`,
  background: active ? (color || "#3b82f6") : "#fff", color: active ? "#fff" : (color || "#475569"),
  cursor: "pointer", fontWeight: active ? 600 : 400,
});
const sevBadge = (sev) => ({
  display: "inline-block", padding: "2px 8px", borderRadius: 4, fontSize: 12, fontWeight: 600,
  background: SEV_COLORS[sev] || "#6b7280", color: "#fff", textTransform: "uppercase",
});