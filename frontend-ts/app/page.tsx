"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Alert } from "@/lib/types";

const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:8080";
const WS_URL = GATEWAY.replace(/^http/, "ws") + "/ws/alerts";

const SEV_COLOR: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

// A mix of normal + malicious access-log lines to drive the pipeline on demand.
const TEST_TRAFFIC = [
  '10.0.1.20 - - [10/Oct/2026:13:55:36 +0000] "GET /api/products HTTP/1.1" 200 2100',
  '10.0.2.31 - - [10/Oct/2026:13:55:37 +0000] "GET /static/app.js HTTP/1.1" 200 5400',
  `45.13.9.7 - - [10/Oct/2026:13:55:38 +0000] "GET /api/products?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 200 320`,
  '203.0.113.5 - - [10/Oct/2026:13:55:39 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 210',
  '185.220.101.4 - - [10/Oct/2026:13:55:40 +0000] "GET /api/export/all HTTP/1.1" 200 9800000',
  '198.51.100.22 - - [10/Oct/2026:13:55:41 +0000] "POST /login HTTP/1.1" 401 90',
  '10.0.3.44 - - [10/Oct/2026:13:55:42 +0000] "GET /api/cart HTTP/1.1" 200 1800',
];

export default function Page() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (e) => {
      try {
        const a: Alert = JSON.parse(e.data);
        setAlerts((prev) => [a, ...prev].slice(0, 100));
      } catch {
        /* ignore */
      }
    };
    return () => ws.close();
  }, []);

  const sendTraffic = useCallback(async () => {
    try {
      await fetch(`${GATEWAY}/ingest`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lines: TEST_TRAFFIC }),
      });
    } catch {
      /* gateway down */
    }
  }, []);

  const counts = alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});
  const threatLevel = counts.critical
    ? "CRITICAL"
    : counts.high
    ? "HIGH"
    : counts.medium
    ? "ELEVATED"
    : alerts.length
    ? "GUARDED"
    : "NOMINAL";

  return (
    <main style={{ maxWidth: 1080, margin: "0 auto", padding: 24 }}>
      <header style={{ display: "flex", alignItems: "baseline", gap: 14 }}>
        <h1 style={{ margin: 0 }}>threatmesh</h1>
        <span style={{ color: "var(--muted)" }}>real-time SIEM · Go ingest · Rust normalize · Python detect</span>
        <span style={{ marginLeft: "auto", color: connected ? "var(--low)" : "var(--muted)" }}>
          {connected ? "● live" : "○ offline"}
        </span>
      </header>

      {/* top row: threat level + severity tallies */}
      <section style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 12, margin: "16px 0" }}>
        <div style={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 12, padding: 16 }}>
          <div style={{ color: "var(--muted)" }}>THREAT LEVEL</div>
          <div
            style={{
              fontSize: 30,
              fontWeight: 800,
              color:
                threatLevel === "CRITICAL"
                  ? "var(--critical)"
                  : threatLevel === "HIGH"
                  ? "var(--high)"
                  : threatLevel === "ELEVATED"
                  ? "var(--medium)"
                  : "var(--low)",
            }}
          >
            {threatLevel}
          </div>
          <div style={{ color: "var(--muted)", marginTop: 6 }}>{alerts.length} incidents</div>
        </div>

        <div style={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 12, padding: 16 }}>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
            {(["critical", "high", "medium", "low"] as const).map((sev) => (
              <div key={sev}>
                <div style={{ color: SEV_COLOR[sev], fontSize: 26, fontWeight: 800 }}>{counts[sev] || 0}</div>
                <div style={{ color: "var(--muted)", textTransform: "uppercase", fontSize: 12 }}>{sev}</div>
              </div>
            ))}
            <button style={{ marginLeft: "auto", alignSelf: "center" }} onClick={sendTraffic}>
              ⚡ Simulate attack traffic
            </button>
          </div>
          {/* live strip of recent alerts, colored by severity */}
          <div style={{ display: "flex", gap: 2, marginTop: 14, height: 26, alignItems: "flex-end" }}>
            {alerts
              .slice(0, 60)
              .reverse()
              .map((a, i) => (
                <div
                  key={i}
                  title={`${a.kind} · ${a.severity}`}
                  style={{ width: 6, height: `${8 + a.score * 18}px`, background: SEV_COLOR[a.severity] || "var(--muted)" }}
                />
              ))}
          </div>
        </div>
      </section>

      {/* incident feed */}
      <section style={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden" }}>
        <div style={{ padding: "10px 14px", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>
          INCIDENT FEED
        </div>
        <div style={{ maxHeight: 460, overflowY: "auto" }}>
          {alerts.length === 0 && (
            <div style={{ padding: 16, color: "var(--muted)" }}>
              No incidents yet. Click “Simulate attack traffic” (or send logs to the Go gateway on :5514/udp, :5515/tcp, or POST /ingest).
            </div>
          )}
          {alerts.map((a, i) => (
            <div key={i} style={{ display: "flex", gap: 12, padding: "10px 14px", borderBottom: "1px solid var(--border)" }}>
              <div
                style={{
                  width: 84,
                  color: SEV_COLOR[a.severity] || "var(--muted)",
                  fontWeight: 800,
                  textTransform: "uppercase",
                  fontSize: 12,
                }}
              >
                {a.severity}
              </div>
              <div style={{ flex: 1 }}>
                <div>
                  <strong>{a.kind}</strong> · <span style={{ color: "var(--muted)" }}>{a.ip}</span> · score {a.score.toFixed(2)}
                </div>
                <div style={{ color: "var(--muted)", wordBreak: "break-all" }}>{a.summary}</div>
                <div style={{ color: "var(--low)", marginTop: 4 }}>⛨ {a.firewall_rule}</div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
