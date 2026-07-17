# threatmesh wire protocol

Ingest live logs, normalize them at line-rate, score them for anomalies, and let
an AI agent draft remediation — each layer in the language built for it, joined by
one JSON contract.

```
sources ──syslog/UDP/TCP──▶ Go gateway ──HTTP──▶ Rust normalizer ──HTTP──▶ Python detector
                              │  (queue+workers)   (parse+hash)             (IsolationForest + agent)
                              └──WebSocket──▶ TypeScript SIEM  ◀── alerts ──┘
```

## 1. Sources ⇄ Gateway (Go)

```
UDP  :5514   raw syslog / access-log lines (one per packet or newline-delimited)
TCP  :5515   newline-delimited log stream
POST /ingest { "lines": ["...", "..."] }     (for testing / HTTP shippers)
GET  /health
WS   /ws/alerts   -> streamed Alert events (see below)
```

## 2. Gateway ⇄ Normalizer (Rust)

```jsonc
POST /normalize { "lines": ["192.168.1.10 - - [10/Oct/2026:13:55:36] \"GET /a HTTP/1.1\" 200 1024"] }
->
{ "records": [
  { "ip": "192.168.1.10", "ts": "10/Oct/2026:13:55:36", "method": "GET", "path": "/a",
    "status": 200, "bytes": 1024, "hash": "<sha256>",
    "features": { "bytes": 1024, "status": 200, "method_code": 0, "path_len": 2,
                  "path_entropy": 1.0, "special_chars": 0 } } ] }
GET /health
```

## 3. Gateway ⇄ Detector (Python)

```jsonc
POST /score { "records": [ { ...normalized record with features... } ] }
->
{ "results": [
    { "index": 0, "anomaly": true, "score": 0.81,
      "incident": { "severity": "high", "kind": "sqli",
                    "summary": "Possible SQL injection from 10.0.0.9",
                    "firewall_rule": "iptables -A INPUT -s 10.0.0.9 -j DROP" } } ] }
GET /health
```

## Alert (Gateway → SIEM, WebSocket)

```jsonc
{ "ts": 1730000000.0, "ip": "10.0.0.9", "score": 0.81, "kind": "sqli",
  "severity": "high", "summary": "...", "firewall_rule": "...",
  "path": "/login?id=1' OR '1'='1", "status": 200 }
```

## Anomaly model

The detector fits an **Isolation Forest** (implemented from scratch) on a baseline
of normal traffic, then scores each record in `[0,1]` — higher means more isolated
/ anomalous. Records above the threshold are flagged `-1` (anomaly) and handed to
the incident agent, which classifies the likely attack and drafts a firewall rule.
Everything runs offline; set `THREATMESH_LLM=openai` to draft richer remediations
with a real model.
