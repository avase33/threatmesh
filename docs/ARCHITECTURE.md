# threatmesh architecture

Ingest live logs, normalize them at line-rate, detect anomalies, and let an agent
draft remediation — each layer in the language built for it, one JSON contract
(`proto/protocol.md`) between them.

```
   log sources (apps, proxies, firewalls)
        │  syslog/UDP :5514 · TCP :5515 · HTTP POST /ingest
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Gateway · Go                                                          │
│ absorbs high-rate ingestion · queue · worker pool · alert broadcast    │
└───────┬───────────────────────────────────────────────┬───────────────┘
        │ HTTP /normalize                                 │ WebSocket /ws/alerts
        ▼                                                 ▼
┌──────────────────────────┐                    ┌────────────────────────┐
│ Normalizer · Rust        │                    │ SIEM · TypeScript      │
│ regex parse · SHA-256 ·  │                    │ live incident feed ·   │
│ feature extraction       │                    │ threat level · charts  │
└───────┬──────────────────┘                    └────────────────────────┘
        │ HTTP /score
        ▼
┌──────────────────────────┐
│ Detector · Python        │
│ Isolation Forest +       │
│ incident agent (rules)   │
└──────────────────────────┘
```

## Why each language

| Layer | Language | Reason |
| --- | --- | --- |
| Ingestion | **Go** | Absorbs hundreds of thousands of log lines/sec over UDP/TCP with cheap concurrency; won't drop events under attack. |
| Normalizer | **Rust** | Raw string parsing + hashing at hardware speed, no GC pauses — the step that would bottleneck in Python. |
| Detector | **Python** | The ML ecosystem; here an Isolation Forest + agentic incident response. |
| SIEM | **TypeScript** | Reactive, streaming dashboards over continuous WebSocket updates. |

## Flow

1. Logs arrive at the Go gateway (syslog/UDP, TCP stream, or `POST /ingest`).
   Lines are batched onto a queue.
2. A worker sends a batch to the Rust normalizer, which parses each line into a
   structured record (ip, method, path, status, bytes), hashes the payload, and
   extracts numeric features.
3. The worker sends the records to the Python detector. It fits an **Isolation
   Forest** on baseline traffic and scores each record in `[0,1]`; anything above
   the threshold is an anomaly.
4. For each anomaly the **incident agent** classifies the attack and drafts a
   firewall rule, returning it inline.
5. The gateway broadcasts an `Alert` to every connected SIEM over WebSocket; the
   dashboard renders the incident, severity, and remediation live.

## The anomaly model (from scratch)

Isolation Forest is built on the insight that anomalies are *few and different*, so
random axis-parallel splits isolate them in far fewer steps than normal points.
`detector-python/threatmesh_detector/iforest.py` builds an ensemble of isolation
trees on subsamples and converts the average path length to a score — no
scikit-learn. Attacks (SQLi with long high-entropy paths, data exfil with huge
payloads, brute force with 401 bursts) sit far from the baseline and score high.

## Offline-first

- **Detector**: rule-based incident agent + from-scratch forest → no ML libs, no
  keys. `THREATMESH_LLM=openai` upgrades the remediation write-ups.
- **Rust**: parses real log lines; nothing external needed.
- **Go**: in-process queue → no Redis/Kafka (the interface is ready for them).

`docker compose up` (or `make demo`) gives a working detection pipeline you can
attack from the SIEM's "simulate attack traffic" button, and every layer is
independently testable.
