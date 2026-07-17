# threatmesh 🛡️

**An autonomous real-time cyber threat-intelligence & log-forensic engine.** It
ingests live logs, normalizes them at line-rate, detects anomalous behavior with a
from-scratch Isolation Forest, and an AI incident agent classifies the attack and
drafts a firewall rule — streamed to a live SIEM dashboard.

Four languages, each on the layer it's built for, joined by one JSON protocol:

```
sources ──syslog/UDP/TCP/HTTP──▶ Go gateway ──▶ Rust normalizer ──▶ Python detector
                                    │  (queue+workers)  (parse+hash)     (IsolationForest+agent)
                                    └──WebSocket──▶ TypeScript SIEM ◀── alerts ──┘
```

| Layer | Language | Owns |
| --- | --- | --- |
| **Gateway** | Go | UDP/TCP/HTTP log ingestion, queue, worker pool, alert fan-out |
| **Normalizer** | Rust | Regex parse of access logs, SHA-256, feature extraction |
| **Detector** | Python | Isolation Forest (from scratch) + incident agent |
| **SIEM** | TypeScript / Next.js | Live incident feed, threat level, severity charts |

Runs **offline with no ML libraries and no keys**: the forest is hand-written, the
incident agent is rule-based, and the queue is in-process. Flip env vars for a real
LLM incident writer, Redis/Kafka, etc.

## Quickstart — the detector, offline

```bash
cd detector-python && pip install -e .
python -m threatmesh_detector.cli demo
```

```
threatmesh detector — agent=mock  baseline=800  scored 206 live records
  [CRITICAL] sqli       score=0.79  ip=45.13.9.7
    Sqli indicators from 45.13.9.7 (anomaly score 0.79) on GET /api/products?id=1' UNION SELECT ...
    ⛨ iptables -A INPUT -s 45.13.9.7 -j DROP
  [CRITICAL] data_exfil score=0.88  ip=185.220.101.4
    ⛨ iptables -A INPUT -s 185.220.101.4 -j DROP
  ...
  attacks planted : 6
  attacks caught  : 5
  false positives : 3 / 200 normal records
```

Offline end-to-end check:

```bash
python scripts/verify.py     # RESULT: N passed, 0 failed
```

## Quickstart — the whole mesh

```bash
docker compose up --build
# SIEM:       http://localhost:3000   (click "Simulate attack traffic")
# Gateway:    http://localhost:8080/health   · syslog udp :5514 · tcp :5515
# Normalizer: http://localhost:8090/health
# Detector:   http://localhost:8000/health
```

Feed it real logs:

```bash
# HTTP
curl -XPOST localhost:8080/ingest -H 'content-type: application/json' \
  -d '{"lines":["45.13.9.7 - - [x] \"GET /p?id=1'\'' UNION SELECT pw FROM users-- HTTP/1.1\" 200 320"]}'
# or syslog/UDP
logger -n localhost -P 5514 -d "$(cat /var/log/nginx/access.log)"
```

## The interesting engineering

- **Isolation Forest, from scratch** — random isolation trees, average path length →
  anomaly score, no scikit-learn. `detector-python/threatmesh_detector/iforest.py`
- **Line-rate Rust parsing** — Common/Combined Log Format regex → structured record +
  SHA-256 + features, the hot path that would throttle Python. `normalizer-rust/src/parse.rs`
- **Go ingestion** — UDP + TCP + HTTP listeners feeding a bounded queue and a worker
  pool that chains normalize → score → broadcast. `gateway-go/`
- **Incident agent** — classifies SQLi / XSS / traversal / brute-force / recon / exfil
  and drafts an iptables rule (rule-based offline, LLM-written with a key).
  `detector-python/threatmesh_detector/agent.py`
- **Live SIEM** — threat level, per-severity tallies, and a streaming incident feed
  over WebSocket. `frontend-ts/app/page.tsx`

## Testing

```bash
make test                       # rust + python + go
cd detector-python && pytest -q
cd normalizer-rust && cargo test
cd gateway-go      && go test ./...
cd frontend-ts     && npm run build
```

## Layout

```
proto/               shared JSON wire protocol
frontend-ts/         Next.js SIEM dashboard
gateway-go/          Go ingestion gateway (UDP/TCP/HTTP, queue, workers, WS)
normalizer-rust/     Rust log normalizer (regex parse, SHA-256, features)
detector-python/     Isolation Forest + incident agent + FastAPI
scripts/verify.py    offline end-to-end check
docs/ARCHITECTURE.md
```

## License

MIT © 2026 Akhil Vase
