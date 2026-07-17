# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/); versioning: [SemVer](https://semver.org/).

## [0.1.0] - 2026-07-17

Initial release — a four-language real-time threat-intelligence & log-forensic engine.

### Added
- **Python detector**: Isolation Forest implemented from scratch over log features
  (bytes, status, method, path length/entropy/special-chars), an incident agent that
  classifies the attack (SQLi/XSS/traversal/brute-force/scan/exfil) and drafts an
  iptables rule, FastAPI (`/score`, `/fit`), CLI, synthetic normal+attack generator,
  tests + offline verifier.
- **Rust normalizer**: Common/Combined Log Format regex parser → structured JSON,
  SHA-256 of the payload, feature extraction, axum `/normalize` service + `--stdin`
  CLI. Unit tests.
- **Go gateway**: UDP syslog + TCP stream + HTTP `/ingest` listeners, in-process
  queue, worker pool that calls the Rust normalizer then the Python detector, and
  broadcasts threat alerts to the SIEM over WebSocket. Tests.
- **Next.js SIEM**: live incident feed, threat-level indicator, per-severity tallies,
  a live severity strip, and a one-click attack-traffic simulator.
- Shared JSON protocol (`proto/protocol.md`), docker-compose, per-language
  Dockerfiles, multi-language CI, Makefile, MIT license.
