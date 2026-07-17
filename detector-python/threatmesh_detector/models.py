"""Shared data types (see proto/protocol.md)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class Incident:
    severity: str
    kind: str
    summary: str
    firewall_rule: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "summary": self.summary,
            "firewall_rule": self.firewall_rule,
        }


@dataclass
class ScoreResult:
    index: int
    anomaly: bool
    score: float
    incident: Optional[Incident] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"index": self.index, "anomaly": self.anomaly, "score": round(self.score, 4)}
        if self.incident is not None:
            d["incident"] = self.incident.to_dict()
        return d


# A normalized log record is a plain dict with keys:
#   ip, ts, method, path, status, bytes, hash, features
# We keep it as a dict so it round-trips 1:1 with the Rust normalizer's JSON.
FEATURE_KEYS = ["bytes", "status", "method_code", "path_len", "path_entropy", "special_chars"]
