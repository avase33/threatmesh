"""Feature extraction from a normalized log record.

Mirrors the feature schema the Rust normalizer emits, so the detector works
whether features arrive from Rust or are computed here (offline/tests).
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

_METHOD = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "HEAD": 4, "PATCH": 5, "OPTIONS": 6}
_SPECIAL = set("'\";=%<>()|&$*")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def compute_features(rec: dict[str, Any]) -> dict[str, float]:
    path = str(rec.get("path", ""))
    method = str(rec.get("method", "GET")).upper()
    return {
        "bytes": float(rec.get("bytes", 0) or 0),
        "status": float(rec.get("status", 200) or 200),
        "method_code": float(_METHOD.get(method, 7)),
        "path_len": float(len(path)),
        "path_entropy": round(_entropy(path), 4),
        "special_chars": float(sum(1 for ch in path if ch in _SPECIAL)),
    }


def feature_vector(features: dict[str, float]) -> list[float]:
    return [
        math.log1p(features.get("bytes", 0.0)),
        features.get("status", 200.0) / 100.0,
        features.get("method_code", 0.0),
        features.get("path_len", 0.0),
        features.get("path_entropy", 0.0),
        features.get("special_chars", 0.0),
    ]


def features_of(rec: dict[str, Any]) -> dict[str, float]:
    """Use Rust-supplied features if present, else compute them."""
    f = rec.get("features")
    if isinstance(f, dict) and "path_len" in f:
        return {k: float(v) for k, v in f.items()}
    return compute_features(rec)
