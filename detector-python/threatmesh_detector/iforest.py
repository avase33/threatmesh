"""Isolation Forest — implemented from scratch, no scikit-learn.

Anomalies are 'few and different', so they get isolated by random axis-parallel
splits in far fewer steps than normal points. We build an ensemble of random
isolation trees on subsamples and turn the average path length into an anomaly
score in [0, 1] (higher = more anomalous), per Liu et al. 2008.
"""

from __future__ import annotations

import math
import random
from typing import Any

_EULER = 0.5772156649015329


def _harmonic(i: int) -> float:
    return math.log(i) + _EULER if i > 0 else 0.0


def _c(n: int) -> float:
    """Expected path length of an unsuccessful BST search over n points."""
    if n <= 1:
        return 1.0
    return 2.0 * _harmonic(n - 1) - (2.0 * (n - 1) / n)


def _build(rows: list[list[float]], depth: int, max_depth: int, rng: random.Random) -> dict[str, Any]:
    n = len(rows)
    if depth >= max_depth or n <= 1:
        return {"size": n}
    dim = len(rows[0])
    feats = list(range(dim))
    rng.shuffle(feats)
    for f in feats:
        vals = [r[f] for r in rows]
        mn, mx = min(vals), max(vals)
        if mn < mx:
            split = rng.uniform(mn, mx)
            left = [r for r in rows if r[f] < split]
            right = [r for r in rows if r[f] >= split]
            return {
                "feat": f,
                "split": split,
                "left": _build(left, depth + 1, max_depth, rng),
                "right": _build(right, depth + 1, max_depth, rng),
            }
    return {"size": n}  # all identical on every feature


def _path_length(x: list[float], node: dict[str, Any], depth: int) -> float:
    while "feat" in node:
        node = node["left"] if x[node["feat"]] < node["split"] else node["right"]
        depth += 1
    return depth + _c(node["size"])


class IsolationForest:
    def __init__(self, n_trees: int = 100, sample_size: int = 256, seed: int = 7) -> None:
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.rng = random.Random(seed)
        self._trees: list[dict[str, Any]] = []
        self._c_norm = 1.0

    def fit(self, X: list[list[float]]) -> "IsolationForest":
        if not X:
            raise ValueError("cannot fit on empty data")
        n = len(X)
        sample = min(self.sample_size, n)
        max_depth = max(1, math.ceil(math.log2(sample)))
        self._c_norm = _c(sample)
        self._trees = []
        for _ in range(self.n_trees):
            subset = [X[self.rng.randrange(n)] for _ in range(sample)]
            self._trees.append(_build(subset, 0, max_depth, self.rng))
        return self

    def score_samples(self, X: list[list[float]]) -> list[float]:
        out = []
        for x in X:
            avg = sum(_path_length(x, t, 0) for t in self._trees) / max(1, len(self._trees))
            out.append(2.0 ** (-avg / self._c_norm))
        return out

    def predict(self, X: list[list[float]], threshold: float = 0.6) -> list[int]:
        """1 = normal, -1 = anomaly (matching scikit-learn's convention)."""
        return [-1 if s >= threshold else 1 for s in self.score_samples(X)]
