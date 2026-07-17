"""The detector: fit an Isolation Forest on baseline traffic, then score live
records and dispatch anomalies to the incident agent."""

from __future__ import annotations

from typing import Any, Optional

from .agent import SecurityAgent, build_agent
from .features import feature_vector, features_of
from .iforest import IsolationForest
from .models import ScoreResult


class Detector:
    def __init__(
        self,
        forest: Optional[IsolationForest] = None,
        agent: Optional[SecurityAgent] = None,
        threshold: float = 0.62,
    ) -> None:
        self.forest = forest or IsolationForest()
        self.agent = agent or build_agent()
        self.threshold = threshold
        self.fitted = False

    def fit(self, records: list[dict[str, Any]]) -> "Detector":
        X = [feature_vector(features_of(r)) for r in records]
        self.forest.fit(X)
        self.fitted = True
        return self

    def score(self, records: list[dict[str, Any]]) -> list[ScoreResult]:
        if not self.fitted:
            raise RuntimeError("detector not fitted — call fit() on baseline traffic first")
        X = [feature_vector(features_of(r)) for r in records]
        scores = self.forest.score_samples(X)
        out: list[ScoreResult] = []
        for i, (rec, s) in enumerate(zip(records, scores)):
            anomaly = s >= self.threshold
            incident = self.agent.investigate(rec, s) if anomaly else None
            out.append(ScoreResult(index=i, anomaly=anomaly, score=float(s), incident=incident))
        return out
