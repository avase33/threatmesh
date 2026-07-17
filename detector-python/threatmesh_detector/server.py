"""FastAPI service for the detector. Fits on a synthetic baseline at startup so
`/score` works immediately; POST your own baseline to `/fit` to re-fit."""

from __future__ import annotations

from typing import Any

from .detector import Detector
from .synth import baseline

try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
except ImportError as e:  # pragma: no cover
    raise RuntimeError("Install server extras: pip install 'threatmesh-detector[server]'") from e

app = FastAPI(title="threatmesh-detector", version="0.1.0")
_detector = Detector().fit(baseline())


class Records(BaseModel):
    records: list[dict[str, Any]]


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "detector", "agent": _detector.agent.name,
                         "fitted": _detector.fitted})


@app.post("/fit")
def fit(body: Records) -> dict[str, Any]:
    _detector.fit(body.records)
    return {"fitted": True, "baseline": len(body.records)}


@app.post("/score")
def score(body: Records) -> dict[str, Any]:
    results = _detector.score(body.records)
    return {"results": [r.to_dict() for r in results]}
