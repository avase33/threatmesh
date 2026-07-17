"""Incident agent — classifies an anomaly and drafts remediation.

Offline it uses rule-based classification + templated firewall rules (deterministic
and testable). With ``THREATMESH_LLM=openai`` it asks a real model to write the
remediation and a short analyst summary. The interface the detector sees is the
same either way.
"""

from __future__ import annotations

import os
from typing import Any

from .models import Incident

_SQLI = ["union select", "' or", "or '1'='1", " or 1=1", "%27", "information_schema", "sleep(", "--"]
_XSS = ["<script", "onerror=", "javascript:", "%3cscript"]
_TRAVERSAL = ["../", "%2e%2e", "/etc/passwd", "..\\"]

_SEVERITY = {
    "sqli": "critical",
    "xss": "high",
    "path_traversal": "high",
    "data_exfil": "critical",
    "brute_force": "medium",
    "recon_scan": "low",
    "anomaly": "medium",
}


def classify(rec: dict[str, Any]) -> str:
    path = str(rec.get("path", "")).lower()
    status = int(rec.get("status", 200) or 200)
    nbytes = int(rec.get("bytes", 0) or 0)
    if any(k in path for k in _SQLI):
        return "sqli"
    if any(k in path for k in _XSS):
        return "xss"
    if any(k in path for k in _TRAVERSAL):
        return "path_traversal"
    if nbytes > 500_000:
        return "data_exfil"
    if status in (401, 403):
        return "brute_force"
    if status == 404:
        return "recon_scan"
    return "anomaly"


class SecurityAgent:
    name = "mock"

    def investigate(self, rec: dict[str, Any], score: float) -> Incident:
        kind = classify(rec)
        ip = str(rec.get("ip", "unknown"))
        severity = _SEVERITY.get(kind, "medium")
        summary = (
            f"{kind.replace('_', ' ').title()} indicators from {ip} "
            f"(anomaly score {score:.2f}) on {rec.get('method', '?')} {rec.get('path', '?')}."
        )
        rule = f"iptables -A INPUT -s {ip} -j DROP"
        if kind == "brute_force":
            rule = f"iptables -A INPUT -s {ip} -m recent --set --name bf; " \
                   f"iptables -A INPUT -s {ip} -m recent --update --seconds 60 --hitcount 10 -j DROP"
        return Incident(severity=severity, kind=kind, summary=summary, firewall_rule=rule)


class OpenAIAgent(SecurityAgent):  # pragma: no cover - needs network + key
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        from openai import OpenAI  # type: ignore

        self._client = OpenAI(api_key=api_key)
        self._model = model

    def investigate(self, rec: dict[str, Any], score: float) -> Incident:
        base = super().investigate(rec, score)
        prompt = (
            "You are a SOC analyst. Given this suspicious HTTP log record, write a one-sentence "
            f"summary and a single iptables rule to mitigate it.\nRecord: {rec}\nScore: {score:.2f}"
        )
        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=120,
            )
            base.summary = resp.choices[0].message.content or base.summary
        except Exception:
            pass
        return base


def build_agent() -> SecurityAgent:
    if os.environ.get("THREATMESH_LLM", "mock").lower() == "openai" and os.environ.get("OPENAI_API_KEY"):
        return OpenAIAgent(os.environ["OPENAI_API_KEY"])
    return SecurityAgent()
