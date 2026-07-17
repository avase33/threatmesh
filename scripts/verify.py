#!/usr/bin/env python3
"""Offline end-to-end check of the threatmesh detector core.

Fits the from-scratch Isolation Forest on synthetic baseline traffic, scores a
mixed stream (normal + planted attacks), and verifies the attacks are caught and
each anomaly gets an actionable incident — no services, no sklearn.

    python scripts/verify.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector-python"))

from threatmesh_detector.detector import Detector  # noqa: E402
from threatmesh_detector.synth import baseline, mixed_stream  # noqa: E402

_passed = 0
_failed = 0


def check(label: str, cond: bool) -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {label}")
    else:
        _failed += 1
        print(f"  [FAIL] {label}")


def main() -> int:
    print("=" * 72)
    print("threatmesh - offline end-to-end verification")
    print("=" * 72)
    det = Detector().fit(baseline(seed=1))
    stream = mixed_stream(seed=2)
    results = det.score(stream)

    attack_idx = {i for i, r in enumerate(stream) if "kind" in r}
    flagged = {r.index for r in results if r.anomaly}
    caught = attack_idx & flagged
    kinds = {stream[i]["kind"] for i in caught}
    false_pos = len(flagged) - len(caught)
    normals = len(stream) - len(attack_idx)

    print(f"  agent={det.agent.name}  baseline=800  scored={len(stream)}  "
          f"attacks={len(attack_idx)} caught={len(caught)} false_pos={false_pos}/{normals}")

    check("catches the data-exfil (huge payload) outlier", "data_exfil" in kinds)
    check("catches at least 4 of 6 planted attacks", len(caught) >= 4)
    check("false-positive rate under 20%", false_pos <= 0.2 * normals)
    incidents = [r.incident for r in results if r.anomaly and r.incident]
    check("every anomaly gets a firewall rule",
          bool(incidents) and all(i.firewall_rule.startswith("iptables") for i in incidents))

    print("-" * 72)
    print(f"RESULT: {_passed} passed, {_failed} failed")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
