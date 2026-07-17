"""CLI: ``threatmesh-detector demo|serve``."""

from __future__ import annotations

import argparse
import sys

from .detector import Detector
from .synth import baseline, mixed_stream


def _demo() -> int:
    det = Detector().fit(baseline())
    stream = mixed_stream()
    results = det.score(stream)

    print("=" * 72)
    print(f"threatmesh detector — agent={det.agent.name}  "
          f"baseline=800  scored {len(stream)} live records")
    print("=" * 72)

    attacks = [i for i, r in enumerate(stream) if "kind" in r]
    flagged = {res.index for res in results if res.anomaly}
    caught = [i for i in attacks if i in flagged]

    for res in results:
        if res.anomaly and res.incident:
            rec = stream[res.index]
            print(f"\n  [{res.incident.severity.upper():8}] {res.incident.kind}  "
                  f"score={res.score:.2f}  ip={rec.get('ip')}")
            print(f"    {res.incident.summary}")
            print(f"    ⛨ {res.incident.firewall_rule}")

    fp = len(flagged) - len(caught)
    print("\n" + "-" * 72)
    print(f"  attacks planted : {len(attacks)}")
    print(f"  attacks caught  : {len(caught)}")
    print(f"  false positives : {fp} / {len(stream) - len(attacks)} normal records")
    return 0


def _serve(host: str, port: int) -> int:
    try:
        import uvicorn  # type: ignore
    except ImportError:
        print("Install server extras: pip install 'threatmesh-detector[server]'", file=sys.stderr)
        return 1
    uvicorn.run("threatmesh_detector.server:app", host=host, port=port, log_level="info")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="threatmesh-detector")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="fit on baseline, score a mixed stream, show incidents")
    s = sub.add_parser("serve", help="run the FastAPI service")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8000)
    args = p.parse_args(argv)
    if args.cmd == "demo":
        return _demo()
    return _serve(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
