import random

from threatmesh_detector.agent import classify
from threatmesh_detector.detector import Detector
from threatmesh_detector.features import compute_features, feature_vector
from threatmesh_detector.iforest import IsolationForest
from threatmesh_detector.synth import baseline, mixed_stream


def test_iforest_isolates_outliers():
    rng = random.Random(1)
    normal = [[rng.gauss(0, 0.3), rng.gauss(0, 0.3)] for _ in range(200)]
    f = IsolationForest(n_trees=60, sample_size=128, seed=3).fit(normal)
    center, outlier = f.score_samples([[0.0, 0.0], [8.0, 8.0]])
    assert outlier > center
    assert outlier > 0.6
    assert center < 0.6


def test_feature_extraction():
    f = compute_features({"path": "/api/products?id=1' OR '1'='1", "method": "POST", "status": 200, "bytes": 300})
    assert f["special_chars"] >= 3
    assert f["path_entropy"] > 0
    assert f["method_code"] == 1.0
    vec = feature_vector(f)
    assert len(vec) == 6


def test_classify_attack_kinds():
    assert classify({"path": "/x?id=1 UNION SELECT * FROM users", "status": 200}) == "sqli"
    assert classify({"path": "/s?q=<script>alert(1)</script>", "status": 200}) == "xss"
    assert classify({"path": "/f?p=../../../etc/passwd", "status": 200}) == "path_traversal"
    assert classify({"path": "/login", "status": 401}) == "brute_force"
    assert classify({"path": "/wp-admin/x.php", "status": 404}) == "recon_scan"
    assert classify({"path": "/export", "status": 200, "bytes": 9_000_000}) == "data_exfil"


def test_end_to_end_detection_and_incidents():
    det = Detector().fit(baseline(seed=1))
    stream = mixed_stream(seed=2)
    results = det.score(stream)

    attack_idx = {i for i, r in enumerate(stream) if "kind" in r}
    flagged = {r.index for r in results if r.anomaly}
    caught = attack_idx & flagged

    # catch most planted attacks
    assert len(caught) >= 4
    caught_kinds = {stream[i]["kind"] for i in caught}
    assert "data_exfil" in caught_kinds  # a huge-payload record is an obvious outlier

    # every anomaly carries an actionable incident
    for r in results:
        if r.anomaly:
            assert r.incident is not None
            assert r.incident.firewall_rule.startswith("iptables")

    # keep false positives on normal traffic low
    normals = len(stream) - len(attack_idx)
    false_pos = len(flagged) - len(caught)
    assert false_pos <= 0.2 * normals


def test_score_requires_fit():
    det = Detector()
    import pytest

    with pytest.raises(RuntimeError):
        det.score([{"path": "/", "status": 200, "bytes": 100}])
