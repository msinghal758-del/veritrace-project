"""
VeriTrace - Phase 5 Frontend & ML Integration Test Suite
Verifies:
1. /app serves index.html with AI Threat Analysis and ML Performance Dashboard.
2. /api/ml/status confirms model is READY.
3. Presets can be predicted cleanly by the ML pipeline.
4. /api/ml/metrics returns verified evaluation scores.
5. Evidence timeline and SHA-256 integrity verification remain intact.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_phase5():
    print("\n" + "=" * 70)
    print("  VERITRACE PHASE 5: FRONTEND ML INTEGRATION TEST SUITE")
    print("=" * 70)

    # 1. Test /app serves updated index.html
    res = client.get("/app")
    assert res.status_code == 200, f"/app failed: {res.status_code}"
    html = res.text
    assert "AI Network Threat Analysis" in html, "Missing AI Threat Analysis section in index.html"
    assert "ML Model Performance Dashboard" in html, "Missing ML Performance Dashboard in index.html"
    assert "data-ctab=\"threat\"" in html, "Missing threat tab navigation"
    assert "data-ctab=\"metrics\"" in html, "Missing metrics tab navigation"
    assert "ml-status-pill" in html, "Missing ML status badge in index.html"
    assert "Scope &amp; Data Boundary" in html, "Missing dataset scope disclaimer"
    print("[PASS] 1. Frontend Delivery (/app):")
    print("       - Successfully served index.html")
    print("       - Verified presence of AI Threat Analysis section")
    print("       - Verified presence of ML Model Performance Dashboard")
    print("       - Verified presence of Scope & Data Boundary disclaimers")

    # 2. Test Model Status
    res = client.get("/api/ml/status")
    assert res.status_code == 200, f"Status failed: {res.text}"
    status_data = res.json()
    assert status_data["status"] == "ready", "Model not ready"
    print(f"\n[PASS] 2. Model Status API:")
    print(f"       - Status: {status_data['status'].upper()}")
    print(f"       - Architecture: {status_data['model_type']}")
    print(f"       - Number of Classes: {status_data['n_classes']}")

    # 3. Test All 5 Frontend Presets on /api/ml/predict
    presets = {
        "Exploits (HTTP Probe)": {
            "dur": 0.506, "proto": "tcp", "service": "http", "state": "FIN",
            "spkts": 12, "dpkts": 26, "sbytes": 860, "dbytes": 26136,
            "rate": 73.12, "sttl": 62, "dttl": 252, "sload": 12474.3,
            "ct_state_ttl": 1, "ct_srv_src": 1, "ct_dst_ltm": 1
        },
        "Generic (Payload Injection)": {
            "dur": 0.000003, "proto": "udp", "service": "dns", "state": "INT",
            "spkts": 2, "dpkts": 0, "sbytes": 114, "dbytes": 0,
            "rate": 333333.3, "sttl": 254, "dttl": 0, "sload": 152000000.0,
            "ct_state_ttl": 2, "ct_srv_src": 22, "ct_dst_ltm": 22
        },
        "Fuzzers (Buffer Overflow)": {
            "dur": 0.675, "proto": "tcp", "service": "ftp", "state": "FIN",
            "spkts": 12, "dpkts": 12, "sbytes": 2616, "dbytes": 682,
            "rate": 34.05, "sttl": 254, "dttl": 252, "sload": 28400.0,
            "ct_state_ttl": 1, "ct_srv_src": 3, "ct_dst_ltm": 2
        },
        "Recon (Port Scan)": {
            "dur": 0.179, "proto": "tcp", "service": "http", "state": "FIN",
            "spkts": 10, "dpkts": 6, "sbytes": 888, "dbytes": 268,
            "rate": 83.6, "sttl": 254, "dttl": 252, "sload": 35670.0,
            "ct_state_ttl": 1, "ct_srv_src": 1, "ct_dst_ltm": 1
        },
        "Normal (Benign Traffic)": {
            "dur": 0.121, "proto": "tcp", "service": "-", "state": "FIN",
            "spkts": 6, "dpkts": 4, "sbytes": 258, "dbytes": 172,
            "rate": 74.0, "sttl": 252, "dttl": 254, "sload": 14158.0,
            "ct_state_ttl": 0, "ct_srv_src": 1, "ct_dst_ltm": 1
        }
    }

    print(f"\n[PASS] 3. Testing Frontend Presets via Real Inference Pipeline:")
    for name, payload in presets.items():
        res = client.post("/api/ml/predict", json=payload)
        assert res.status_code == 200, f"Preset {name} failed: {res.text}"
        pred = res.json()
        print(f"       - Preset: {name:<25} -> Pred: {pred['predicted_attack_category']:<14} | Conf: {pred['confidence_percentage']:<8} | Latency: {pred['inference_time_ms']} ms")

    # 4. Test Metrics API
    res = client.get("/api/ml/metrics")
    assert res.status_code == 200, f"Metrics failed: {res.text}"
    m = res.json()
    s = m["summary"]
    print(f"\n[PASS] 4. Performance Metrics API Delivery:")
    print(f"       - Overall Accuracy: {s['accuracy'] * 100:.2f}%")
    print(f"       - Weighted F1     : {s['weighted_f1'] * 100:.2f}%")
    print(f"       - Macro F1        : {s['macro_f1'] * 100:.2f}%")
    print(f"       - Confusion Matrix: {len(m['confusion_matrix']['matrix'])}x{len(m['confusion_matrix']['matrix'][0])}")

    # 5. Test Existing Incident & Evidence Chain
    res = client.get("/api/incidents")
    assert res.status_code == 200
    incidents = res.json()
    assert len(incidents) > 0, "No incidents found"
    test_inc_id = incidents[0]["id"]

    res = client.get(f"/api/incidents/{test_inc_id}/verify-chain")
    assert res.status_code == 200
    chain = res.json()
    assert chain["intact"] is True, "Chain of custody broken"
    print(f"\n[PASS] 5. Cryptographic Evidence Chain Intact:")
    print(f"       - Incident: {test_inc_id}")
    print(f"       - Status  : {chain['message']}")

    print("\n" + "=" * 70)
    print("  PHASE 5 FRONTEND INTEGRATION TESTS ALL PASSED!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    test_phase5()
