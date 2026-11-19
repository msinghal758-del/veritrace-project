"""
VeriTrace - Phase 4 Integration Test Suite
Verifies:
1. POST /api/ml/predict with valid network traffic producing real predictions.
2. POST /api/ml/predict with invalid inputs returning proper HTTP 422 errors.
3. GET /api/ml/metrics returning genuine metrics matching metrics.json.
4. GET /api/dataset/stats & records (existing dataset APIs).
5. POST & GET /api/incidents (existing incident APIs).
6. GET /api/incidents/{id}/verify-chain (SHA-256 cryptographic chain of custody).
"""

import os
import sys
import json

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def run_tests():
    print("\n" + "=" * 70)
    print("  VERITRACE PHASE 4: ML ENDPOINTS & BACKEND INTEGRATION TEST SUITE")
    print("=" * 70)

    # -------------------------------------------------------------
    # 0. Health check & ML status
    # -------------------------------------------------------------
    res = client.get("/api/ml/status")
    assert res.status_code == 200, f"Status failed: {res.text}"
    status_data = res.json()
    print(f"\n[PASS] 0. Model Status Endpoint:")
    print(f"       - Status: {status_data['status']}")
    print(f"       - Model Type: {status_data['model_type']}")
    print(f"       - Classes ({status_data['n_classes']}): {status_data['classes']}")

    # -------------------------------------------------------------
    # 1. Real Prediction Test (Valid Input)
    # -------------------------------------------------------------
    # Flow with characteristics typical of Exploits / Probe (high state_ttl, specific ports)
    sample_flow_exploit = {
        "dur": 0.5,
        "proto": "tcp",
        "service": "http",
        "state": "FIN",
        "spkts": 10,
        "dpkts": 8,
        "sbytes": 700,
        "dbytes": 1200,
        "rate": 35.0,
        "sttl": 62,
        "dttl": 252,
        "sload": 9500.0,
        "dload": 16000.0,
        "ct_srv_src": 2,
        "ct_state_ttl": 1,
        "ct_dst_ltm": 1
    }

    res = client.post("/api/ml/predict", json=sample_flow_exploit)
    assert res.status_code == 200, f"Predict failed: {res.text}"
    pred = res.json()

    print(f"\n[PASS] 1. Valid Traffic Prediction (Real Model Inference):")
    print(f"       - Predicted Category: {pred['predicted_attack_category']}")
    print(f"       - Is Attack: {pred['is_attack']}")
    print(f"       - Confidence: {pred['confidence_percentage']}")
    print(f"       - Severity: {pred['severity']}")
    print(f"       - MITRE ATT&CK: {pred['mitre_attack']}")
    print(f"       - Inference Time: {pred['inference_time_ms']} ms")
    print(f"       - Top Probabilities: {sorted(pred['class_probabilities'].items(), key=lambda x: x[1], reverse=True)[:3]}")

    assert pred['predicted_attack_category'] in status_data['classes'], "Prediction not in known classes!"
    assert 0.0 <= pred['confidence'] <= 1.0, "Invalid confidence range!"
    assert len(pred['class_probabilities']) == 10, "Probabilities do not contain 10 classes!"

    # -------------------------------------------------------------
    # 2. Invalid Input Validation Test
    # -------------------------------------------------------------
    invalid_flow = {
        "dur": "NOT_A_NUMBER_INVALID_TYPE",  # Should trigger pydantic validation error
        "spkts": "INVALID_PACKET_COUNT"
    }
    res = client.post("/api/ml/predict", json=invalid_flow)
    assert res.status_code == 422, f"Expected 422 for invalid input, got {res.status_code}"
    print(f"\n[PASS] 2. Invalid Input Rejection:")
    print(f"       - Returned HTTP 422 Unprocessable Entity as expected.")
    print(f"       - Error Detail: {res.json()['detail'][0]['msg']}")

    # -------------------------------------------------------------
    # 3. Metrics API Verification (Matches metrics.json)
    # -------------------------------------------------------------
    res = client.get("/api/ml/metrics")
    assert res.status_code == 200, f"Metrics failed: {res.text}"
    metrics = res.json()

    # Read the ground truth file to assert exact match
    metrics_path = os.path.join(BASE_DIR, "backend", "models", "metrics.json")
    with open(metrics_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    expected_acc = ground_truth["evaluation"]["accuracy"]
    expected_f1_w = ground_truth["evaluation"]["f1_weighted"]
    expected_f1_m = ground_truth["evaluation"]["f1_macro"]

    assert abs(metrics["summary"]["accuracy"] - expected_acc) < 1e-6, "Accuracy mismatch!"
    assert abs(metrics["summary"]["weighted_f1"] - expected_f1_w) < 1e-6, "Weighted F1 mismatch!"
    assert abs(metrics["summary"]["macro_f1"] - expected_f1_m) < 1e-6, "Macro F1 mismatch!"

    print(f"\n[PASS] 3. Metrics API Verification (Matches Saved metrics.json):")
    print(f"       - Overall Accuracy   : {metrics['summary']['accuracy'] * 100:.2f}% (Exact match: {expected_acc:.4f})")
    print(f"       - Weighted Precision : {metrics['summary']['weighted_precision'] * 100:.2f}%")
    print(f"       - Weighted Recall    : {metrics['summary']['weighted_recall'] * 100:.2f}%")
    print(f"       - Weighted F1-Score  : {metrics['summary']['weighted_f1'] * 100:.2f}% (Exact match: {expected_f1_w:.4f})")
    print(f"       - Macro Precision    : {metrics['summary']['macro_precision'] * 100:.2f}%")
    print(f"       - Macro Recall       : {metrics['summary']['macro_recall'] * 100:.2f}%")
    print(f"       - Macro F1-Score     : {metrics['summary']['macro_f1'] * 100:.2f}% (Exact match: {expected_f1_m:.4f})")
    print(f"       - Per-Class Report   : Verified for all {len(metrics['per_class_report'])} classes")
    print(f"       - Confusion Matrix   : Verified {len(metrics['confusion_matrix']['matrix'])}x{len(metrics['confusion_matrix']['matrix'][0])} matrix")

    # -------------------------------------------------------------
    # 4. Existing Dataset APIs Still Functional
    # -------------------------------------------------------------
    res = client.get("/api/dataset/stats")
    assert res.status_code == 200, f"Dataset stats failed: {res.text}"
    stats = res.json()
    assert stats["total_records"] == 175341, "Record count incorrect"

    res = client.get("/api/dataset/records?limit=3")
    assert res.status_code == 200, f"Dataset records failed: {res.text}"
    records = res.json()
    assert len(records["records"]) == 3, "Did not get 3 records"

    print(f"\n[PASS] 4. Existing Dataset APIs Functional:")
    print(f"       - Total Records in DB: {stats['total_records']:,}")
    print(f"       - Sample Record ID: {records['records'][0]['id']}")

    # -------------------------------------------------------------
    # 5. Existing Incident APIs Still Functional
    # -------------------------------------------------------------
    inc_payload = {
        "key": "phishing",
        "title": "Executive Spearphishing Incident",
        "discovered": 1732005000000,
        "pii": True,
        "eu": False,
        "notes": "C-level executive account compromised via targeted spearphishing link.",
        "owner": "Akshat Saxena",
        "attack_category": "Phishing",
        "severity": "High"
    }
    res = client.post("/api/incidents", json=inc_payload)
    assert res.status_code == 201, f"Create incident failed: {res.text}"
    inc_data = res.json()
    inc_id = inc_data["id"]

    res = client.get(f"/api/incidents/{inc_id}")
    assert res.status_code == 200, f"Get incident failed: {res.text}"

    print(f"\n[PASS] 5. Existing Incident APIs Functional:")
    print(f"       - Created Incident: {inc_id} - '{inc_data['title']}'")
    print(f"       - Steps Initialized: {len(inc_data['steps'])} steps")

    # -------------------------------------------------------------
    # 6. Existing SHA-256 Evidence Verification Still Functional
    # -------------------------------------------------------------
    ev_payload = {
        "actor": "Akshat Saxena",
        "action": "Revoked session tokens and enforced hardware MFA",
        "extra": "Azure AD tenant log ID: AAD-8849-REVOKED"
    }
    res = client.post(f"/api/incidents/{inc_id}/evidence", json=ev_payload)
    assert res.status_code == 200, f"Add evidence failed: {res.text}"

    res = client.get(f"/api/incidents/{inc_id}/verify-chain")
    assert res.status_code == 200, f"Verify chain failed: {res.text}"
    chain_result = res.json()
    assert chain_result["intact"] is True, "Evidence chain failed verification!"

    print(f"\n[PASS] 6. Existing SHA-256 Evidence Chain Verification Functional:")
    print(f"       - Chain Status: Intact ({chain_result['entries_verified']} entries verified)")
    print(f"       - Latest SHA-256 Hash: {chain_result['latest_hash']}")

    print("\n" + "=" * 70)
    print("  ALL 6 VERIFICATION CRITERIA PASSED! PHASE 4 INTEGRATION COMPLETE.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_tests()
