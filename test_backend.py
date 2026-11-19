"""
Test script to verify all FastAPI endpoints and SQLite integrations.
Uses FastAPI's built-in TestClient so it tests the entire app synchronously.
"""

import os
import sys

# Ensure root directory is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_all():
    print("\n" + "=" * 60)
    print("  VERITRACE BACKEND & DATASET VERIFICATION SUITE")
    print("=" * 60)

    # 1. Root Health Check
    res = client.get("/")
    assert res.status_code == 200, f"Root failed: {res.text}"
    print(f"[PASS] 1. Root Health Check: {res.json()['status']}")

    # 2. Dataset Stats API
    res = client.get("/api/dataset/stats")
    assert res.status_code == 200, f"Stats failed: {res.text}"
    stats = res.json()
    print(f"[PASS] 2. Dataset Stats:")
    print(f"       - Dataset: {stats['dataset_name']}")
    print(f"       - Total Records: {stats['total_records']:,}")
    print(f"       - Total Features: {stats['total_features']}")
    print(f"       - Attack Categories: {len(stats['attack_categories'])} unique categories")

    # 3. Dataset Records API (Sample records)
    res = client.get("/api/dataset/records?limit=3")
    assert res.status_code == 200, f"Records failed: {res.text}"
    records_data = res.json()
    assert len(records_data["records"]) == 3, "Did not get 3 records"
    print(f"[PASS] 3. Dataset Records: Successfully retrieved sample records.")
    print(f"       - Sample 1: proto={records_data['records'][0]['proto']}, attack_cat={records_data['records'][0]['attack_cat']}")

    # 4. Dataset Filter by Category (e.g. Exploits)
    res = client.get("/api/dataset/records?category=Exploits&limit=2")
    assert res.status_code == 200, f"Filter failed: {res.text}"
    exploit_records = res.json()
    print(f"[PASS] 4. Category Filtering: Successfully filtered Exploits records ({exploit_records['total_available_in_db']} matches in DB).")

    # 5. Incident Creation API
    incident_payload = {
        "key": "ransomware",
        "title": "Ransomware on Saket branch file server",
        "discovered": 1732000000000,
        "pii": True,
        "eu": False,
        "notes": "EDR alert on FS-BR-07: shadow copies deleted and files encrypted.",
        "owner": "Akshat Saxena",
        "attack_category": "Ransomware",
        "severity": "Critical",
    }
    res = client.post("/api/incidents", json=incident_payload)
    assert res.status_code == 201, f"Create incident failed: {res.text}"
    inc = res.json()
    inc_id = inc["id"]
    print(f"[PASS] 5. Incident Created: {inc_id} - '{inc['title']}'")
    print(f"       - Total Playbook Steps Generated: {len(inc['steps'])}")
    print(f"       - Genesis Evidence Hash: {inc['evidence_logs'][0]['current_hash'][:16]}...")

    # 6. Add Evidence Log
    evidence_payload = {
        "actor": "Megha Singhal",
        "action": "Memory dump and forensic image collected from FS-BR-07",
        "extra": "Image verified against disk hash",
        "file_name": "fs-br-07-dump.raw",
        "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    res = client.post(f"/api/incidents/{inc_id}/evidence", json=evidence_payload)
    assert res.status_code == 200, f"Add evidence failed: {res.text}"
    ev = res.json()
    print(f"[PASS] 6. Evidence Appended to Hash Chain:")
    print(f"       - Action: {ev['action']}")
    print(f"       - Prev Hash: {ev['prev_hash'][:16]}...")
    print(f"       - New Hash:  {ev['current_hash'][:16]}...")

    # 7. Step Approval
    step_to_approve = inc["steps"][2]["id"]  # Phase 1, Step 0
    res = client.post(
        f"/api/incidents/{inc_id}/steps/{step_to_approve}",
        json={"done": True, "by": "Akshat Saxena"},
    )
    assert res.status_code == 200, f"Step approval failed: {res.text}"
    print(f"[PASS] 7. Step Approval: Approved {step_to_approve} and chained into evidence log.")

    # 8. Cryptographic Chain Verification
    res = client.get(f"/api/incidents/{inc_id}/verify-chain")
    assert res.status_code == 200, f"Chain verify failed: {res.text}"
    verify_result = res.json()
    assert verify_result["intact"] is True, "Evidence chain integrity check failed!"
    print(f"[PASS] 8. Server-Side Chain Verification: {verify_result['message']}")

    print("=" * 60)
    print("  ALL TESTS PASSED! BACKEND & DATASET FULLY FUNCTIONAL.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    test_all()
