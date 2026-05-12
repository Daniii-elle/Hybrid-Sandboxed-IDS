#!/usr/bin/env python3
"""
ELK API Test Script
Tests all ELK API functionality for the IDS system
"""

import sys
import time
from datetime import datetime
from elk_api import (
    ELKClient, initialize_elk_indices, send_anomaly_to_elk,
    send_alert_to_elk, send_event_to_elk, get_recent_anomalies,
    get_recent_alerts, get_elk_health
)

def test_basic_connectivity():
    """Test basic Elasticsearch connectivity"""
    print("Testing ELK connectivity...")
    client = ELKClient()

    if client.health_check():
        print("Elasticsearch is healthy")
        return True
    else:
        print("Elasticsearch connection failed")
        return False

def test_index_operations():
    """Test index creation, checking, and deletion"""
    print("\n Testing index operations...")
    client = ELKClient()

    test_index = "test-ids-api"

    # Test index creation
    if client.create_index(test_index):
        print("Index creation successful")
    else:
        print("Index creation failed")
        return False

    # Test index existence check
    if client.index_exists(test_index):
        print("Index existence check successful")
    else:
        print("Index existence check failed")
        return False

    # Test index deletion
    if client.delete_index(test_index):
        print("Index deletion successful")
    else:
        print("Index deletion failed")
        return False

    return True

def test_document_operations():
    """Test document indexing and searching"""
    print("\n Testing document operations...")
    client = ELKClient()

    test_index = "test-documents"

    # Create test index
    client.create_index(test_index)

    # Test single document indexing
    test_doc = {
        "message": "Test document",
        "test_type": "api_test",
        "timestamp": datetime.now().isoformat()
    }

    if client.index_document(test_index, test_doc):
        print("Single document indexing successful")
    else:
        print("Single document indexing failed")
        return False

    # Test bulk indexing
    bulk_docs = [
        {"message": "Bulk test 1", "test_type": "bulk_test"},
        {"message": "Bulk test 2", "test_type": "bulk_test"},
        {"message": "Bulk test 3", "test_type": "bulk_test"}
    ]

    if client.bulk_index(test_index, bulk_docs):
        print("Bulk document indexing successful")
    else:
        print("Bulk document indexing failed")
        return False

    # Test search
    time.sleep(1)  # Allow indexing to complete
    results = client.search(test_index, {"term": {"test_type": "bulk_test"}})

    if results and len(results) >= 3:
        print("Search operation successful")
    else:
        print("Search operation failed")
        return False

    # Cleanup
    client.delete_index(test_index)
    return True

def test_ids_operations():
    """Test IDS-specific operations"""
    print("\n Testing IDS operations...")

    # Test anomaly sending
    anomaly_data = {
        "duration": 2.5,
        "src_bytes": 1500,
        "dst_bytes": 2048,
        "anomaly_score": -1.0,
        "label": "Suspicious"
    }

    if send_anomaly_to_elk(anomaly_data):
        print("Anomaly sending successful")
    else:
        print("Anomaly sending failed")
        return False

    # Test alert sending
    alert_data = {
        "signature": "Test Alert Signature",
        "severity": 2,
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "protocol": "TCP"
    }

    if send_alert_to_elk(alert_data):
        print("Alert sending successful")
    else:
        print("Alert sending failed")
        return False

    # Test event sending
    event_data = {
        "event_type": "test_event",
        "message": "Test security event",
        "priority": "medium"
    }

    if send_event_to_elk(event_data, "test_event"):
        print("Event sending successful")
    else:
        print("Event sending failed")
        return False

    # Test data retrieval
    time.sleep(1)  # Allow indexing to complete

    anomalies = get_recent_anomalies(hours=1, limit=10)
    if anomalies is not None:
        print("Anomaly retrieval successful")
    else:
        print("Anomaly retrieval failed")
        return False

    alerts = get_recent_alerts(hours=1)
    if alerts is not None:
        print("Alert retrieval successful")
    else:
        print("Alert retrieval failed")
        return False

    return True

def test_system_health():
    """Test system health monitoring"""
    print("\n Testing system health monitoring...")

    health = get_elk_health()

    if 'elasticsearch_healthy' in health:
        if health['elasticsearch_healthy']:
            print("System health check successful")
        else:
            print("Elasticsearch not healthy")
            return False
    else:
        print("System health check failed")
        return False

    if 'indices' in health:
        print("Index status check successful")
        for index_name, exists in health['indices'].items():
            status = "Done" if exists else "Failed"
            print(f"   {status} {index_name} index")
    else:
        print("Index status check failed")
        return False

    return True

def main():
    """Run all ELK API tests"""
    print("Starting ELK API Tests\n")

    tests = [
        ("Basic Connectivity", test_basic_connectivity),
        ("Index Operations", test_index_operations),
        ("Document Operations", test_document_operations),
        ("IDS Operations", test_ids_operations),
        ("System Health", test_system_health)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"{test_name}: PASSED")
            else:
                print(f"{test_name}: FAILED")
        except Exception as e:
            print(f"{test_name}: ERROR - {e}")

    print(f"\n Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("All ELK API tests passed! System is ready.")
        print("\n Initializing production indices...")
        initialize_elk_indices()
        print("Production indices initialized")
        return True
    else:
        print("Some tests failed. Check Elasticsearch configuration.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)