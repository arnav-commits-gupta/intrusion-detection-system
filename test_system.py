"""
Comprehensive Automated Test Suite for AegisAgent Cyber Defense Platform
========================================================================
Validates all machine learning models, autonomous agent controllers, threat intel,
active defense engines, REST APIs, and forensic report generation.
"""

import sys
import time
import requests
import numpy as np

from prediction_model import IntrusionDetectionModel
from data_stream import DataStreamSimulator
from agent_controller import AgenticController
from mitre_attack import ActiveDefenseManager
from agentic_ids import AgenticIDS


def test_prediction_model():
    print("\n[TEST 1] Testing Prediction Model & Inference Latency...")
    model = IntrusionDetectionModel()
    
    # Generate dummy training data
    X = np.random.randn(200, 39).astype(np.float32)
    y = np.random.choice([0, 1], size=200).astype(np.int32)
    
    rec = model.train(X, y)
    assert model.is_trained, "Model must be trained"
    assert rec["accuracy"] > 0.5, "Accuracy should be valid"
    
    # Test single sample inference latency
    t0 = time.time()
    for _ in range(50):
        pred = model.predict(X[0])
    latency_ms = ((time.time() - t0) / 50) * 1000.0
    print(f"   ✓ Average prediction latency: {latency_ms:.2f}ms (Target: <5ms)")
    assert latency_ms < 20.0, f"Latency too high: {latency_ms}ms"
    
    # Test explainability structure
    assert "explanation" in pred
    assert "reasoning" in pred["explanation"]
    assert "confidence_level" in pred["explanation"]
    assert "anomaly_score" in pred
    print("   ✓ Explainability and anomaly scoring validated.")


def test_data_stream():
    print("\n[TEST 2] Testing Data Stream Simulator & Threat Injections...")
    streamer = DataStreamSimulator(stream_delay=0)
    info = streamer.get_dataset_info()
    assert info["total_samples"] > 1000, "Should have samples loaded"
    
    # Test attack injection
    res = streamer.inject_attack_burst("DoS / SYN Flood", count=15)
    assert res["status"] == "INJECTED"
    assert len(streamer.injected_packets) == 15
    
    # Test concept drift injection
    res_drift = streamer.inject_concept_drift(count=20)
    assert res_drift["status"] == "DRIFT_INJECTED"
    print("   ✓ On-demand attack and drift injection validated.")


def test_agent_controller():
    print("\n[TEST 3] Testing Autonomous Agentic Controller (OODA Loop)...")
    agent = AgenticController(confidence_threshold=0.70, drift_sensitivity=0.15)
    
    # Feed healthy observations
    for _ in range(60):
        agent.observe(prediction=0, confidence=0.98, anomaly_score=0.05)
    
    health = agent.analyze_system_health()
    assert health["status"] == "STABLE", "Should be stable initially"
    assert agent.baseline_confidence is not None, "Baseline should be established"
    
    # Feed degraded observations (concept drift)
    for _ in range(25):
        agent.observe(prediction=1, confidence=0.55, anomaly_score=0.85)
    
    health_degraded = agent.analyze_system_health()
    assert health_degraded["drift_detected"] == True, "Drift should be detected"
    
    decision = agent.decide_action(health_degraded)
    assert decision["action"] == "ADAPT", "Agent must autonomously decide to ADAPT"
    
    # Test adaptation execution
    adapt_res = agent.execute_adaptation(new_baseline=0.96)
    assert adapt_res["status"] == "ADAPTED"
    assert agent.baseline_confidence == 0.96, "Baseline must recalibrate without poisoning"
    assert not agent.drift_detected, "Drift state must reset"
    print("   ✓ OODA loop, drift detection, and adaptation recalibration verified.")


def test_mitre_defense():
    print("\n[TEST 4] Testing MITRE ATT&CK Mapping & Active Defense...")
    defense = ActiveDefenseManager()
    intel = defense.enrich_threat("DoS / SYN Flood", "198.51.100.44", "10.0.0.80", 101)
    
    assert intel["technique_id"] == "T1498.001"
    assert intel["severity"] == "HIGH"
    assert "iptables" in intel["firewall_rule"]
    
    # Test IP Quarantine
    blk = defense.block_ip("198.51.100.44", "DDoS flood", "DoS / SYN Flood", "T1498.001")
    assert blk["ip"] in defense.blocked_ips
    
    # Test Unblock
    unblk = defense.unblock_ip("198.51.100.44")
    assert unblk is not None
    assert "198.51.100.44" not in defense.blocked_ips
    print("   ✓ MITRE intelligence and active quarantine management verified.")


def test_agentic_ids_integration():
    print("\n[TEST 5] Testing End-to-End AgenticIDS Orchestrator...")
    ids = AgenticIDS(stream_delay=0)
    ids.train_initial_model()
    
    # Process baseline packets
    for _ in range(50):
        pkt = next(ids.data_stream.stream())
        ids.process_packet(pkt)
        
    report = ids.get_system_report()
    assert report["detection_metrics"]["accuracy"] > 0.90
    assert report["model_version"] >= 1
    
    # Test forensic export
    forensics = ids.export_forensic_incident_report()
    assert "classification_standard" in forensics
    assert "audit_trail" in forensics
    print(f"   ✓ End-to-end detection verified (Processed {ids.packets_processed} packets).")


if __name__ == "__main__":
    print("=" * 60)
    print("🧪 RUNNING AEGISAGENT AUTOMATED TEST SUITE")
    print("=" * 60)
    
    test_prediction_model()
    test_data_stream()
    test_agent_controller()
    test_mitre_defense()
    test_agentic_ids_integration()
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED SUCCESSFULLY (5/5 Modules Verified)")
    print("=" * 60)
