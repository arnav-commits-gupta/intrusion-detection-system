"""
Agentic Intrusion Detection System (IDS) Orchestrator
===================================================
Self-Adaptive Cyber Defense Platform integrating Prediction Model,
Autonomous Agentic Controller, Threat Intelligence, and Active Defense.
"""

import time
import numpy as np
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Callable

from agent_controller import AgenticController
from data_stream import DataStreamSimulator
from prediction_model import IntrusionDetectionModel
from mitre_attack import ActiveDefenseManager


class AgenticIDS:
    """
    Self-Adaptive Intrusion Detection System with Agentic AI.

    Key Features:
    1. Real-time packet telemetry & classification
    2. Autonomous concept drift detection & OODA loop reasoning
    3. Self-healing model adaptation with baseline recalibration
    4. MITRE ATT&CK threat intelligence enrichment
    5. Active defense containment (automated IP quarantining)
    6. Incident deduplication & forensic audit logging
    """

    def __init__(self, data_path=None, stream_delay=0.005, autonomous_mode=True):
        print("=" * 60)
        print("🛡️  AGENTIC CYBER DEFENSE PLATFORM (AEGIS-IDS)")
        print("=" * 60)
        print("Initializing self-adaptive cyber defense platform...")

        # Initialize core components
        print("📡 Initializing Data Stream Simulator...")
        self.data_stream = DataStreamSimulator(data_path, stream_delay)

        print("\n🧠 Initializing Random Forest Prediction Model...")
        self.model = IntrusionDetectionModel()

        print("\n🤖 Initializing Autonomous Agentic Controller...")
        self.agent = AgenticController(
            confidence_threshold=0.70,
            drift_window_size=100,
            drift_sensitivity=0.15,
            autonomous_mode=autonomous_mode,
        )

        print("\n🎯 Initializing MITRE ATT&CK Active Defense Engine...")
        self.defense_mgr = ActiveDefenseManager()

        # Telemetry & Performance State
        self.is_running = False
        self.is_paused = False
        self.packets_processed = 0
        self.attacks_detected = 0
        self.normal_traffic = 0
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        self.start_time = None
        self.last_packet_time = None
        self.recent_latencies = deque(maxlen=50)

        # Attack taxonomy breakdown
        self.attack_distribution = defaultdict(int)

        # Telemetry history for live charts (last 60 data points)
        self.telemetry_history = deque(maxlen=60)

        # Incident Management & Deduplication
        self.incidents: Dict[str, dict] = {}  # keyed by src_ip + attack_type
        self.alerts = deque(maxlen=100)
        self.incident_counter = 0

        # Event callbacks (e.g. for WebSockets)
        self.event_callbacks: List[Callable] = []

        print("\n✓ Aegis-IDS Orchestrator initialized successfully")
        print("=" * 60)

    def train_initial_model(self):
        """
        Train baseline model on first partition of dataset before real-time detection.
        """
        print("\n🎓 Training initial detection model...")
        info = self.data_stream.get_dataset_info()

        # Use first 70% clean data; hold out the last 20% of it as a validation set
        # that retraining must not get worse on.
        train_size = int(info["total_samples"] * 0.70)
        split = int(train_size * 0.80)
        X_train = self.data_stream.features[:split]
        y_train = self.data_stream.labels[:split]
        X_val = self.data_stream.features[split:train_size]
        y_val = self.data_stream.labels[split:train_size]

        # Initial model uses all training rows.
        rng = np.random.RandomState(42)
        self.val_X, self.val_y = X_val, y_val

        # Clean replay reference so retraining never forgets normal traffic
        ref_n = min(5000, len(X_train))
        ref_idx = rng.choice(len(X_train), ref_n, replace=False)
        self.reference_X, self.reference_y = X_train[ref_idx], y_train[ref_idx]

        self.train_rows = len(X_train)
        record = self.model.train(X_train, y_train, self.data_stream.feature_names)
        self.data_stream.reset()

        # Calibrate initial agent baseline
        self.agent.baseline_confidence = float(record["accuracy"])
        print(f"✓ Initial baseline calibrated: {self.agent.baseline_confidence:.2%}")
        return record

    def register_callback(self, callback: Callable):
        """Register a subscriber callback for real-time packet telemetry events"""
        self.event_callbacks.append(callback)

    def process_packet(self, packet: dict) -> dict:
        """
        Process a single packet through classification, agent reasoning, and active defense.
        """
        t0 = time.time()

        # Cache features & label for online sliding retraining buffer
        if not hasattr(self, "recent_samples_buffer"):
            self.recent_samples_buffer = deque(maxlen=500)
        self.recent_samples_buffer.append((packet["features"], int(packet["label"])))

        # Predict with model
        result = self.model.predict(packet["features"])
        latency_ms = (time.time() - t0) * 1000.0
        self.recent_latencies.append(latency_ms)

        self.packets_processed += 1
        true_label = int(packet["label"])
        pred_label = int(result["prediction"])
        confidence = float(result["confidence"])
        anomaly_score = float(result["anomaly_score"])
        attack_type = result["attack_type"] if pred_label == 1 else "BENIGN / NORMAL"

        # Update confusion metrics
        if pred_label == 1:
            self.attacks_detected += 1
            self.attack_distribution[attack_type] += 1
        else:
            self.normal_traffic += 1

        if pred_label == 1 and true_label == 1:
            self.true_positives += 1
        elif pred_label == 1 and true_label == 0:
            self.false_positives += 1
        elif pred_label == 0 and true_label == 0:
            self.true_negatives += 1
        else:
            self.false_negatives += 1

        # Agent Observation
        self.agent.observe(
            prediction=pred_label,
            confidence=confidence,
            features=packet["features"],
            anomaly_score=anomaly_score,
        )

        # Agent Analysis & Health Assessment
        health = self.agent.analyze_system_health()

        # Agent Decision Making
        decision = self.agent.decide_action(health)

        # Autonomous Adaptation Execution if triggered
        adaptation_result = None
        if decision["action"] == "ADAPT":
            adaptation_result = self._execute_adaptation()
            self._create_alert(
                alert_type="DRIFT_DETECTED",
                severity="HIGH",
                message=f"Autonomous adaptation triggered: {decision['reason']}",
                details=decision["confidence_metrics"],
                src_ip="System Agent",
                attack_type="Concept Drift / Distribution Shift",
            )

        # Active Threat Handling & MITRE Enrichment
        threat_intel = None
        containment_action = None

        if pred_label == 1:
            threat_intel = self.defense_mgr.enrich_threat(
                attack_type=attack_type,
                src_ip=packet.get("src_ip", "0.0.0.0"),
                dst_ip=packet.get("dst_ip", "10.0.0.1"),
                packet_id=packet.get("packet_id", self.packets_processed),
            )

            # Auto-Containment: If in autonomous mode, automatically block IP
            if self.agent.autonomous_mode and packet.get("src_ip") and packet["src_ip"] not in self.defense_mgr.blocked_ips:
                containment_action = self.defense_mgr.block_ip(
                    ip=packet["src_ip"],
                    reason=f"High-confidence {attack_type} detected ({confidence:.1%})",
                    attack_type=attack_type,
                    technique_id=threat_intel["technique_id"],
                    auto=True,
                )

            # Deduplicated Incident & Alert Creation
            self._record_incident(packet, result, threat_intel, containment_action)

        # Record telemetry sample for real-time charting
        if self.packets_processed % 3 == 0:
            self.telemetry_history.append({
                "packet_id": packet.get("packet_id", self.packets_processed),
                "timestamp": datetime.now().isoformat(),
                "confidence": round(confidence, 4),
                "baseline": round(self.agent.baseline_confidence or confidence, 4),
                "drift_threshold": round((self.agent.baseline_confidence or confidence) - self.agent.drift_sensitivity, 4),
                "anomaly_score": round(anomaly_score, 4),
                "is_attack": pred_label == 1,
            })

        response = {
            "packet_id": packet.get("packet_id", self.packets_processed),
            "timestamp": datetime.now().isoformat(),
            "src_ip": packet.get("src_ip", "192.168.1.100"),
            "dst_ip": packet.get("dst_ip", "10.0.0.80"),
            "port": packet.get("port", 80),
            "protocol": packet.get("protocol", "TCP"),
            "service": packet.get("service", "http"),
            "true_label": true_label,
            "prediction": result,
            "agent_health": health,
            "agent_decision": decision,
            "adaptation": adaptation_result,
            "threat_intel": threat_intel,
            "containment": containment_action,
            "latency_ms": round(latency_ms, 2),
        }

        # Dispatch to registered callbacks
        for cb in self.event_callbacks:
            try:
                cb(response)
            except Exception:
                pass

        return response

    def _execute_adaptation(self) -> dict:
        """
        Retrain on clean reference data plus recent traffic, then keep the new model
        only if it does not get worse on held-out clean validation data.
        Retraining on the recent window alone let an attack burst overwrite the model.
        """
        import copy

        window = list(self.recent_samples_buffer) if hasattr(self, "recent_samples_buffer") else []
        if len(window) < 200:
            return {"status": "SKIPPED", "reason": "Not enough recent samples yet (need 200)."}

        X_recent = np.array([s[0] for s in window], dtype=np.float32)
        y_recent = np.array([s[1] for s in window], dtype=np.int32)
        if len(np.unique(y_recent)) < 2:
            return {"status": "SKIPPED", "reason": "Recent window has only one traffic class; retraining would be biased."}

        X_retrain = np.vstack([self.reference_X, X_recent]).astype(np.float32)
        y_retrain = np.concatenate([self.reference_y, y_recent]).astype(np.int32)

        old_model = copy.deepcopy(self.model)
        old_val_acc = float(old_model.model.score(self.val_X, self.val_y))

        retrain_result = self.model.retrain(X_retrain, y_retrain)
        new_val_acc = float(self.model.model.score(self.val_X, self.val_y))

        if new_val_acc < old_val_acc - 0.02:
            # Reject: keep the previous model and report the reason.
            self.model = old_model
            self.agent.execute_adaptation(new_baseline=old_val_acc)
            return {
                "status": "REJECTED",
                "reason": f"New model scored {new_val_acc:.1%} on clean validation data vs {old_val_acc:.1%} before; kept previous model.",
                "model_version": self.model.model_version,
                "new_accuracy": old_val_acc,
                "agent_baseline": old_val_acc,
                "samples_used": len(X_retrain),
            }

        agent_result = self.agent.execute_adaptation(new_baseline=new_val_acc)
        return {
            "status": "SUCCESS",
            "model_version": retrain_result["version"],
            "new_accuracy": new_val_acc,
            "agent_baseline": agent_result["new_baseline"],
            "samples_used": len(X_retrain),
        }

    def _record_incident(self, packet: dict, result: dict, threat_intel: dict, containment: Optional[dict]):
        """Deduplicate bursts into trackable SOC incidents"""
        src_ip = packet.get("src_ip", "Unknown")
        attack_type = result["attack_type"]
        key = f"{src_ip}:{attack_type}"

        now_str = datetime.now().isoformat()

        if key in self.incidents:
            inc = self.incidents[key]
            inc["packet_count"] += 1
            inc["last_seen"] = now_str
            inc["peak_confidence"] = max(inc["peak_confidence"], result["confidence"])
            if containment:
                inc["contained"] = True
        else:
            self.incident_counter += 1
            inc = {
                "incident_id": f"INC-{self.incident_counter:04d}",
                "src_ip": src_ip,
                "dst_ip": packet.get("dst_ip", "10.0.0.80"),
                "attack_type": attack_type,
                "technique_id": threat_intel["technique_id"],
                "severity": threat_intel["severity"],
                "first_seen": now_str,
                "last_seen": now_str,
                "packet_count": 1,
                "peak_confidence": result["confidence"],
                "contained": containment is not None or src_ip in self.defense_mgr.blocked_ips,
                "mitigation": threat_intel["recommended_action"],
            }
            self.incidents[key] = inc

            # Also push deduplicated alert to list
            self._create_alert(
                alert_type="THREAT_INCIDENT",
                severity=threat_intel["severity"],
                message=f"{attack_type} detected from {src_ip} ({threat_intel['technique_id']})",
                details={
                    "incident_id": inc["incident_id"],
                    "confidence": round(result["confidence"], 4),
                    "anomaly_score": result["anomaly_score"],
                    "tactic": threat_intel["tactic"],
                },
                src_ip=src_ip,
                attack_type=attack_type,
            )

    def _create_alert(self, alert_type, severity, message, details, src_ip="", attack_type=""):
        """Create a structured alert for SOC analyst queue"""
        alert = {
            "id": f"ALT-{len(self.alerts) + 1:05d}",
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "severity": severity,
            "message": message,
            "src_ip": src_ip,
            "attack_type": attack_type,
            "details": details,
        }
        self.alerts.append(alert)
        return alert

    def run_realtime_detection(self, max_packets=1000, display_interval=50):
        """
        Run synchronous real-time intrusion detection loop (CLI mode).
        """
        print("\n" + "=" * 60)
        print("🚀 STARTING REAL-TIME DETECTION ENGINE")
        print("=" * 60)

        self.is_running = True
        self.start_time = time.time()
        packet_count = 0

        for packet in self.data_stream.stream():
            if packet_count >= max_packets:
                break

            result = self.process_packet(packet)
            packet_count += 1

            if packet_count % display_interval == 0:
                self._display_status()

            if result["agent_decision"]["action"] == "ADAPT":
                print(f"\n⚡ ADAPTATION EVENT at packet {packet_count}")
                print(f"   Reason: {result['agent_decision']['reason']}")
                if result["adaptation"]:
                    print(f"   Model Version: {result['adaptation'].get('model_version', 'N/A')}")
                    print(f"   Accuracy: {result['adaptation'].get('new_accuracy', 0):.2%}")

        self.is_running = False
        self._display_final_summary()

    def _display_status(self):
        """Display current CLI telemetry"""
        elapsed = time.time() - self.start_time if self.start_time else 0.001
        rate = self.packets_processed / elapsed
        acc = (self.true_positives + self.true_negatives) / max(self.packets_processed, 1)

        health = self.agent.analyze_system_health()

        print(f"\n{'─' * 60}")
        print(f"📊 SYSTEM TELEMETRY - Packet #{self.packets_processed}")
        print(f"{'─' * 60}")
        print(f"⏱️  Rate: {rate:.1f} pkts/sec | Latency: {np.mean(self.recent_latencies) if self.recent_latencies else 0:.1f}ms")
        print(f"📈 Accuracy: {acc:.2%} | Normal: {self.normal_traffic} | Attacks: {self.attacks_detected}")
        print(f"🤖 Agent Health: {health['status']} | OODA: {self.agent.ooda_phase}")
        print(f"   Confidence: {health['current_confidence']:.2%} (Baseline: {health['baseline_confidence']:.2%})")
        print(f"   Adaptations: {self.agent.total_adaptations} | Blocked IPs: {len(self.defense_mgr.blocked_ips)}")
        print(f"{'─' * 60}")

    def _display_final_summary(self):
        """Display final run summary"""
        elapsed = time.time() - self.start_time if self.start_time else 0.001
        acc = (self.true_positives + self.true_negatives) / max(self.packets_processed, 1)
        prec = self.true_positives / max(self.true_positives + self.false_positives, 1)
        rec = self.true_positives / max(self.true_positives + self.false_negatives, 1)
        f1 = (2 * prec * rec) / max(prec + rec, 1e-6)

        print("\n" + "=" * 60)
        print("📋 FINAL FORENSIC SUMMARY")
        print("=" * 60)
        print(f"⏱️  Runtime: {elapsed:.2f}s | Packets: {self.packets_processed}")
        print(f"📊 Accuracy: {acc:.2%} | Precision: {prec:.2%} | Recall: {rec:.2%} | F1: {f1:.2%}")
        print(f"🎯 Attacking IPs Blocked: {len(self.defense_mgr.blocked_ips)}")
        print(f"🤖 Autonomous Adaptations: {self.agent.total_adaptations}")
        print("=" * 60)

    def get_system_report(self) -> dict:
        """
        Generate complete system telemetry report for frontend and APIs.
        """
        elapsed = time.time() - self.start_time if self.start_time else 0
        acc = (self.true_positives + self.true_negatives) / max(self.packets_processed, 1)
        prec = self.true_positives / max(self.true_positives + self.false_positives, 1)
        rec = self.true_positives / max(self.true_positives + self.false_negatives, 1)
        f1 = (2 * prec * rec) / max(prec + rec, 1e-6)
        far = self.false_positives / max(self.false_positives + self.true_negatives, 1)

        avg_latency = float(np.mean(self.recent_latencies)) if self.recent_latencies else 1.2

        return {
            "system_info": {
                "name": "AegisAgent Autonomous IDS",
                "is_running": self.is_running,
                "is_paused": self.is_paused,
                "packets_processed": self.packets_processed,
                "runtime_seconds": round(elapsed, 2),
                "throughput_pps": round(self.packets_processed / max(elapsed, 1), 1),
                "avg_latency_ms": round(avg_latency, 2),
            },
            "detection_metrics": {
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "false_alarm_rate": round(far, 4),
                "attacks_detected": self.attacks_detected,
                "normal_traffic": self.normal_traffic,
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "false_negatives": self.false_negatives,
            },
            "attack_taxonomy": dict(self.attack_distribution),
            "agent_status": self.agent.get_status_summary(),
            "model_version": self.model.model_version,
            "training_history": self.model.training_history,
            "active_incidents": list(self.incidents.values())[-20:],
            "blocked_ips": self.defense_mgr.get_blocked_list(),
            "recent_alerts": list(self.alerts)[-20:],
            "telemetry_points": list(self.telemetry_history),
        }

    def export_forensic_incident_report(self) -> dict:
        """Generate structured forensic report suitable for export"""
        report = self.get_system_report()
        report["generated_at"] = datetime.now().isoformat()
        report["classification_standard"] = "MITRE ATT&CK Enterprise Matrix v14"
        report["audit_trail"] = self.agent.decision_log
        return report
