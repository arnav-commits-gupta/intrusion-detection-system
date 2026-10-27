"""
Agentic AI Controller for Intrusion Detection System
====================================================
This module implements the autonomous agent that monitors system performance,
detects drift, and triggers adaptive actions without human intervention.

Inspired by: "Agentic Intelligence for Unified Cyber Defense"
Incorporating the Observe-Orient-Decide-Act (OODA) autonomous loop.
"""

import numpy as np
from collections import deque
from datetime import datetime
import logging


class AgenticController:
    """
    Autonomous Agent for Self-Adaptive Cyber Defense

    Responsibilities:
    1. Continuous Sensory Observation: Monitor prediction confidence & anomaly trends
    2. Orientation & Cognitive Drift Detection: Detect concept drift, performance drops, high variance
    3. Autonomous Decision Making: Decide when to adapt, retrain, or alert (OODA loop)
    4. Autonomous Execution: Trigger model retraining and baseline recalibration
    5. Explainable Reasoning: Provide human-auditable logs and natural language rationales
    """

    def __init__(
        self,
        confidence_threshold=0.70,
        drift_window_size=100,
        drift_sensitivity=0.15,
        autonomous_mode=True,
        adapt_cooldown=300,
    ):
        """
        Initialize the Agentic Controller.

        Args:
            confidence_threshold: Minimum acceptable prediction confidence (default: 0.70)
            drift_window_size: Number of recent predictions to monitor in sliding buffer
            drift_sensitivity: Threshold for detecting confidence degradation against baseline
            autonomous_mode: If True, executes adaptations autonomously; if False, requires operator approval
        """
        # Configuration
        self.confidence_threshold = confidence_threshold
        self.drift_window_size = drift_window_size
        self.drift_sensitivity = drift_sensitivity
        self.autonomous_mode = autonomous_mode
        self.adapt_cooldown = adapt_cooldown  # min packets between two retrains
        self.packets_since_adapt = adapt_cooldown  # no cooldown before the first retrain
        self._drift_logged = False  # log each drift episode once, not per packet

        # Monitoring buffers
        self.confidence_buffer = deque(maxlen=drift_window_size)
        self.prediction_buffer = deque(maxlen=drift_window_size)
        self.anomaly_buffer = deque(maxlen=drift_window_size)

        # State tracking
        self.baseline_confidence = None
        self.drift_detected = False
        self.total_adaptations = 0
        self.consecutive_low_confidence = 0
        self.ooda_phase = "OBSERVE"  # OBSERVE, ORIENT, DECIDE, ACT

        # Agent memory & audit trails
        self.decision_log = []
        self.thought_stream = deque(maxlen=50)

        # Setup logging
        self._setup_logging()
        self._add_thought("SYSTEM_INIT", "Agentic cyber defense controller initialized and standing by.")

    def _setup_logging(self):
        """Configure structured logging for agent decisions"""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - AGENT - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger("AgenticController")

    def _add_thought(self, phase, message):
        """Record an internal agent thought for live audit feed"""
        thought = {
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "message": message,
        }
        self.thought_stream.append(thought)
        return thought

    def observe(self, prediction, confidence, features=None, anomaly_score=0.0):
        """
        Sensory Observation: Ingest real-time packet classification diagnostics.
        """
        self.ooda_phase = "OBSERVE"
        self.packets_since_adapt += 1
        self.confidence_buffer.append(float(confidence))
        self.prediction_buffer.append(int(prediction))
        self.anomaly_buffer.append(float(anomaly_score))

        # Establish initial baseline from first 50 observations
        if self.baseline_confidence is None and len(self.confidence_buffer) >= 50:
            self.baseline_confidence = float(np.mean(list(self.confidence_buffer)))
            self.logger.info(f"Baseline confidence established: {self.baseline_confidence:.3f}")
            self._add_thought(
                "OBSERVE",
                f"Established operational baseline confidence at {self.baseline_confidence:.1%}.",
            )

    def analyze_system_health(self):
        """
        Cognitive Orientation: Analyze trends in prediction confidence and identify drift.
        """
        self.ooda_phase = "ORIENT"

        if len(self.confidence_buffer) < 20:
            return {
                "status": "INITIALIZING",
                "drift_detected": False,
                "drift_reason": None,
                "current_confidence": float(np.mean(list(self.confidence_buffer))) if self.confidence_buffer else 0.0,
                "baseline_confidence": self.baseline_confidence or 0.0,
                "confidence_drop": 0.0,
                "confidence_std": 0.0,
                "consecutive_low": 0,
                "anomaly_avg": 0.0,
            }

        recent_window = list(self.confidence_buffer)[-20:]
        current_confidence = float(np.mean(recent_window))
        confidence_std = float(np.std(list(self.confidence_buffer)))
        anomaly_avg = float(np.mean(list(self.anomaly_buffer)[-20:])) if self.anomaly_buffer else 0.0

        drift_detected = False
        drift_reason = None

        if self.baseline_confidence is not None:
            confidence_drop = float(self.baseline_confidence - current_confidence)

            # Criterion 1: Statistical drop exceeding sensitivity threshold
            if confidence_drop > self.drift_sensitivity:
                drift_detected = True
                drift_reason = f"Confidence degradation of {confidence_drop:.1%} detected (Current: {current_confidence:.1%}, Baseline: {self.baseline_confidence:.1%})"

            # Criterion 2: Sustained low confidence below threshold
            elif current_confidence < self.confidence_threshold:
                self.consecutive_low_confidence += 1
                if self.consecutive_low_confidence >= 4:
                    drift_detected = True
                    drift_reason = f"Sustained low confidence ({current_confidence:.1%}) over {self.consecutive_low_confidence} consecutive cycles"
            else:
                self.consecutive_low_confidence = 0

            # Criterion 3: High variance / prediction instability
            if not drift_detected and confidence_std > 0.28:
                drift_detected = True
                drift_reason = f"High prediction variance detected (σ={confidence_std:.3f}), indicating distribution shift"

        else:
            confidence_drop = 0.0

        self.drift_detected = drift_detected

        if drift_detected:
            self._add_thought("ORIENT", f"ALERT: Behavioral drift detected. {drift_reason}")

        return {
            "status": "DRIFT_DETECTED" if drift_detected else "STABLE",
            "drift_detected": drift_detected,
            "drift_reason": drift_reason,
            "current_confidence": current_confidence,
            "baseline_confidence": self.baseline_confidence or current_confidence,
            "confidence_drop": confidence_drop,
            "confidence_std": confidence_std,
            "consecutive_low": self.consecutive_low_confidence,
            "anomaly_avg": anomaly_avg,
        }

    def decide_action(self, health_assessment):
        """
        Autonomous Decision Making: Determine necessary adaptive actions.
        """
        self.ooda_phase = "DECIDE"

        if not health_assessment["drift_detected"]:
            self._drift_logged = False

        if health_assessment["drift_detected"] and self.packets_since_adapt < self.adapt_cooldown:
            return {
                "action": "COOLDOWN",
                "autonomous": self.autonomous_mode,
                "reason": f"Drift seen, but last retrain was {self.packets_since_adapt} packets ago (cooldown {self.adapt_cooldown}).",
                "timestamp": datetime.now().isoformat(),
            }

        if health_assessment["drift_detected"]:
            action = "ADAPT" if self.autonomous_mode else "ADAPT_RECOMMENDED"
            decision = {
                "action": action,
                "autonomous": self.autonomous_mode,
                "reason": health_assessment["drift_reason"],
                "timestamp": datetime.now().isoformat(),
                "confidence_metrics": {
                    "current": round(health_assessment["current_confidence"], 4),
                    "baseline": round(health_assessment["baseline_confidence"], 4),
                    "drop": round(health_assessment["confidence_drop"], 4),
                },
            }

            if not self._drift_logged:
                self._drift_logged = True
                self.decision_log.append(decision)
                self._add_thought(
                    "DECIDE",
                    f"DECISION: {'Autonomous trigger to retrain' if self.autonomous_mode else 'Operator approval required to retrain'} - {decision['reason']}",
                )
                self.logger.warning(f"🤖 AUTONOMOUS DECISION: {action} - {decision['reason']}")
            return decision

        else:
            return {
                "action": "MONITOR",
                "autonomous": self.autonomous_mode,
                "reason": "System operating within healthy parameters",
                "timestamp": datetime.now().isoformat(),
            }

    def execute_adaptation(self, new_baseline=None):
        """
        Adaptive Execution (OODA Phase: ACT):
        Execute retraining recalibration and reset drift triggers without baseline poisoning.
        """
        self.ooda_phase = "ACT"
        self.logger.info("⚡ EXECUTING ADAPTATION: Model retrained and recalibrating agent baseline...")

        self.total_adaptations += 1
        self.packets_since_adapt = 0

        # Fix baseline poisoning: calibrate to new retrained accuracy or healthy default
        if new_baseline is not None and new_baseline > 0.70:
            self.baseline_confidence = float(new_baseline)
        else:
            # Re-estimate baseline from upper quartile or reset to healthy level
            self.baseline_confidence = 0.95

        # Clear drift state and degraded counters
        self.drift_detected = False
        self.consecutive_low_confidence = 0
        
        # Flush buffer partially so old degraded packets don't re-trigger drift
        if len(self.confidence_buffer) > 10:
            # Retain only the calibrated baseline in buffer
            self.confidence_buffer.clear()
            for _ in range(20):
                self.confidence_buffer.append(self.baseline_confidence)

        self._add_thought(
            "ACT",
            f"ADAPTATION COMPLETE: Model v{self.total_adaptations + 1} deployed. Baseline reset to {self.baseline_confidence:.1%}.",
        )

        return {
            "status": "ADAPTED",
            "new_baseline": self.baseline_confidence,
            "adaptation_count": self.total_adaptations,
        }

    def set_autonomous_mode(self, enabled: bool):
        """Toggle between Autonomous Mode and Human-In-The-Loop Mode"""
        self.autonomous_mode = enabled
        mode_str = "AUTONOMOUS (Auto-Pilot)" if enabled else "HUMAN-IN-THE-LOOP (Manual Approval)"
        self._add_thought("MODE_CHANGE", f"Agent operational mode updated to {mode_str}.")
        return self.autonomous_mode

    def get_status_summary(self):
        """
        Get comprehensive agent status telemetry.
        """
        health = self.analyze_system_health()

        return {
            "agent_status": "ACTIVE",
            "autonomous_mode": self.autonomous_mode,
            "ooda_phase": self.ooda_phase,
            "system_health": health["status"],
            "drift_detected": health.get("drift_detected", False),
            "drift_reason": health.get("drift_reason", None),
            "total_adaptations": self.total_adaptations,
            "monitoring_window": len(self.confidence_buffer),
            "current_confidence": health["current_confidence"],
            "baseline_confidence": health["baseline_confidence"],
            "confidence_drop": health["confidence_drop"],
            "confidence_std": health["confidence_std"],
            "recent_decisions": len(self.decision_log),
            "recent_thoughts": list(self.thought_stream)[-10:],
        }

    def get_explanation(self, prediction, confidence, feature_importance=None):
        """
        Generate human-readable explanation for classification.
        """
        pred_label = "ATTACK" if prediction == 1 else "NORMAL"
        conf_level = "HIGH" if confidence > 0.8 else "MEDIUM" if confidence > 0.6 else "LOW"

        explanation = f"Classification: {pred_label} (Confidence: {conf_level} - {confidence:.2%})"

        if feature_importance:
            top_features = sorted(
                feature_importance.items(),
                key=lambda x: abs(x[1]) if isinstance(x[1], (int, float)) else 0,
                reverse=True,
            )[:3]
            explanation += "\nKey factors: " + ", ".join([f"{k}={v:.3f}" for k, v in top_features])

        return explanation
