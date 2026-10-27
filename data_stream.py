"""
Data Stream Simulator for Intrusion Detection System
===================================================
Streams network traffic packet-by-packet with realistic network metadata
(IPs, ports, protocols, services), attack scenario injection, and concept drift simulation.
"""

import os
import time
import random
from collections import deque
import numpy as np
import pandas as pd



# Pool of realistic IP addresses
BENIGN_IPS = [
    "192.168.1.104", "192.168.1.115", "192.168.1.142", "192.168.1.178",
    "10.0.0.45", "10.0.0.88", "10.0.1.12", "172.16.0.24", "192.168.2.55",
]

ATTACKER_IPS = [
    "198.51.100.42", "203.0.113.89", "185.220.101.5", "45.33.32.156",
    "91.240.118.172", "194.26.29.112", "103.251.167.20", "77.88.55.66",
]

SERVER_TARGETS = [
    {"ip": "10.0.0.80", "port": 80, "service": "http", "proto": "TCP"},
    {"ip": "10.0.0.143", "port": 443, "service": "https", "proto": "TCP"},
    {"ip": "10.0.0.22", "port": 22, "service": "ssh", "proto": "TCP"},
    {"ip": "10.0.0.53", "port": 53, "service": "dns", "proto": "UDP"},
    {"ip": "10.0.0.25", "port": 25, "service": "smtp", "proto": "TCP"},
    {"ip": "10.0.0.21", "port": 21, "service": "ftp", "proto": "TCP"},
]


class DataStreamSimulator:
    """
    Streams network traffic data packet-by-packet.
    Enhanced with realistic SOC network telemetry and live attack scenario injection.
    """

    def __init__(self, data_path=None, stream_delay=0.01):
        self.data_path = data_path
        self.stream_delay = stream_delay
        self.current_index = 0
        self.injected_packets = deque()

        print("   Loading dataset... synthetic data.")
        self._generate_synthetic()

    def stream(self):
        """
        Generator — yields one enriched packet dict at a time.
        """
        n = len(self.features)
        while self.current_index < n or len(self.injected_packets) > 0:
            # Prioritize interactive injections if present
            if len(self.injected_packets) > 0:
                packet = self.injected_packets.popleft()
                yield packet
                if self.stream_delay > 0:
                    time.sleep(self.stream_delay)
                continue

            idx = self.current_index
            features = self.features[idx]
            label = int(self.labels[idx])
            raw_label = self.raw_labels[idx] if self.raw_labels is not None else ""

            packet = self._enrich_packet(idx, features, label, raw_label)
            self.current_index += 1

            yield packet

            if self.stream_delay > 0:
                time.sleep(self.stream_delay)

    def reset(self):
        """Reset stream to the beginning."""
        self.current_index = 0
        self.injected_packets.clear()

    def get_dataset_info(self):
        """Return metadata about the loaded dataset."""
        attack_count = int(np.sum(self.labels == 1))
        normal_count = int(np.sum(self.labels == 0))
        return {
            "total_samples": len(self.features),
            "n_features": self.features.shape[1],
            "feature_names": self.feature_names,
            "attack_count": attack_count,
            "normal_count": normal_count,
            "attack_ratio": round(attack_count / max(len(self.labels), 1), 4),
            "source": self.source,
            "current_index": self.current_index,
        }

    # ─────────────────────────────────────────
    # INTERACTIVE INJECTION PLAYGROUND (FOR HACKATHON DEMOS)
    # ─────────────────────────────────────────

    def inject_attack_burst(self, attack_type="DoS / SYN Flood", count=30):
        """
        Inject an immediate burst of specific attacks for live demonstration.
        """
        rng = np.random.default_rng()
        n_features = self.features.shape[1]

        attacker_ip = random.choice(ATTACKER_IPS)

        for i in range(count):
            pkt_id = self.current_index + len(self.injected_packets) + 100000 + i

            if "DoS" in attack_type or "SYN" in attack_type:
                feat = rng.normal(0.5, 0.3, n_features).astype(np.float32)
                feat[0] += 2.0   # duration
                feat[4] += 1.0   # src_bytes
                feat[22] += 4.5  # count spike
                feat[24] = 1.0   # serror_rate
                target = SERVER_TARGETS[0]  # port 80
                protocol = "TCP"

            elif "Port Scan" in attack_type or "Probe" in attack_type:
                feat = rng.normal(-0.2, 0.4, n_features).astype(np.float32)
                feat[22] += 3.5  # count
                feat[29] += 4.0  # diff_srv_rate
                target = random.choice(SERVER_TARGETS)
                protocol = "TCP"

            elif "Brute Force" in attack_type or "R2L" in attack_type:
                feat = rng.normal(0.8, 0.4, n_features).astype(np.float32)
                feat[10] += 5.0  # num_failed_logins
                feat[0] += 3.5   # duration
                target = SERVER_TARGETS[2]  # port 22 SSH
                protocol = "TCP"

            elif "Exfiltration" in attack_type:
                feat = rng.normal(0.2, 0.3, n_features).astype(np.float32)
                feat[4] += 6.0   # huge src_bytes
                target = {"ip": "198.51.100.99", "port": 443, "service": "https", "proto": "TCP"}
                protocol = "TCP"

            else:
                feat = rng.normal(1.5, 0.5, n_features).astype(np.float32)
                target = random.choice(SERVER_TARGETS)
                protocol = "TCP"

            packet = {
                "packet_id": pkt_id,
                "features": feat,
                "label": 1,
                "raw_label": attack_type,
                "src_ip": attacker_ip,
                "dst_ip": target["ip"],
                "port": target["port"],
                "protocol": protocol,
                "service": target["service"],
                "attack_type": attack_type,
                "injected": True,
            }
            self.injected_packets.append(packet)

        print(f"   ⚡ INJECTED {count} packets of type '{attack_type}' from {attacker_ip}")
        return {"status": "INJECTED", "type": attack_type, "count": count, "attacker_ip": attacker_ip}

    def inject_concept_drift(self, count=40):
        """
        Inject concept drift packets into the stream to trigger autonomous retraining.
        """
        rng = np.random.default_rng()
        n_features = self.features.shape[1]

        for i in range(count):
            pkt_id = self.current_index + len(self.injected_packets) + 200000 + i
            # Overlapping drifted distribution
            label = 1 if i % 2 == 0 else 0
            feat = rng.normal(1.1, 1.3, n_features).astype(np.float32)

            src = random.choice(ATTACKER_IPS) if label == 1 else random.choice(BENIGN_IPS)
            target = random.choice(SERVER_TARGETS)

            packet = {
                "packet_id": pkt_id,
                "features": feat,
                "label": label,
                "raw_label": "concept_drift_anomaly",
                "src_ip": src,
                "dst_ip": target["ip"],
                "port": target["port"],
                "protocol": target["proto"],
                "service": target["service"],
                "attack_type": "Zero-Day / Concept Drift" if label == 1 else "BENIGN / NORMAL",
                "injected": True,
            }
            self.injected_packets.append(packet)

        print(f"   🌪️ INJECTED {count} concept drift packets to trigger agent adaptation.")
        return {"status": "DRIFT_INJECTED", "count": count}

    # ─────────────────────────────────────────
    # INTERNAL HELPERS
    # ─────────────────────────────────────────

    def _enrich_packet(self, idx, features, label, raw_label):
        """Enrich raw vector with realistic network fields"""
        target = SERVER_TARGETS[idx % len(SERVER_TARGETS)]

        if label == 1:
            src_ip = ATTACKER_IPS[idx % len(ATTACKER_IPS)]
            attack_type = raw_label if raw_label else "Attack"
            if not raw_label or raw_label == "Attack":
                if idx % 4 == 0:
                    attack_type = "DoS / SYN Flood"
                elif idx % 4 == 1:
                    attack_type = "Probe / Stealth Port Scan"
                elif idx % 4 == 2:
                    attack_type = "R2L / SSH Brute Force"
                else:
                    attack_type = "Data Exfiltration / C2"
        else:
            src_ip = BENIGN_IPS[idx % len(BENIGN_IPS)]
            attack_type = "BENIGN / NORMAL"

        return {
            "packet_id": idx,
            "features": features,
            "label": label,
            "raw_label": raw_label,
            "src_ip": src_ip,
            "dst_ip": target["ip"],
            "port": target["port"],
            "protocol": target["proto"],
            "service": target["service"],
            "attack_type": attack_type,
            "injected": False,
        }

    def _generate_synthetic(self, n_samples=5000, n_features=39, seed=42):
        """
        Generate synthetic network traffic with programmed concept drift.
        """
        rng = np.random.default_rng(seed)

        # Phase 1 (0-70%): clean, easy-to-classify traffic
        n_phase1 = int(n_samples * 0.70)
        n1_attack = int(n_phase1 * 0.35)
        n1_normal = n_phase1 - n1_attack

        X1_normal = rng.normal(0.0, 0.4, (n1_normal, n_features)).astype(np.float32)
        X1_attack = rng.normal(2.0, 0.4, (n1_attack, n_features)).astype(np.float32)
        X1_attack[:, 0] += 3.0   # duration spike
        X1_attack[:, 4] += 4.0   # src_bytes spike
        X1_attack[:, 22] += 3.0  # count spike

        X1 = np.vstack([X1_normal, X1_attack])
        y1 = np.array([0] * n1_normal + [1] * n1_attack, dtype=np.int32)

        p1 = rng.permutation(n_phase1)
        X1, y1 = X1[p1], y1[p1]

        # Phase 2 (70-100%): concept drift
        n_phase2 = n_samples - n_phase1
        n2_attack = int(n_phase2 * 0.35)
        n2_normal = n_phase2 - n2_attack

        X2_normal = rng.normal(1.0, 1.1, (n2_normal, n_features)).astype(np.float32)
        X2_attack = rng.normal(1.2, 1.1, (n2_attack, n_features)).astype(np.float32)
        X2_attack[:, 0] += rng.normal(1.0, 1.5, n2_attack)
        X2_attack[:, 4] += rng.normal(1.0, 1.5, n2_attack)
        X2_attack[:, 22] += rng.normal(1.0, 1.5, n2_attack)

        X2 = np.vstack([X2_normal, X2_attack])
        y2 = np.array([0] * n2_normal + [1] * n2_attack, dtype=np.int32)

        p2 = rng.permutation(n_phase2)
        X2, y2 = X2[p2], y2[p2]

        self.features = np.vstack([X1, X2])
        self.labels = np.concatenate([y1, y2])
        self.raw_labels = None
        self.feature_names = [f"feature_{i:02d}" for i in range(n_features)]
        self.source = "synthetic"

        print(f"\n   ℹ Synthetic stream: {n_phase1} baseline packets + "
              f"{n_phase2} drifted packets (drift at packet ~{n_phase1}).")
