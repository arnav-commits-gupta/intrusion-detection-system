# 🛡️ AegisAgent: Autonomous Cyber Defense Platform (Agentic IDS)

> **Next-Generation Self-Adaptive Intrusion Detection System powered by Agentic AI, Autonomous Drift Recovery, and MITRE ATT&CK Active Defense.**  
> *Inspired by the research paper "Agentic Intelligence for Unified Cyber Defense" (AISAF Framework).*

---

## 🌟 Key Highlights & Hackathon Features

| Feature | Description |
| :--- | :--- |
| **🤖 Autonomous Agentic OODA Loop** | Continuous **Observe ➔ Orient ➔ Decide ➔ Act** cognitive cycle monitoring prediction confidence and anomalies. |
| **🌪️ Self-Healing Concept Drift Recovery** | Detects statistical distribution shifts in real-time and executes zero-touch model retraining and baseline recalibration without human intervention. |
| **🖥️ Modern Cyber SOC Dashboard** | High-performance dark cyberpunk Security Operations Center dashboard with glassmorphism, glowing telemetry, and real-time WebSockets. |
| **💥 Adversary Threat Injection Playground** | 1-click simulation for **DDoS SYN Flood**, **Stealth Port Scan**, **SSH Brute Force**, **Data Exfiltration**, and **Zero-Day Concept Drift**. |
| **🎯 MITRE ATT&CK Integration** | Maps threats to tactics & techniques (e.g., T1498.001, T1046, T1110.001) with automated firewall rules (`iptables`). |
| **🔍 Deep AI Explainability (XAI)** | Plain-English reasoning explaining *why* an alert fired, with top contributing feature indicators, weights, and anomaly scores. |
| **⚡ 10x Performance Optimization** | Optimized low-latency inference path reducing single-packet latency to **<4.5ms** (~240+ pkts/sec). |
| **📥 Forensic Incident Export** | 1-click export of structured JSON forensic incident reports and audit trails for compliance. |

---

## 🏗️ Architecture

```
                                      ┌──────────────────────────────────────────────┐
                                      │             Network Telemetry Stream         │
                                      │   (TCP, UDP, ICMP, Synthetic)      │
                                      └───────────────────────┬──────────────────────┘
                                                              │
                                                              ▼
                                      ┌──────────────────────────────────────────────┐
                                      │        Intrusion Detection Model (RF)        │
                                      │   - Low-latency inference (<4.5ms)           │
                                      │   - Per-class probabilities                  │
                                      │   - Z-score Anomaly Deviation Score          │
                                      └───────────────────────┬──────────────────────┘
                                                              │
                                                              ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       AUTONOMOUS AGENTIC CONTROLLER (OODA)                                       │
│                                                                                                                  │
│    [1. OBSERVE] ───────────────► [2. ORIENT] ───────────────► [3. DECIDE] ───────────────► [4. ACT]             │
│    Sensory stream ingestion      Statistical drift check      Threshold evaluation         Autonomous Retraining │
│    Confidence & Anomaly scores   CUSUM & variance analysis    Adapt vs Monitor             Baseline Recalibrate  │
└─────────────────────────────────────────────┬────────────────────────────────────────────────────────────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
┌──────────────────────────────────────────┐    ┌──────────────────────────────────────────┐
│   MITRE ATT&CK Active Defense Engine     │    │       Real-Time Cyber SOC Dashboard      │
│   - Tactic & Technique classification    │    │   - WebSockets live packet feed          │
│   - Automated IP Quarantine (iptables)   │    │   - Canvas Confidence & Drift chart      │
│   - Threat deduplication & incident mgmt │    │   - Threat Injection Playground          │
└──────────────────────────────────────────┘    └──────────────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### 1. Requirements & Dependencies
- Python 3.8+
- Scikit-learn, NumPy, Pandas, FastAPI, Uvicorn, WebSockets

To install required packages:
```bash
pip install -r requirements.txt
# Or directly:
pip install numpy scikit-learn pandas fastapi uvicorn websockets pydantic requests
```

---

### 2. Launch the Web Cyber SOC Dashboard (Recommended for Demos)
Run the server:
```bash
python3 server.py
# Or via demo launcher:
python3 demo.py --web
```
Now open your browser at:
👉 **[http://localhost:8000](http://localhost:8000)**

#### In the Web Dashboard:
1. Click **START STREAM** to see packets flowing in real-time at ~15-20 pkts/sec.
2. In the **Threat Injection Playground**, click **DDoS SYN Flood** or **Stealth Port Scan** to inject hostile bursts.
3. Watch the **Quarantined IPs** list update automatically via Active Defense.
4. Click **Trigger Concept Drift** and observe the **Agentic AI Reasoning Stream** terminal detect drift and retrain to `Model v2.0` automatically!
5. Click **INSPECT** on any packet to view the Deep AI Forensic inspection drawer with MITRE ATT&CK recommendations.
6. Click **EXPORT FORENSICS** to download the complete audit trail.

---

### 3. Run the CLI Automated Demonstration
Run non-interactive automated detection:
```bash
python3 demo.py --auto --packets 300
```

Run prediction explainability sample:
```bash
python3 demo.py --xai
```

---

### 4. Run the Automated Test Suite
Run the 5-module validation test suite:
```bash
python3 test_system.py
```
Validates:
- ✅ Prediction Model latency & accuracy
- ✅ Data Stream Simulator & scenario injections
- ✅ Autonomous Agentic Controller OODA loop & drift recovery
- ✅ MITRE ATT&CK active defense & containment
- ✅ End-to-end integration & forensic report generation

---

## 📡 REST & WebSocket API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `WS /ws/stream` | `WEBSOCKET` | Real-time bidirectional telemetry, packet streaming, and command channel. |
| `GET /api/status` | `GET` | Overall system health, OODA phase, model version, and KPIs. |
| `GET /api/metrics` | `GET` | Confusion matrix, throughput (pps), average latency, and accuracy. |
| `GET /api/incidents` | `GET` | Deduplicated active incident records. |
| `GET /api/firewall` | `GET` | Active quarantined IP addresses and iptables containment rules. |
| `POST /api/stream/start` | `POST` | Starts real-time streaming worker. |
| `POST /api/stream/pause` | `POST` | Pauses real-time streaming worker. |
| `POST /api/attack/inject` | `POST` | Injects attack burst (`DoS / SYN Flood`, `Probe`, `Brute Force`, etc.). |
| `POST /api/drift/inject` | `POST` | Injects concept drift to demonstrate autonomous agent retraining. |
| `POST /api/agent/mode` | `POST` | Toggles Auto-Pilot (Autonomous Mode) vs Human-in-the-Loop. |
| `GET /api/export/forensic` | `GET` | Downloads complete incident forensic audit report (JSON). |

---

## 🏆 Best Features to Showcase to Hackathon Judges

1. **Autonomous Self-Healing Loop:** Click *"Trigger Concept Drift"* in the web UI. Show the judges the live terminal: the agent observes confidence degrading below threshold, cognitive phase shifts `OBSERVE ➔ ORIENT ➔ DECIDE ➔ ACT`, model retrains, and baseline confidence is restored live!
2. **Interactive Attack Playground:** Click *"DDoS SYN Flood"* and watch the system flag packets in red, categorize the threat under MITRE T1498.001, and automatically quarantine the attacking IP with a zero-delay active defense rule.
3. **Deep AI Explainability (XAI):** Click any packet in the stream table to open the forensic inspection drawer. Show that the AI doesn't just output an opaque score—it provides plain-English reasoning and explains exactly which feature indicators triggered the alert.
4. **Sub-5ms Real-Time Performance:** Show the KPI header: processing packets at 200+ packets/sec with latency < 4.5ms per packet.

---

## 📄 License
MIT License. Developed for Hackathon & Advanced Agentic Cyber Defense Research.

