"""
AegisAgent Cyber Defense Demo
=============================
Demonstration script for the Agentic Intrusion Detection System.
Supports both terminal interactive/automated modes and launching the Web SOC Dashboard.
"""

import sys
import os
import argparse
from datetime import datetime

from agentic_ids import AgenticIDS


def print_banner():
    """Print system banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║           🛡️  AEGISAGENT: AUTONOMOUS CYBER DEFENSE (IDS)         ║
║                                                                   ║
║        Self-Adaptive Intrusion Detection with Agentic AI          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

Inspired by: "Agentic Intelligence for Unified Cyber Defense"

Key Features:
✓ Real-time packet telemetry & network anomaly classification
✓ Autonomous drift detection with OODA cognitive loop
✓ Self-healing model adaptation & baseline recalibration
✓ MITRE ATT&CK framework mapping & active defense containment
✓ Explainable AI (XAI) feature factor breakdown
✓ Full Web Cyber SOC Dashboard with live WebSockets
"""
    print(banner)


def demonstrate_agentic_capabilities(max_packets=500, non_interactive=False):
    """
    Run a comprehensive demonstration of the Agentic IDS
    """
    print_banner()

    print("\n📦 Initializing Aegis-IDS Orchestrator...")
    ids = AgenticIDS(data_path=None, stream_delay=0.001)

    print("\n🎓 Fitting baseline model...")
    ids.train_initial_model()

    print("\n" + "=" * 70)
    print("🎬 LIVE DEMONSTRATION WORKFLOW")
    print("=" * 70)
    print("""
1. SENSORY INGESTION: Streaming network telemetry (TCP, UDP, ICMP)
2. PREDICTION & ANOMALY SCORING: Low-latency Random Forest + Z-score distance
3. COGNITIVE AGENT LOOP: Real-time OODA loop (Observe -> Orient -> Decide -> Act)
4. CONCEPT DRIFT RECOVERY: Autonomous retraining triggered upon statistical shift
5. ACTIVE DEFENSE: Offending IPs quarantined via simulated iptables
6. EXPLAINABILITY: Human-readable reasoning and MITRE ATT&CK mapping
""")

    if not non_interactive:
        try:
            input("Press ENTER to start real-time detection... ")
        except (EOFError, KeyboardInterrupt):
            pass

    # Inject concept drift halfway to demonstrate autonomous adaptation
    print(f"\n🚀 Running real-time detection for {max_packets} packets...")
    if max_packets >= 200:
        # Schedule a concept drift burst at packet ~100
        print("   (Programmed concept drift will be introduced to demonstrate autonomous adaptation)")
        ids.data_stream.inject_concept_drift(count=40)

    ids.run_realtime_detection(max_packets=max_packets, display_interval=50)

    # Detailed Forensic Summary
    print("\n" + "=" * 70)
    print("📊 GENERATING DETAILED FORENSIC AUDIT REPORT")
    print("=" * 70)

    report = ids.get_system_report()
    agent_status = report["agent_status"]

    print(f"\n🎯 AGENTIC BEHAVIOR SUMMARY:")
    print(f"   Agent State:        {agent_status['agent_status']}")
    print(f"   System Health:      {agent_status['system_health']}")
    print(f"   Autonomous Adaptations: {agent_status['total_adaptations']}")
    print(f"   Quarantined IPs:    {len(ids.defense_mgr.blocked_ips)}")
    print(f"   Final Accuracy:     {report['detection_metrics']['accuracy']:.2%}")
    print(f"   F1-Score:           {report['detection_metrics']['f1_score']:.2%}")

    if agent_status["total_adaptations"] > 0:
        print("\n   ✅ AUTONOMOUS AGENT ACTIONS OBSERVED:")
        print("      • Detected performance degradation exceeding sensitivity threshold")
        print("      • Made autonomous decision to adapt WITHOUT human operator intervention")
        print("      • Triggered model retraining and recalibrated operational baseline")
        print("      • Maintained uninterrupted intrusion detection")
    else:
        print("\n   ℹ️  System operated within nominal baseline thresholds.")

    print("\n" + "=" * 70)
    print("✅ DEMONSTRATION COMPLETE")
    print("=" * 70)
    return report


def show_example_prediction():
    """
    Show a detailed example of how predictions work with explanations
    """
    print("\n" + "=" * 70)
    print("🔍 EXAMPLE: DETAILED PREDICTION WITH XAI EXPLANATIONS")
    print("=" * 70)

    ids = AgenticIDS(stream_delay=0)
    ids.train_initial_model()

    packet_iter = ids.data_stream.stream()
    print("\nProcessing 3 example packets with full explainability forensics...\n")

    for i in range(3):
        packet = next(packet_iter)
        result = ids.process_packet(packet)
        pred = result["prediction"]

        print(f"{'─' * 70}")
        print(f"Packet #{i+1} | Source: {result['src_ip']} ➔ Target: {result['dst_ip']}:{result['port']}")
        print(f"{'─' * 70}")
        print(f"Classification: {pred['label']} ({pred['attack_type']})")
        print(f"Confidence:     {pred['confidence']:.2%} | Anomaly Score: {pred['anomaly_score']:.2%}")
        print(f"Latency:        {result['latency_ms']:.2f}ms")

        expl = pred.get("explanation", {})
        if expl:
            print(f"AI Reasoning:   {expl.get('reasoning', 'N/A')}")
            top_feats = expl.get("top_contributing_features", {})
            if top_feats:
                print("Key Indicators:")
                for k, v in list(top_feats.items())[:3]:
                    print(f"  • {k}: val={v.get('value')}, importance={v.get('importance', 0):.2%}, {v.get('description')}")

        if result.get("threat_intel"):
            ti = result["threat_intel"]
            print(f"MITRE ATT&CK:   {ti['technique_id']} ({ti['technique_name']}) - Severity: {ti['severity']}")
            print(f"Action:         {ti['recommended_action']}")

        print()

    print("=" * 70)


def start_web_dashboard():
    """Launch the Web Cyber SOC Dashboard"""
    import uvicorn
    print("\n" + "=" * 70)
    print("🚀 LAUNCHING AEGISAGENT CYBER SOC DASHBOARD")
    print("=" * 70)
    print("Open your browser at: http://localhost:8000")
    print("Press Ctrl+C to exit.")
    print("=" * 70 + "\n")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)


def main():
    parser = argparse.ArgumentParser(description="AegisAgent Cyber Defense System")
    parser.add_argument("--web", action="store_true", help="Launch the Web Cyber SOC Dashboard on port 8000")
    parser.add_argument("--auto", action="store_true", help="Run automated demonstration without interactive prompts")
    parser.add_argument("--packets", type=int, default=300, help="Number of packets for demonstration (default: 300)")
    parser.add_argument("--xai", action="store_true", help="Show example predictions with XAI explainability")

    args = parser.parse_args()

    if args.web:
        start_web_dashboard()
        return

    if args.xai:
        show_example_prediction()
        return

    if args.auto:
        demonstrate_agentic_capabilities(max_packets=args.packets, non_interactive=True)
        return

    # If running interactively
    if sys.stdin.isatty():
        print_banner()
        print("\nMAIN MENU:")
        print("  1. Run Full Agentic Cyber Defense Demonstration (CLI)")
        print("  2. Launch Web Cyber SOC Dashboard (http://localhost:8000)")
        print("  3. View Detailed Predictions & XAI Explainability")
        print("  4. Quick Automated Verification")
        try:
            choice = input("\nSelect option (1-4, default: 1): ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "1"

        if choice == "2":
            start_web_dashboard()
        elif choice == "3":
            show_example_prediction()
        elif choice == "4":
            demonstrate_agentic_capabilities(max_packets=150, non_interactive=True)
        else:
            demonstrate_agentic_capabilities(max_packets=args.packets, non_interactive=False)
    else:
        # Non-interactive fallback
        demonstrate_agentic_capabilities(max_packets=args.packets, non_interactive=True)


if __name__ == "__main__":
    main()
