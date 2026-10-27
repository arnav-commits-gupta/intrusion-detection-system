"""
FastAPI Server for AegisAgent Cyber Defense Platform
===================================================
Provides real-time WebSockets, REST APIs, threat injection playground,
and static frontend hosting for the Cyber SOC Dashboard.
"""

import os
import sys
import asyncio
import json
from datetime import datetime
from typing import Optional, List, Dict, Set
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agentic_ids import AgenticIDS
import os


# Base directory for static files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# System Instance
ids_system: Optional[AgenticIDS] = None
is_streaming = False
stream_delay_seconds = 0.08  # Default ~12-15 packets/second for smooth visualization
connected_websockets: Set[WebSocket] = set()
streaming_task: Optional[asyncio.Task] = None


class AttackInjectRequest(BaseModel):
    attack_type: str = "DoS / SYN Flood"
    count: int = 30


class SpeedRequest(BaseModel):
    delay: float = 0.08


class BlockIpRequest(BaseModel):
    ip: str
    reason: str = "Manual SOC Operator Quarantine"


class AgentModeRequest(BaseModel):
    autonomous: bool


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ids_system, streaming_task
    print("\n[AEGIS SERVER] Booting up AegisAgent Cyber Defense Backend...")
    ids_system = AgenticIDS(stream_delay=0, autonomous_mode=True)
    ids_system.train_initial_model()
    print("[AEGIS SERVER] Baseline model trained & calibrated. Ready for requests.")
    yield
    print("[AEGIS SERVER] Shutting down backend...")
    global is_streaming
    is_streaming = False
    if streaming_task and not streaming_task.done():
        streaming_task.cancel()


app = FastAPI(
    title="AegisAgent Autonomous Cyber Defense API",
    description="Real-time Agentic AI Intrusion Detection, Drift Adaptation & MITRE ATT&CK Defense",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware for development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────
# BACKGROUND STREAMING WORKER
# ─────────────────────────────────────────

async def broadcast_ws(payload: dict):
    """Broadcast JSON message to all connected clients"""
    if not connected_websockets:
        return
    text = json.dumps(payload)
    disconnected = set()
    for ws in connected_websockets:
        try:
            await ws.send_text(text)
        except Exception:
            disconnected.add(ws)
    for ws in disconnected:
        connected_websockets.discard(ws)


async def streaming_worker():
    """Background worker continuously pulling packets and broadcasting updates"""
    global is_streaming, ids_system, stream_delay_seconds
    print("[AEGIS STREAM] Real-time packet streaming worker started.")

    packet_gen = ids_system.data_stream.stream()

    while is_streaming:
        try:
            packet = next(packet_gen, None)
            if packet is None:
                # Loop stream
                ids_system.data_stream.reset()
                packet_gen = ids_system.data_stream.stream()
                packet = next(packet_gen, None)
                if packet is None:
                    await asyncio.sleep(0.5)
                    continue

            # Process through agentic IDS pipeline
            result = ids_system.process_packet(packet)

            # Build telemetry packet for frontend
            payload = {
                "type": "PACKET_EVENT",
                "packet": {
                    "packet_id": result["packet_id"],
                    "timestamp": result["timestamp"],
                    "src_ip": result["src_ip"],
                    "dst_ip": result["dst_ip"],
                    "port": result["port"],
                    "protocol": result["protocol"],
                    "service": result["service"],
                    "is_attack": result["prediction"]["prediction"] == 1,
                    "label": result["prediction"]["label"],
                    "attack_type": result["prediction"]["attack_type"],
                    "confidence": result["prediction"]["confidence"],
                    "anomaly_score": result["prediction"]["anomaly_score"],
                    "latency_ms": result["latency_ms"],
                    "explanation": result["prediction"]["explanation"],
                    "threat_intel": result["threat_intel"],
                    "containment": result["containment"],
                },
                "agent_status": {
                    "ooda_phase": ids_system.agent.ooda_phase,
                    "system_health": result["agent_health"]["status"],
                    "current_confidence": result["agent_health"]["current_confidence"],
                    "baseline_confidence": result["agent_health"]["baseline_confidence"],
                    "drift_detected": result["agent_health"]["drift_detected"],
                    "total_adaptations": ids_system.agent.total_adaptations,
                    "autonomous_mode": ids_system.agent.autonomous_mode,
                    "recent_thought": ids_system.agent.thought_stream[-1] if ids_system.agent.thought_stream else None,
                },
                "metrics": {
                    "packets_processed": ids_system.packets_processed,
                    "attacks_detected": ids_system.attacks_detected,
                    "normal_traffic": ids_system.normal_traffic,
                    "accuracy": (round((ids_system.true_positives + ids_system.true_negatives) / ids_system.packets_processed, 4) if ids_system.packets_processed else None),
                    "model_version": ids_system.model.model_version,
                    "blocked_ips_count": len(ids_system.defense_mgr.blocked_ips),
                    "data_source": ids_system.data_stream.source,
                    "train_rows": getattr(ids_system, "train_rows", None),
                },
            }

            if result.get("adaptation"):
                payload["adaptation_event"] = result["adaptation"]

            await broadcast_ws(payload)
            await asyncio.sleep(max(stream_delay_seconds, 0.005))

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[AEGIS STREAM ERROR] {e}")
            await asyncio.sleep(0.1)

    print("[AEGIS STREAM] Worker stopped.")


# ─────────────────────────────────────────
# WEBSOCKET ENDPOINT
# ─────────────────────────────────────────

@app.websocket("/ws/stream")
async def websocket_stream_endpoint(websocket: WebSocket):
    global is_streaming, streaming_task, ids_system, stream_delay_seconds
    await websocket.accept()
    connected_websockets.add(websocket)

    # Send initial full state
    try:
        init_payload = {
            "type": "INIT_STATE",
            "report": ids_system.get_system_report(),
            "is_streaming": is_streaming,
            "stream_delay": stream_delay_seconds,
        }
        await websocket.send_text(json.dumps(init_payload))
    except Exception:
        pass

    try:
        while True:
            data = await websocket.receive_text()
            cmd = json.loads(data)
            action = cmd.get("action")

            if action == "START":
                if not is_streaming:
                    is_streaming = True
                    streaming_task = asyncio.create_task(streaming_worker())
                await broadcast_ws({"type": "STATUS_CHANGE", "is_streaming": True})

            elif action == "PAUSE":
                is_streaming = False
                if streaming_task and not streaming_task.done():
                    streaming_task.cancel()
                await broadcast_ws({"type": "STATUS_CHANGE", "is_streaming": False})

            elif action == "RESET":
                ids_system.data_stream.reset()
                ids_system.packets_processed = 0
                ids_system.attacks_detected = 0
                ids_system.normal_traffic = 0
                ids_system.true_positives = 0
                ids_system.false_positives = 0
                ids_system.true_negatives = 0
                ids_system.false_negatives = 0
                ids_system.defense_mgr.blocked_ips.clear()
                ids_system.incidents.clear()
                ids_system.alerts.clear()
                await broadcast_ws({"type": "RESET_COMPLETE", "report": ids_system.get_system_report()})

            elif action == "SET_SPEED":
                stream_delay_seconds = float(cmd.get("delay", 0.08))
                await broadcast_ws({"type": "SPEED_CHANGED", "delay": stream_delay_seconds})

            elif action == "INJECT_ATTACK":
                att_type = cmd.get("attack_type", "DoS / SYN Flood")
                cnt = int(cmd.get("count", 30))
                inj = ids_system.data_stream.inject_attack_burst(att_type, cnt)
                # Auto-start if stopped so judge sees results
                if not is_streaming:
                    is_streaming = True
                    streaming_task = asyncio.create_task(streaming_worker())
                await broadcast_ws({"type": "INJECTION_CONFIRMED", "details": inj})

            elif action == "INJECT_DRIFT":
                cnt = int(cmd.get("count", 40))
                inj = ids_system.data_stream.inject_concept_drift(cnt)
                if not is_streaming:
                    is_streaming = True
                    streaming_task = asyncio.create_task(streaming_worker())
                await broadcast_ws({"type": "DRIFT_CONFIRMED", "details": inj})

            elif action == "TOGGLE_AUTONOMOUS":
                auto = bool(cmd.get("autonomous", True))
                ids_system.agent.set_autonomous_mode(auto)
                await broadcast_ws({"type": "MODE_CHANGED", "autonomous": auto})

            elif action == "UNBLOCK_IP":
                ip = cmd.get("ip")
                res = ids_system.defense_mgr.unblock_ip(ip)
                await broadcast_ws({"type": "IP_UNBLOCKED", "ip": ip, "details": res})

            elif action == "BLOCK_IP":
                ip = cmd.get("ip")
                reason = cmd.get("reason", "Operator Manual Block")
                res = ids_system.defense_mgr.block_ip(ip, reason, "Manual Admin Action", "T0000", auto=False)
                await broadcast_ws({"type": "IP_BLOCKED", "ip": ip, "details": res})

    except WebSocketDisconnect:
        connected_websockets.discard(websocket)
    except Exception:
        connected_websockets.discard(websocket)


# ─────────────────────────────────────────
# REST API ENDPOINTS
# ─────────────────────────────────────────

@app.get("/api/status")
async def get_status():
    """Get overall system health and status"""
    return ids_system.get_system_report()


@app.get("/api/metrics")
async def get_metrics():
    """Get performance telemetry and detection confusion matrix"""
    report = ids_system.get_system_report()
    return {
        "detection_metrics": report["detection_metrics"],
        "attack_taxonomy": report["attack_taxonomy"],
        "throughput_pps": report["system_info"]["throughput_pps"],
        "avg_latency_ms": report["system_info"]["avg_latency_ms"],
        "model_version": report["model_version"],
    }


@app.get("/api/incidents")
async def get_incidents():
    """Get active deduplicated SOC incidents"""
    return list(ids_system.incidents.values())


@app.get("/api/alerts")
async def get_alerts():
    """Get recent alerts queue"""
    return list(ids_system.alerts)


@app.get("/api/firewall")
async def get_firewall_rules():
    """Get list of active quarantined / blocked IPs"""
    return ids_system.defense_mgr.get_blocked_list()


@app.post("/api/firewall/block")
async def manual_block_ip(req: BlockIpRequest):
    """Manually quarantine an IP address"""
    res = ids_system.defense_mgr.block_ip(req.ip, req.reason, "Manual Operator Action", "T0000", auto=False)
    await broadcast_ws({"type": "IP_BLOCKED", "ip": req.ip, "details": res})
    return res


@app.post("/api/firewall/unblock")
async def unblock_ip(req: BlockIpRequest):
    """Lift quarantine from an IP address"""
    res = ids_system.defense_mgr.unblock_ip(req.ip)
    if res:
        await broadcast_ws({"type": "IP_UNBLOCKED", "ip": req.ip, "details": res})
        return {"status": "SUCCESS", "unblocked": req.ip}
    raise HTTPException(status_code=404, detail="IP not found in blocklist")


@app.post("/api/stream/start")
async def start_stream():
    """Start real-time packet stream"""
    global is_streaming, streaming_task
    if not is_streaming:
        is_streaming = True
        streaming_task = asyncio.create_task(streaming_worker())
    await broadcast_ws({"type": "STATUS_CHANGE", "is_streaming": True})
    return {"status": "STREAMING"}


@app.post("/api/stream/pause")
async def pause_stream():
    """Pause real-time packet stream"""
    global is_streaming, streaming_task
    is_streaming = False
    if streaming_task and not streaming_task.done():
        streaming_task.cancel()
    await broadcast_ws({"type": "STATUS_CHANGE", "is_streaming": False})
    return {"status": "PAUSED"}


@app.post("/api/stream/speed")
async def set_speed(req: SpeedRequest):
    """Adjust packet stream rate"""
    global stream_delay_seconds
    stream_delay_seconds = req.delay
    await broadcast_ws({"type": "SPEED_CHANGED", "delay": stream_delay_seconds})
    return {"status": "SPEED_UPDATED", "delay": stream_delay_seconds}


@app.post("/api/attack/inject")
async def inject_attack(req: AttackInjectRequest):
    """Inject attack scenario into live traffic"""
    global is_streaming, streaming_task
    res = ids_system.data_stream.inject_attack_burst(req.attack_type, req.count)
    if not is_streaming:
        is_streaming = True
        streaming_task = asyncio.create_task(streaming_worker())
    await broadcast_ws({"type": "INJECTION_CONFIRMED", "details": res})
    return res


@app.post("/api/drift/inject")
async def inject_drift(count: int = 40):
    """Inject concept drift to demonstrate autonomous agent retraining"""
    global is_streaming, streaming_task
    res = ids_system.data_stream.inject_concept_drift(count)
    if not is_streaming:
        is_streaming = True
        streaming_task = asyncio.create_task(streaming_worker())
    await broadcast_ws({"type": "DRIFT_CONFIRMED", "details": res})
    return res


@app.post("/api/agent/mode")
async def set_agent_mode(req: AgentModeRequest):
    """Toggle between Autonomous Auto-Pilot and Human-In-The-Loop"""
    res = ids_system.agent.set_autonomous_mode(req.autonomous)
    await broadcast_ws({"type": "MODE_CHANGED", "autonomous": res})
    return {"autonomous_mode": res}


@app.post("/api/adapt/trigger")
async def trigger_adaptation():
    """Manually force model retraining and adaptation"""
    res = ids_system._execute_adaptation()
    await broadcast_ws({"type": "ADAPTATION_TRIGGERED", "result": res})
    return res


@app.get("/api/model/features")
async def get_feature_importances():
    """Get top feature importance rankings for model explainability"""
    return ids_system.model.get_feature_importance(top_n=15)


@app.get("/api/export/forensic")
async def export_forensic_report():
    """Export complete incident report as JSON forensic file"""
    data = ids_system.export_forensic_incident_report()
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f"attachment; filename=aegis_forensic_report_{int(datetime.now().timestamp())}.json"},
    )


# ─────────────────────────────────────────
# STATIC DASHBOARD HOSTING
# ─────────────────────────────────────────

# Ensure static directories exist
os.makedirs(os.path.join(STATIC_DIR, "css"), exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "js"), exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>AegisAgent Cyber SOC Dashboard Initializing...</h1>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
