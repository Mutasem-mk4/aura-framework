import os
import sys
import json
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Set
import asyncio

# Fix: Add current working directory to path to resolve 'aura' module
sys.path.append(os.getcwd())

from aura.core.storage import AuraStorage
from aura.modules.scanner import AuraScanner
from aura.modules.exploiter import AuraExploiter
from aura.core.reporter import AuraReporter
from aura.core.orchestrator import NeuralOrchestrator
from aura.core import state

app = FastAPI(title="Aura Nexus API", version="4.0.0")
db = AuraStorage()
reporter = AuraReporter()

# WebSocket Manager for live streaming
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Broadcasts a structured JSON message to all connected clients."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# Middleware...
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount screenshots directory to serve images
if not os.path.exists("screenshots"):
    os.makedirs("screenshots")
app.mount("/screenshots", StaticFiles(directory="screenshots"), name="screenshots_files")

class ScanRequest(BaseModel):
    domain: str
    campaign_id: Optional[int] = None

class CampaignRequest(BaseModel):
    name: str
    whitelist: Optional[List[str]] = None
    blacklist: Optional[List[str]] = None

class TriageStatusRequest(BaseModel):
    status: str

# In-memory scope settings (for now, in real impl these would be in DB or config)
GLOBAL_WHITELIST = []
GLOBAL_BLACKLIST = ["google.com", "facebook.com", "microsoft.com", "apple.com"]

@app.get("/", response_class=HTMLResponse)
def read_root():
    """Serves the Zenith Nexus Dashboard."""
    nexus_path = os.path.join(os.path.dirname(__file__), "nexus.html")
    if os.path.exists(nexus_path):
        with open(nexus_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Aura Nexus API Online</h1>"

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def run_zenith_background(domain: str, campaign_id: int = None):
    """Background task to run Zenith scan and stream logs via WS."""
    orchestrator = NeuralOrchestrator(
        whitelist=GLOBAL_WHITELIST, 
        blacklist=GLOBAL_BLACKLIST,
        broadcast_callback=manager.broadcast
    )
    
    # Send Mission Start
    await manager.broadcast({
        "type": "status",
        "level": "info",
        "content": f"Initiating Zenith Mission for {domain}...",
        "icon": "brain"
    })
    
    result = await orchestrator.execute_advanced_chain(domain, campaign_id=campaign_id)
    
    if result.get("status") == "blocked":
        await manager.broadcast({
            "type": "alert",
            "level": "critical",
            "content": f"MISSION BLOCKED: {domain} is OUT OF SCOPE.",
            "icon": "skull-crossbones"
        })
    else:
        await manager.broadcast({
            "type": "status",
            "level": "success",
            "content": f"Mission Complete for {domain}.",
            "icon": "check-circle"
        })

@app.post("/scan")
async def launch_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Triggers a background Zenith scan."""
    background_tasks.add_task(run_zenith_background, request.domain, request.campaign_id)
    return {"message": f"Scan initiated for {request.domain}", "status": "processing"}

@app.post("/campaigns")
def create_campaign(request: CampaignRequest):
    cid = db.create_campaign(request.name, {"whitelist": request.whitelist, "blacklist": request.blacklist})
    return {"message": "Campaign created", "id": cid}

@app.get("/audit/logs")
def get_audit_logs(campaign_id: Optional[int] = None):
    return db.get_audit_logs(campaign_id)

@app.get("/targets")
def get_targets():
    return db.get_all_targets()

@app.get("/findings")
def get_all_findings():
    return db.get_all_findings()

@app.get("/findings/{target_id}")
def get_findings_by_id(target_id: int):
    target = db.get_target_by_id(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    findings = db.get_findings_by_target(target["value"])
    return {"target": target, "findings": findings}

@app.get("/report/pdf")
def get_pdf_report():
    path = reporter.generate_pdf_report()
    return FileResponse(path, media_type="application/pdf")

@app.get("/report/html")
def get_html_report():
    path = reporter.generate_report()
    return FileResponse(path, media_type="text/html")

@app.post("/stop")
def stop_ops():
    state.emergency_stop()
    return {"status": "halting"}

@app.get("/api/screenshots")
def list_screenshots():
    screenshot_dir = "screenshots"
    if not os.path.exists(screenshot_dir): return []
    return [f for f in os.listdir(screenshot_dir) if f.endswith(".png")]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
