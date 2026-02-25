import os
import sys
import json
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

# Fix: Add current working directory to path to resolve 'aura' module
sys.path.append(os.getcwd())

from aura.core.storage import AuraStorage
from aura.modules.scanner import AuraScanner
from aura.modules.exploiter import AuraExploiter

app = FastAPI(title="Aura Nexus API", version="3.0.0")
db = AuraStorage()

# Enable CORS for the React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    domain: str

class Target(BaseModel):
    id: int
    source: str
    type: str
    value: str

@app.get("/", response_class=HTMLResponse)
def read_root():
    """Serves the Zenith Nexus Dashboard."""
    nexus_path = os.path.join(os.path.dirname(__file__), "nexus.html")
    if os.path.exists(nexus_path):
        with open(nexus_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Aura Nexus API Online</h1><p>Dashboard file not found.</p>"

@app.get("/targets", response_model=List[Target])
def get_targets():
    """Returns all discovered targets from the SQLite memory."""
    return db.get_all_targets()

@app.post("/scan")
def launch_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Triggers a background scan for a domain."""
    # This is a placeholder for the background execution logic
    # In a full impl, we'd use a task queue or asyncio background tasks
    return {"message": f"Scan initiated for {request.domain}", "status": "processing"}

@app.get("/findings/{target_id}")
def get_findings(target_id: int):
    """Returns all findings associated with a specific target ID."""
    target = db.get_target_by_id(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    findings = db.get_findings_by_target(target["value"])
    return {"target": target, "findings": findings}

@app.get("/screenshots")
def list_screenshots():
    """Lists all captured visual recon files."""
    screenshot_dir = "screenshots"
    if not os.path.exists(screenshot_dir):
        return []
    return [f for f in os.listdir(screenshot_dir) if f.endswith(".png")]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
