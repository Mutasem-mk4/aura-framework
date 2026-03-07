from fastapi import FastAPI, WebSocket, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import sqlite3
import json
import asyncio
import os
import uvicorn
from contextlib import asynccontextmanager

# Initialize DB connection to the Aura Intel DB
DB_PATH = "aura_intel.db"

def get_db_stats():
    """Fetches high-level stats from the Aura database."""
    if not os.path.exists(DB_PATH):
        return {"targets": 0, "findings": 0, "critical": 0, "high": 0, "operations": 0}
        
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        targets = c.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        findings = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        ops = c.execute("SELECT COUNT(*) FROM operation_logs").fetchone()[0]
        
        # Severity breakdown
        critical = c.execute("SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL'").fetchone()[0]
        high = c.execute("SELECT COUNT(*) FROM findings WHERE severity = 'HIGH'").fetchone()[0]
        
        conn.close()
        return {
            "targets": targets,
            "findings": findings,
            "critical": critical,
            "high": high,
            "operations": ops
        }
    except Exception as e:
        print(f"DB Read Error: {e}")
        return {"targets": 0, "findings": 0, "critical": 0, "high": 0, "operations": 0}

def get_recent_findings():
    if not os.path.exists(DB_PATH):
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT target, type, severity, timestamp FROM findings ORDER BY id DESC LIMIT 15")
        rows = [{"target": r[0], "type": r[1], "severity": r[2], "time": r[3]} for r in c.fetchall()]
        conn.close()
        return rows
    except:
        return []

def get_recent_ops():
    if not os.path.exists(DB_PATH):
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT target, module, details, timestamp FROM operation_logs ORDER BY id DESC LIMIT 20")
        rows = [{"target": r[0], "module": r[1], "details": r[2], "time": r[3]} for r in c.fetchall()]
        conn.close()
        return rows
    except:
        return []

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start the background data pulser
    yield
    # Shutdown logic if needed

app = FastAPI(title="Aura CommandCenter", lifespan=lifespan)

# Setup Templates & Static
os.makedirs("src/templates", exist_ok=True)
os.makedirs("src/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="src/static"), name="static")
templates = Jinja2Templates(directory="src/templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Poll local DB for updates and push to frontend
            stats = get_db_stats()
            findings = get_recent_findings()
            ops = get_recent_ops()
            
            payload = {
                "stats": stats,
                "findings": findings,
                "operations": ops
            }
            await websocket.send_json(payload)
            await asyncio.sleep(2) # Refresh every 2 seconds
    except Exception as e:
        print(f"WebSocket Client Disconnected: {e}")

if __name__ == "__main__":
    print("[+] Starting Aura CommandCenter Web Server on port 8000...")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
