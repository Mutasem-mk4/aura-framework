from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os
import sqlite3
from aura.core.storage import AuraStorage

app = FastAPI(title="Aura Omni-Hub")
storage = AuraStorage()

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

if not os.path.exists(STATIC_DIR): os.makedirs(STATIC_DIR)
if not os.path.exists(TEMPLATES_DIR): os.makedirs(TEMPLATES_DIR)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/status")
async def get_status():
    # Fetch real-time status from DB
    stats = storage.get_stats() # Assuming get_stats exists or adding it
    return {
        "status": "ONLINE",
        "brain": "Sentinel-G v16.1",
        "findings": stats.get("findings", 0),
        "targets": stats.get("targets", 0),
        "swarm_nodes": 5,
        "active_campaign": "Z-OVERLORD-7"
    }

@app.get("/api/findings")
async def get_findings():
    conn = sqlite3.connect(storage.db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings ORDER BY id DESC LIMIT 10")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
