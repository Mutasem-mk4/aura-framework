import os
import asyncio
from celery import Celery
from celery.signals import worker_process_init
from rich.console import Console
from urllib.parse import urlparse
from aura.core.metrics import METRICS

console = Console()

# Detect environment
broker_url = os.getenv("CELERY_BROKER_URL", "amqp://guest:guest@localhost:5672//")
backend_url = os.getenv("DATABASE_URL", "db+sqlite:///aura_intel.db")

# Optional: Add retry logic for broker connection during startup
app = Celery(
    'aura_swarm',
    broker=broker_url,
    backend=backend_url,
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1, # Fair dispatching
    task_acks_late=True # Don't ack until task is fully done
)

@worker_process_init.connect
def init_worker_metrics(**kwargs):
    """Start Prometheus Metrics Server on worker startup.
    Uses port 8000. If running multiple workers on the same machine,
    you may need logic to increment the port dynamically."""
    try:
        METRICS.start_server(port=8000)
    except Exception as e:
        console.print(f"[dim yellow]Worker metrics server skipped (port in use?): {e}[/dim yellow]")

@app.task(bind=True, name="aura.tasks.dast_scan")
def task_dast_scan(self, target_url: str, engine_type: str, campaign_id: str = None):
    """
    Executes a heavy DAST scan (XSS, SQLi, Fuzzing) on a worker node.
    """
    console.print(f"[bold magenta][Swarm Worker][/bold magenta] Executing {engine_type} scan on {target_url}...")
    
    # We must instantiate the required engine locally on the worker process
    # and run its async method inside a synchronous Celery wrapper.
    try:
        if engine_type == "fuzzer":
            from aura.modules.scanner import AuraScanner
            from aura.core.stealth import StealthEngine
            stealth = StealthEngine()
            scanner = AuraScanner(stealth=stealth)
            
            # Run the async method
            loop = asyncio.get_event_loop()
            results = loop.run_until_complete(scanner.force_fuzz(target_url))
            
            METRICS.tasks_completed.labels(engine=engine_type, status='success').inc()
            return {"status": "success", "engine": engine_type, "target": target_url, "hits": results}
            
        elif engine_type == "nuclei":
            from aura.modules.nuclei_engine import NucleiEngine
            engine = NucleiEngine()
            
            loop = asyncio.get_event_loop()
            results = loop.run_until_complete(engine.scan(target_url))
            
            METRICS.tasks_completed.labels(engine=engine_type, status='success').inc()
            return {"status": "success", "engine": engine_type, "target": target_url, "findings": results}
            
        else:
            METRICS.tasks_completed.labels(engine=engine_type, status='error').inc()
            return {"status": "error", "reason": f"Unknown engine_type: {engine_type}"}
            
    except Exception as e:
        console.print(f"[bold red][Swarm Worker][/bold red] Task failed: {e}")
        METRICS.tasks_completed.labels(engine=engine_type, status='exception').inc()
        return {"status": "exception", "error": str(e)}

@app.task(bind=True, name="aura.tasks.recon_pipeline")
def task_recon_pipeline(self, domain: str, target_ip: str = None, intel_data: dict = None):
    """
    Executes the Recon Pipeline on a worker node.
    """
    console.print(f"[bold magenta][Swarm Worker][/bold magenta] Executing Recon on {domain}...")
    
    try:
        from aura.modules.recon_pipeline import ReconPipeline
        pipeline = ReconPipeline()
        
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(pipeline.run(domain, target_ip, intel_data=intel_data))
        
        METRICS.tasks_completed.labels(engine='recon', status='success').inc()
        return {"status": "success", "domain": domain, "results": results}
    except Exception as e:
        console.print(f"[bold red][Swarm Worker][/bold red] Recon failed: {e}")
        METRICS.tasks_completed.labels(engine='recon', status='exception').inc()
        return {"status": "exception", "error": str(e)}

if __name__ == '__main__':
    app.start()
