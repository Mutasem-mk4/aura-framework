import threading
from prometheus_client import start_http_server, Counter, Gauge, Histogram

class AuraMetrics:
    """Enterprise Observability: Prometheus Metrics Exporter (Phase 7)"""
    
    def __init__(self):
        self._server_started = False
        
        # Define Metrics
        self.vulns_found = Counter(
            'aura_vulnerabilities_found_total', 
            'Total vulnerabilities discovered by Aura',
            ['severity', 'engine']
        )
        
        self.requests_sent = Counter(
            'aura_http_requests_total',
            'Total HTTP requests sent'
        )
        
        self.requests_blocked = Counter(
            'aura_http_blocked_total',
            'Total HTTP requests blocked by WAF (403/406/429)'
        )
        
        self.tasks_completed = Counter(
            'aura_swarm_tasks_completed',
            'Total distributed tasks finished',
            ['engine', 'status']
        )
        
        self.active_scans = Gauge(
            'aura_active_scans_gauge',
            'Current number of parallel scanning operations'
        )
        
        self.phase_duration = Histogram(
            'aura_phase_duration_seconds',
            'Time spent executing each mission phase',
            ['phase_name']
        )

    def start_server(self, port=8000):
        """Starts the Prometheus HTTP metrics server in a background thread."""
        if not self._server_started:
            try:
                start_http_server(port)
                self._server_started = True
            except Exception as e:
                pass # Depending on environment, port might be in use or no bind

# Singleton Instance
METRICS = AuraMetrics()
