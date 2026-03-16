from burp import IBurpExtender
from burp import IExtensionStateListener
from java.io import PrintWriter
import threading
import json
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Aura Bridge API")
        
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        callbacks.registerExtensionStateListener(self)
        
        # Start the local API server on a background thread so Burp doesn't freeze
        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        self.stdout.println("=====================================")
        self.stdout.println("Aura Bridge Extension Loaded!")
        self.stdout.println("REST API listening on http://127.0.0.1:8090")
        self.stdout.println("=====================================")

    def extensionUnloaded(self):
        self.stdout.println("Unloading Aura Bridge...")
        if hasattr(self, 'httpd'):
            self.httpd.shutdown()
            self.httpd.server_close()

    def start_server(self):
        # Define the HTTP Request Handler inside to easily access callbacks
        class AuraRequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/sitemap':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    sitemap = self.server.callbacks.getSiteMap(None)
                    results = []
                    for item in sitemap:
                        request_info = self.server.helpers.analyzeRequest(item)
                        url = str(request_info.getUrl())
                        status_code = 0
                        if item.getResponse():
                            response_info = self.server.helpers.analyzeResponse(item.getResponse())
                            status_code = response_info.getStatusCode()
                            
                        # Deduplicate simple URLs for cleaner output
                        entry = {
                            "url": url,
                            "method": request_info.getMethod(),
                            "status": status_code
                        }
                        if entry not in results:
                            results.append(entry)
                        
                    self.wfile.write(json.dumps({"sitemap": results}))
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                if self.path == '/proxy':
                    content_length = int(self.headers.getheader('content-length', 0))
                    post_data = self.rfile.read(content_length)
                    try:
                        data = json.loads(post_data)
                        url_str = data.get('url')
                        if url_str:
                            import java.net.URL
                            java_url = java.net.URL(url_str)
                            port = java_url.getPort()
                            if port == -1:
                                port = 443 if java_url.getProtocol() == 'https' else 80
                            
                            # Build a basic GET request to send through Burp
                            request_bytes = self.server.helpers.buildHttpRequest(java_url)
                            http_service = self.server.helpers.buildHttpService(java_url.getHost(), port, java_url.getProtocol() == 'https')
                            
                            # Make the HTTP request through Burp's engine
                            # This will populate the sitemap and proxy history automatically
                            self.server.callbacks.makeHttpRequest(http_service, request_bytes)
                            
                            self.send_response(200)
                            self.send_header('Content-type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({"status": "success", "message": "Request sent via Burp proxy."}))
                        else:
                            self.send_response(400)
                            self.end_headers()
                    except Exception as e:
                        self.server.stdout.println("Aura Bridge Error: " + str(e))
                        self.send_response(500)
                        self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

            # Suppress default logging to avoid cluttering Burp's output
            def log_message(self, format, *args):
                pass

        try:
            self.httpd = HTTPServer(('127.0.0.1', 8090), AuraRequestHandler)
            # Attach Burp objects to the server instance so the handler can use them
            self.httpd.callbacks = self._callbacks
            self.httpd.helpers = self._helpers
            self.httpd.stdout = self.stdout
            self.httpd.serve_forever()
        except Exception as e:
            self.stderr.println("Failed to start API server: " + str(e))
