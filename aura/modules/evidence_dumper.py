import urllib.parse
from rich.console import Console

console = Console()

class EvidenceDumper:
    """
    v26.0 The Verdict: Raw HTTP Evidence Dumper.
    Formats exact HTTP Requests and Responses into Burp Suite compatible 
    raw text blocks for irrefutable Proof of Concept documentation.
    """
    
    @staticmethod
    def dump_request(response_obj, original_payload: str = None) -> str:
        """
        Reconstructs the raw HTTP/1.1 request from a curl_cffi Response object.
        """
        if not response_obj or not hasattr(response_obj, 'request'):
            return "Raw request data unavailable."
            
        req = response_obj.request
        
        try:
            # Reconstruct Request Line
            method = req.method.upper() if req.method else "GET"
            url_parsed = urllib.parse.urlparse(req.url)
            path = url_parsed.path or "/"
            if url_parsed.query:
                path += f"?{url_parsed.query}"
                
            raw_req = f"{method} {path} HTTP/1.1\r\n"
            
            # Host header is mandatory
            host = url_parsed.netloc
            raw_req += f"Host: {host}\r\n"
            
            # Inject Headers
            headers = req.headers if req.headers else {}
            for k, v in headers.items():
                if k.lower() == 'host':
                    continue # Already added
                raw_req += f"{k}: {v}\r\n"
                
            raw_req += "\r\n"
            
            # Inject Body (Payload)
            if req.content:
                if isinstance(req.content, bytes):
                    body = req.content.decode('utf-8', errors='replace')
                else:
                    body = str(req.content)
                raw_req += body
            elif original_payload and method in ["POST", "PUT", "PATCH"]:
                 raw_req += original_payload

            return raw_req
            
        except Exception as e:
             # console.print(f"[dim red][Evidence Dumper] Failed to parse request: {e}[/dim red]")
             return f"Error regenerating raw request: {e}"

    @staticmethod
    def dump_response(response_obj, max_body_len: int = 2000) -> str:
        """
        Reconstructs the raw HTTP/1.1 response from a curl_cffi Response object.
        Truncates the body if it's too large to keep reports clean.
        """
        if not response_obj:
            return "Raw response data unavailable."
            
        try:
            status_code = getattr(response_obj, 'status_code', 0)
            reason = getattr(response_obj, 'reason', 'OK')
            
            raw_resp = f"HTTP/1.1 {status_code} {reason}\r\n"
            
            # Inject Headers
            headers = getattr(response_obj, 'headers', {})
            for k, v in headers.items():
                raw_resp += f"{k}: {v}\r\n"
                
            raw_resp += "\r\n"
            
            # Inject Body
            body_text = getattr(response_obj, 'text', '')
            if body_text:
                if len(body_text) > max_body_len:
                    raw_resp += body_text[:max_body_len] + f"\n\n... [TRUNCATED {len(body_text) - max_body_len} BYTES] ..."
                else:
                    raw_resp += body_text
                    
            return raw_resp
            
        except Exception as e:
            return f"Error regenerating raw response: {e}"
