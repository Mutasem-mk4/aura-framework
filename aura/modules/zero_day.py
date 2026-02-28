import os
import subprocess
from rich.console import Console
from google import genai
from aura.core import state

console = Console()

class ZeroDayAgent:
    """Uses generative AI to write and execute custom exploit scripts dynamically."""
    
    def __init__(self):
        self.workspace = "/tmp/aura_zero_day"
        if not os.path.exists(self.workspace):
            os.makedirs(self.workspace)
            
    async def synthesize_and_execute(self, target_url, vulnerability_context):
        """Asks AI to generate a python exploit script, runs it, and fixes errors iteratively (v2)."""
        console.print(f"[bold red][*] ZERO-DAY AGENT v2: Synthesizing exploit for {target_url}...[/bold red]")
        
        api_key = os.getenv("GEMINI_API_KEY") or state.GEMINI_API_KEY
        if not api_key:
            console.print("[dim yellow][!] GEMINI_API_KEY missing. Cannot synthesize zero-day.[/dim yellow]")
            return False
            
        try:
            client = genai.Client(api_key=api_key)
            model_id = state.GEMINI_MODEL
        except Exception as e:
            console.print(f"[dim red][!] Failed to initialize Gemini Client: {e}[/dim red]")
            return False
        
        system_prompt = "You are Aura-AI, an autonomous offensive security engine. Write complete, executable Python scripts for security testing."
        prompt = f"Write a complete, executable Python script to test the following vulnerability on {target_url}.\nContext: {vulnerability_context}\nReturn ONLY the raw python code, no markdown, no explanations."
        
        history = []
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                console.print(f"[bold cyan][*] Synthesis Attempt {attempt + 1}/{max_retries}...[/bold cyan]")
                
                content = prompt if attempt == 0 else f"The previous script failed with this error:\n{history[-1]['error']}\n\nPlease fix the script and return the full corrected Python code. ONLY raw code."
                
                response = client.models.generate_content(
                    model=model_id,
                    contents=content,
                    config={'system_instruction': system_prompt}
                )
                
                script_code = response.text.strip().replace('```python', '').replace('```', '')
                
                script_path = os.path.join(self.workspace, "exploit.py")
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(script_code)
                    
                console.print("[bold green][+] Script generated. Executing in sandbox...[/bold green]")
                
                # Execute the generated script
                result = subprocess.run(["python", script_path], capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    console.print(f"[bold green][!!!] ZERO-DAY SUCCESS: {result.stdout.strip()}[/bold green]")
                    return True
                else:
                    error_msg = result.stderr.strip() or "Unknown error / Timeout"
                    console.print(f"[dim yellow][?] Attempt {attempt + 1} failed: {error_msg}[/dim yellow]")
                    history.append({"script": script_code, "error": error_msg})
                    
            except Exception as e:
                console.print(f"[dim red][!] Synthesis exception on attempt {attempt + 1}: {e}[/dim red]")
                history.append({"error": str(e)})
                
        console.print("[bold red][!] Zero-Day Agent: Failed to synthesize a working exploit after all retries.[/bold red]")
        return False
