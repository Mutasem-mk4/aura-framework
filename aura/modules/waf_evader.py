import asyncio
import json
from rich.console import Console

from aura.ui.formatter import console

class AIEvader:
    """
    v25.0 Apex Automation: AI WAF Evader (Ghost v7.0)
    When a request is blocked (HTTP 403), this engine uses AuraBrain (LLM)
    to dynamically analyze the WAF signature and generate targeted, mutated
    payload variants to bypass the filter.
    """
    
    def __init__(self, brain=None):
        if brain is None:
            from aura.core.brain import AuraBrain
            self.brain = AuraBrain()
        else:
            self.brain = brain
            
    async def mutate_payload(self, blocked_payload: str, waf_response: str, tech_stack: str = "GenericWeb") -> list:
        """
        Asks the Brain to generate 3 obfuscated variants of the blocked payload.
        Returns a list of payload strings.
        """
        console.print(f"[bold magenta][🧠 WAF Evader] WAF Triggered! Sending payload to AI for adaptive mutation...[/bold magenta]")
        
        prompt = (
            "You are an expert Red Team AI specialized in WAF Evasion and Payload Obfuscation.\n"
            f"The following payload was just blocked by a Web Application Firewall:\n\n"
            f"Blocked Payload: `{blocked_payload}`\n"
            f"Target Tech Stack: {tech_stack}\n"
            f"WAF Response Snippet: {waf_response[:300]}\n\n"
            "Your task is to generate exactly 3 mutated, heavily obfuscated variants of this payload designed to bypass the WAF while retaining the exact same execution impact.\n"
            "- Use techniques like Unicode/Hex encoding, SQL chunking, JS weird syntax, comment injection, or alternate protocol wrappers.\n"
            "- Output ONLY a valid JSON array of 3 strings. No markdown formatting, no explanations, no wrappers, just the raw `[\"variant1\", \"variant2\", \"variant3\"]`."
        )
        
        try:
            # Call AI in a thread to prevent blocking
            response = await asyncio.to_thread(self.brain._call_ai, prompt)
            
            # Clean up potential markdown formatting from the response
            clean_response = response.replace("```json", "").replace("```", "").strip()
            
            mutations = json.loads(clean_response)
            if isinstance(mutations, list) and len(mutations) > 0:
                console.print(f"[bold green][🧠 WAF Evader] AI successfully generated {len(mutations)} mutated payloads.[/bold green]")
                return mutations[:3]
                
        except json.JSONDecodeError as e:
            console.print(f"[dim red][WAF Evader] AI returned invalid JSON during payload mutation: {e}[/dim red]")
        except Exception as e:
            console.print(f"[dim red][WAF Evader] AI mutation cycle failed: {e}[/dim red]")
            
        return []

    async def auto_evade_request(self, session, method: str, url: str, block_status: int = 403, original_params=None, original_data=None, **kwargs):
        """
        A high-level wrapper. If a request returns the block_status, it extracts the payload,
        mutates it, and retries.
        """
        # This is a complex method that could be integrated directly into AuraSession.
        # For true autonomous evasion, AuraSession should call `AIEvader.mutate_payload` directly
        # when it detects a WAF block during critical injection tests.
        pass
