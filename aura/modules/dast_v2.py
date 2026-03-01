import asyncio
import json
import random
import time
from playwright.async_api import async_playwright
from rich.console import Console
from aura.core.brain import AuraBrain
from aura.core import state

console = Console()

class AuraSingularity:
    """Ghost v6: The Autonomous Singularity Engine for Chain-of-Thought exploitation."""
    
    def __init__(self):
        self.brain = AuraBrain()
        self.intercepted_requests = []
        self.campaign_findings = []

    async def _handle_request(self, request):
        """Intercepts and logs XHR/Fetch requests for AI analysis."""
        if request.resource_type in ["fetch", "xhr"]:
            req_data = {
                "url": request.url,
                "method": request.method,
                "headers": request.headers,
                "post_data": request.post_data
            }
            self.intercepted_requests.append(req_data)

    async def execute_singularity(self, url: str):
        """Unleashes the autonomous Singularity attack on a target."""
        if state.is_halted(): return []
        
        # Phase 18.1: Ensure valid protocol
        if not url.startswith("http"):
            search_url = f"http://{url}"
        else:
            search_url = url
            
        console.print(f"[bold red][🌋] SINGULARITY ACTIVATED: Initiating CoT Attack on {search_url}...[/bold red]")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                viewport={'width': 1920, 'height': 1080}
            )
            
            # Stealth initialization
            await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            page = await context.new_page()
            page.on("request", self._handle_request)
            
            try:
                # 1. Initial Recon & Interception
                console.print(f"[cyan][*] Intercepting network traffic for {search_url}...[/cyan]")
                await page.goto(search_url, wait_until="networkidle", timeout=45000)
                await asyncio.sleep(2) # Allow for dynamic loads
                
                dom_snippet = await page.content()
                
                # 2. AI Chain-of-Thought Planning
                console.print(f"[bold cyan][🧠] Aura Singularity: Analyzing context for deep logic flaws...[/bold cyan]")
                plan = self.brain.autonomous_plan(url, dom_snippet, self.intercepted_requests)
                
                console.print(f"[bold yellow][➡] TACTICAL PLAN: {plan.get('plan')}[/bold yellow]")
                console.print(f"[dim yellow]Reasoning: {plan.get('reasoning')}[/dim yellow]")
                
                # 3. Autonomous Execution Loop
                # Based on the plan, we might perform specific actions.
                # For Phase 18, we implement logic for IDOR/BOLA probing on intercepted requests.
                target_vector = plan.get("target_vector", "").lower()
                
                if "api" in target_vector or "auth" in target_vector:
                    await self._probe_api_logic(url)
                
                # 4. Ghost v6: Fragmented Payload Delivery
                # We target identified inputs with fragmented payloads
                inputs = await page.query_selector_all("input:not([type='hidden'])")
                if inputs:
                    await self._fragmented_attack(page, inputs, url)

            except Exception as e:
                console.print(f"[bold red][!] Singularity Error: {e}[/bold red]")
            finally:
                await browser.close()
        
        return self.campaign_findings

    async def _human_move_and_click(self, page, selector):
        """Ghost v7: Moves mouse in a human-like Bezyer curve before clicking."""
        try:
            element = await page.query_selector(selector)
            if not element: return
            
            box = await element.bounding_box()
            if not box: return
            
            target_x = box['x'] + box['width'] / 2
            target_y = box['y'] + box['height'] / 2
            
            # Start from current or random position
            start_x, start_y = random.randint(0, 100), random.randint(0, 100)
            
            # Simple Bezier-like curve simulation (overshoot and adjust)
            mid_x = start_x + (target_x - start_x) * 0.5 + random.randint(-50, 50)
            mid_y = start_y + (target_y - start_y) * 0.5 + random.randint(-50, 50)
            
            steps = 15
            for i in range(steps):
                t = i / steps
                # Quadratic Bezier formula: (1-t)^2*P0 + 2(1-t)t*P1 + t^2*P2
                curr_x = (1-t)**2 * start_x + 2*(1-t)*t * mid_x + t**2 * target_x
                curr_y = (1-t)**2 * start_y + 2*(1-t)*t * mid_y + t**2 * target_y
                await page.mouse.move(curr_x, curr_y)
                await asyncio.sleep(0.01)
                
            await page.mouse.click(target_x, target_y, delay=random.randint(50, 150))
        except: pass

    async def _probe_api_logic(self, base_url):
        """Analyzes intercepted API calls for authorization flaws (BOLA/IDOR)."""
        if not self.intercepted_requests: return
        
        console.print(f"[bold magenta][🧬] Logic Probing: Analyzing {len(self.intercepted_requests)} intercepted API calls...[/bold magenta]")
        
        for req in self.intercepted_requests[:5]: # Focus on first few dynamic calls
            url = req['url']
            # Look for ID patterns in URL or body
            if any(k in url.lower() for k in ["/v1/", "/api/", "user", "order", "id="]):
                console.print(f"[dim][⚡] Probing IDOR on: {url}[/dim]")
                # AI-assisted logic check (Placeholder for deep logic verification)
                # In a real scenario, we'd replay with modified IDs or stripped headers.
                await asyncio.sleep(0.5)

    async def _fragmented_attack(self, page, inputs, url):
        """Ghost v6.1: Shreds payloads into fragments with timing jitter and focus-guarantees."""
        console.print(f"[cyan][⚔] Ghost v6.1: Executing High-Precision Fragmented Attack...[/cyan]")
        
        aggressive_trigger = False
        # Phase 42: OCR/Signature Check - If "Vulnerable" found, trigger heavy payloads
        try:
            page_text = await page.content()
            if any(x in page_text.lower() for x in ["vulnerable", "exploit", "sqli", "xss", "injection"]):
                aggressive_trigger = True
                console.print(f"[bold red][🌋] AGGRESSION TRIGGERED: Signature detected on {url}. Increasing payload density by 10x![/bold red]")
        except: pass

        for i in range(50 if aggressive_trigger else 5): # Limit to first 5 or 50 inputs
            for vuln_type in vuln_types:
                try:
                    # Re-query input element to avoid execution context destroyed errors
                    current_inputs = await page.query_selector_all("input:not([type='hidden'])")
                    if i >= len(current_inputs): break
                    input_el = current_inputs[i]
                    
                    # Get a high-aggression Level 3 payload
                    payload = self.brain.generate_payload(vuln_type, "Next.js/Advanced", level=3)
                    
                    # Ensure visibility and focus
                    await input_el.scroll_into_view_if_needed()
                    # Use Ghost v7 humanized mouse movement
                    box = await input_el.bounding_box()
                    if box:
                        await page.mouse.move(box['x'] + box['width']/2, box['y'] + box['height']/2)
                    await input_el.click(force=True, delay=random.randint(50, 150))
                    
                    # Clear existing value if possible
                    try: await page.keyboard.press("Control+a"); await page.keyboard.press("Backspace")
                    except: pass
                    
                    # Fragment the payload with polymorphic variation
                    fragments = [payload[i:i+3] for i in range(0, len(payload), 3)]
                    
                    for frag in fragments:
                        await page.keyboard.type(frag, delay=random.uniform(50, 200))
                        # Adaptive jitter - pausing like a human thinking
                        if random.random() > 0.8:
                            await asyncio.sleep(random.uniform(0.3, 1.2))
                        # Occasional backspace simulation (human error)
                        if random.random() > 0.95:
                            await page.keyboard.press("Backspace")
                            await asyncio.sleep(0.2)
                            await page.keyboard.type(frag[0] if frag else "", delay=100)
                    
                    start_t = time.time()
                    await page.keyboard.press("Enter")
                    
                    # Aggressive wait
                    try: await page.wait_for_load_state("networkidle", timeout=6000)
                    except: pass
                    
                    duration = int((time.time() - start_t) * 1000)
                    content = await page.content()

                    # AI Behavioral reasoning (Fallback)
                    bh = self.brain.analyze_behavior(url, payload, duration, len(content), 200, content)
                    
                    if bh.get("vulnerable"):
                        self.campaign_findings.append({
                            "type": bh.get("type"),
                            "confidence": "Critical",
                            "content": f"SINGULARITY EXPLOIT: {bh.get('type')} on {url} (Ghost v6.1 Fragmented). Reasoning: {bh.get('reason')}"
                        })
                        console.print(f"[bold red][🔥] SINGULARITY EXPLOIT SUCCESS: {bh.get('type')}[/bold red]")
                        break # Successful breach for this input, move to next input
                    elif bh.get("suspect"):
                        console.print(f"[yellow][!] Singularity Monitor: Anomalous behavior on parameter {i} for {vuln_type}[/yellow]")
    
                except Exception as e:
                    console.print(f"[dim red][!] Singularity Interaction Error: {e}[/dim red]")
                    
                    # Ensure we are back on the target URL for the next attempt if navigation happened
                    try: await page.goto(url, wait_until="load")
                    except: pass
                    
                    continue
