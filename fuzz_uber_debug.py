import asyncio
import logging
import sys
import os

# Ensure we can import from the current directory
sys.path.append(os.getcwd())

from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer, WorkflowStepStatus
from aura.ui.formatter import console

# Set up logging to see httpx activity
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger("aura.fuzzer.debug")

async def main():
    console.print("[bold green][*] Starting Uber Logic Fuzzer Debug Mode[/bold green]")
    
    # Initialize fuzzer with a short timeout for debugging
    fuzzer = StatefulLogicFuzzer(base_url="https://uber.com", timeout=10.0, max_retries=1)
    
    # Define a very simple 1-step workflow to test connectivity
    test_workflow = [
        {
            "id": "root_check",
            "name": "Uber Main Page",
            "method": "GET",
            "path": "/",
            "requires_auth": False
        }
    ]
    
    # We need to manually add the steps to the DAG since execute_workflow expects WorkflowStep objects or calls define_workflow
    # Actually, execute_workflow in the version I saw (line 605) expects List[WorkflowStep].
    # But define_workflow (line 534) converts Dict to WorkflowStep and adds to DAG.
    
    console.print("[*] Defining test workflow...")
    steps = fuzzer.define_workflow("Debug-Test", test_workflow)
    
    console.print("[*] Executing workflow...")
    try:
        result = await fuzzer.execute_workflow(steps)
        console.print(f"[bold green][✓] Execution Finished. Status: {result.step_results[0].status}[/bold green]")
        if result.findings:
            console.print(f"[bold yellow][!] Findings: {len(result.findings)}[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red][!] Execution Crashed: {e}[/bold red]")
        import traceback
        traceback.print_exc()
    finally:
        await fuzzer.close()

if __name__ == "__main__":
    # Ensure unbuffered output for real-time debugging
    asyncio.run(main())
