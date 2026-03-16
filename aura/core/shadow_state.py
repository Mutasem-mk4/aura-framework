import json
import logging
from typing import List, Dict, Any, Optional
from aura.core.brain import AuraBrain

logger = logging.getLogger("aura.shadow_state")

class ShadowStateModeler:
    """
    v40.0 OMEGA: Shadow State Modeler.
    Reconstructs the target's business logic state machine from captured traffic.
    Identifies 'Causal Chains' and 'Sensitive State Transitions'.
    """

    def __init__(self, brain: AuraBrain = None):
        self.brain = brain or AuraBrain()
        self.state_model = {"states": [], "transitions": [], "logic_chains": []}

    async def model_sequence(self, traffic_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes a sequence of traffic logs to discover logical dependencies.
        """
        if not traffic_logs:
            return self.state_model

        logger.info(f"[🧠 SHADOW] Analyzing sequence of {len(traffic_logs)} transactions...")

        # 1. Pre-process logs for the brain
        sequence_data = []
        for log in traffic_logs:
            sequence_data.append({
                "method": log.get("method"),
                "url": log.get("url"),
                "status": log.get("response_stats", {}).get("status"),
                "req_keys": list(json.loads(log["request_body"]).keys()) if log.get("request_body", "").startswith("{") else [],
                "resp_keys": list(json.loads(log["response_body"]).keys()) if log.get("response_body", "").startswith("{") else []
            })

        # 2. Ask the brain to map the state machine
        prompt = f"""
        As AURA-Zenith Shadow State Modeler, reconstruct the logical state machine from these transactions.
        Logs: {json.dumps(sequence_data[:30])}
        
        Identify:
        1. Authentication / Permission states.
        2. Sequence Dependencies (e.g., Step B requires ID from Step A).
        3. High-Value Logic Chains (e.g., Cart -> Payment -> Receipt).
        
        Respond ONLY in JSON:
        {{
            "states": [{{ "id": "str", "name": "str", "method": "str", "path": "str", "type": "auth|data|action" }}],
            "transitions": [{{ "from": "id", "to": "id", "required_param": "str" }}],
            "logic_chains": [{{ "name": "str", "steps": ["id", "id"], "attack_vector": "IDOR|BOLA|RaceCondition|PriceManipulation" }}]
        }}
        """

        try:
            raw_model = await self.brain.reason_json(prompt)
            if isinstance(raw_model, str):
                self.state_model = json.loads(raw_model)
            else:
                self.state_model = raw_model
            
            logger.info(f"[✓] Shadow State: Synthesized {len(self.state_model.get('states', []))} states and {len(self.state_model.get('logic_chains', []))} attack chains.")
            return self.state_model
        except Exception as e:
            logger.error(f"[!] Shadow State modeling failed: {e}")
            return self.state_model

    def get_fuzzer_workflow(self) -> List[Dict[str, Any]]:
        """
        Converts the logic chains into a format compatible with StatefulLogicFuzzer.
        """
        workflow = []
        # Convert chains to steps
        for chain in self.state_model.get("logic_chains", []):
            chain_steps = []
            for state_id in chain.get("steps", []):
                state = next((s for s in self.state_model["states"] if s["id"] == state_id), None)
                if state:
                    chain_steps.append({
                        "id": state["id"],
                        "name": state["name"],
                        "method": state["method"],
                        "path": state["path"],
                        "requires_auth": state["type"] == "auth" or state["type"] == "action"
                    })
            workflow.append({
                "name": chain["name"],
                "attack_vector": chain["attack_vector"],
                "steps": chain_steps
            })
        return workflow
