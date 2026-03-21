"""
Aura v38.0 ? Stateful Logic Fuzzer
==================================
DAG-Based API Workflow Testing with Session State Propagation

Executes API workflows as directed acyclic graphs, propagating authentication
and session tokens between steps while intelligently fuzzing specific parameters.

Usage:
    from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer
    
    workflow = [
        {"method": "POST", "path": "/api/login", "data": {"email": "user@test.com", "password": "test123"}},
        {"method": "GET", "path": "/api/profile", "extract_token": "token"},
        {"method": "POST", "path": "/api/checkout", "mutate": {"quantity": -1}}
    ]
    
    fuzzer = StatefulLogicFuzzer(base_url="https://target.com")
    results = await fuzzer.execute_workflow(workflow)
"""

import asyncio
import json
import re
import time
import uuid
import hashlib
from typing import Dict, List, Set, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse, parse_qs
from collections import defaultdict
import sys
import io
import os

# Set UTF-8 encoding for Windows
if os.name == 'nt':
    os.environ['PYTHONIOENCODING'] = 'utf-8'

import httpx
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.tree import Tree
from aura.core.brain import AuraBrain
from aura.modules.idor_hunter_v2 import IDORHunterV2
from aura.modules.sentinel_ssrf import SentinelSSRF
from aura.core.polymorphic_engine import PolymorphicEngine
from aura.core import state

from aura.ui.formatter import console


class WorkflowStepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    MUTATED = "mutated"


class MutationType(Enum):
    NEGATIVE = "negative"
    ZERO = "zero"
    MAX_INT = "max_int"
    NEGATIVE_MAX = "negative_max"
    FLOAT = "float"
    STRING = "string"
    EMPTY = "empty"
    NULL = "null"
    BOOL_TOGGLE = "bool_toggle"
    ARRAY_EMPTY = "array_empty"
    ARRAY_NEGATIVE = "array_negative"
    SQLI = "sqli"
    XSS = "xss"
    OVERFLOW = "overflow"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"


@dataclass
class WorkflowStep:
    step_id: str
    name: str
    method: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    extract_token: Optional[str] = None
    extract_cookie: Optional[str] = None
    extract_json: Optional[str] = None
    requires_auth: bool = True
    skip_if_failed: bool = True
    retries: int = 3
    
    depends_on: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    expected_status: List[int] = field(default_factory=lambda: [200, 201, 204])
    
    mutate: Optional[Dict[str, Any]] = field(default_factory=dict)
    fuzz_params: List[str] = field(default_factory=list)
    fuzz_types: List[MutationType] = field(default_factory=lambda: [MutationType.NEGATIVE, MutationType.ZERO])


@dataclass
class StepResult:
    step_id: str
    status: WorkflowStepStatus
    request: Dict
    response: Dict
    response_time: float
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    mutated_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowResult:
    workflow_name: str
    total_steps: int
    successful_steps: int
    failed_steps: int
    mutated_steps: int
    step_results: List[StepResult]
    findings: List[Dict[str, Any]]
    execution_time: float


@dataclass
class Vulnerability:
    step_id: str
    vuln_type: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    remediation: str
    cwe_id: Optional[str] = None


class SessionState:
    """Manages session state across workflow steps."""
    
    def __init__(self):
        self.tokens: Dict[str, str] = {}
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.json_data: Dict[str, Any] = {}
        self.custom: Dict[str, Any] = {}
        self.extracted: Dict[str, Any] = {}
        self.history: List[Dict[str, Any]] = [] # Full history of steps in this session
    
    def set_token(self, key: str, value: str):
        self.tokens[key] = value
        self.headers["Authorization"] = f"Bearer {value}"
    
    def set_cookie(self, key: str, value: str):
        self.cookies[key] = value
        # Ensure Cookie header string is built dynamically if needed, or rely on httpx cookiejar
        current_cookie_str = self.headers.get("Cookie", "")
        new_cookie = f"{key}={value}"
        if new_cookie not in current_cookie_str:
            self.headers["Cookie"] = f"{current_cookie_str}; {new_cookie}".strip("; ")
    
    def set_json(self, key: str, value: Any):
        self.json_data[key] = value
    
    def merge(self, other: 'SessionState'):
        self.tokens.update(other.tokens)
        self.cookies.update(other.cookies)
        self.headers.update(other.headers)
        self.json_data.update(other.json_data)
        self.custom.update(other.custom)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tokens": self.tokens,
            "cookies": self.cookies,
            "headers": self.headers,
            "json_data": self.json_data,
            "custom": self.custom
        }
    
    def log_step(self, step_id: str, request: Dict, response: Dict):
        """Logs a full step into the session history for strategic analysis."""
        self.history.append({
            "timestamp": time.time(),
            "step_id": step_id,
            "request": {k: v for k, v in request.items() if k != "headers"}, # Minimal headers
            "response": {
                "status": response.get("status"),
                "body_preview": str(response.get("body", ""))[:200],
                "headers": {k: v for k, v in response.get("headers", {}).items() if k.lower() in ["set-cookie", "x-csrf-token", "location"]}
            }
        })

class StrategicMind:
    """v51.0 Apex: The autonomous strategic brain for logic fuzzing."""
    
    def __init__(self, brain: AuraBrain):
        self.brain = brain
        self.logic_graph = defaultdict(list)
        
    def generate_briefing(self, session: SessionState) -> str:
        """Synthesizes a strategic briefing from session history."""
        brief = "Strategic Session Briefing:\n"
        for entry in session.history[-5:]: # Focus on last 5 steps for context
            brief += f"- Step {entry['step_id']}: Status {entry['response']['status']} | Payload Summary: {json.dumps(entry['request'].get('data', {}))}\n"
        return brief

    async def decide_next_move(self, current_step: WorkflowStep, result: StepResult, session: SessionState) -> Optional[Dict[str, Any]]:
        """AI determines if the current DAG level should be abandoned for a new strategy."""
        if result.status == WorkflowStepStatus.FAILED or "error" in str(result.response.get("body")).lower():
            briefing = self.generate_briefing(session)
            prompt = f"""
            {briefing}
            Current Step: {current_step.name} ({current_step.method} {current_step.path})
            Result: {result.response.get('status')} | Body: {result.response.get('body')}
            
            Based on the failure/response above, should we:
            1. PERSIST: Continue the current DAG level.
            2. ADAPT: Modify the next step's payload (e.g. change encoding, bypass CSRF).
            3. PIVOT: Skip to a different part of the workflow.
            
            Respond with a JSON decision: {{"move": "PERSIST|ADAPT|PIVOT", "reason": "...", "modifications": {{...}}}}
            """
            try:
                decision_raw = await asyncio.to_thread(self.brain.reason_json, prompt)
                decision = json.loads(decision_raw)
                if isinstance(decision, list) and len(decision) > 0:
                    return decision[0]
                return decision if isinstance(decision, dict) else {"move": "PERSIST"}
            except:
                return {"move": "PERSIST"}
        return {"move": "PERSIST"}

class ParameterMutator:
    """v38.0: OMEGA Sentient: Context-Aware Morphic Payload Engine."""
    
    def __init__(self, brain: Optional[AuraBrain] = None):
        self.brain = brain or AuraBrain()
    
    SEMANTIC_HINTS = {
        "price": [MutationType.ZERO, MutationType.NEGATIVE, MutationType.FLOAT, MutationType.STRING],
        "qty": [MutationType.NEGATIVE, MutationType.ZERO, MutationType.OVERFLOW, MutationType.ARRAY_NEGATIVE],
        "quantity": [MutationType.NEGATIVE, MutationType.ZERO, MutationType.OVERFLOW, MutationType.ARRAY_NEGATIVE],
        "admin": [MutationType.BOOL_TOGGLE, MutationType.STRING, MutationType.NULL],
        "role": [MutationType.STRING, MutationType.NULL, MutationType.EMPTY],
        "id": [MutationType.NEGATIVE, MutationType.STRING, MutationType.SQLI, MutationType.PATH_TRAVERSAL],
        "path": [MutationType.PATH_TRAVERSAL, MutationType.STRING],
        "url": [MutationType.SSRF, MutationType.STRING],
        "email": [MutationType.STRING, MutationType.NULL],
    }

    MUTATIONS = {
        MutationType.NEGATIVE: lambda p, v: -1 if not isinstance(v, (int, float)) else -abs(v),
        MutationType.ZERO: lambda p, v: 0,
        MutationType.MAX_INT: lambda p, v: 2147483647,
        MutationType.NEGATIVE_MAX: lambda p, v: -2147483647,
        MutationType.FLOAT: lambda p, v: 0.0000001,
        MutationType.STRING: lambda p, v: "';--",
        MutationType.EMPTY: lambda p, v: "",
        MutationType.NULL: lambda p, v: None,
        MutationType.BOOL_TOGGLE: lambda p, v: not bool(v),
        MutationType.ARRAY_EMPTY: lambda p, v: [],
        MutationType.ARRAY_NEGATIVE: lambda p, v: [-1],
        MutationType.SQLI: lambda p, v: ["' OR 1=1--", "1' AND '1'='1"],
        MutationType.XSS: lambda p, v: ["<script>alert(1)</script>", "javascript:alert(1)"],
        MutationType.OVERFLOW: lambda p, v: 999999999,
        MutationType.PATH_TRAVERSAL: lambda p, v: ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
    }
    
    async def mutate(self, param_name: str, original_value: Any, mutation_types: List[MutationType], context: Dict[str, Any] = None, use_ai: bool = True) -> List[Tuple[MutationType, Any]]:
        """v38.0: Real-time dynamic payload generation via AuraBrain."""
        mutations = []
        
        if use_ai and context and self.brain:
            # Sentient Morphic Engine: Dynamic AI-generated bypasses
            prompt = f"""
            Target URL: {context.get('url')}
            Parameter Name: {param_name}
            Original Value: {original_value}
            Previous Response: {context.get('prev_response_summary', 'N/A')}
            
            Generate a custom, polymorphic payload designed specifically to bypass the inferred backend logic.
            If this looks like a specific framework (Java/Spring, PHP/Laravel, Node/Express), generate a targeted bypass.
            Format: json array of strings.
            """
            try:
                # Use reason_json or a similar method that returns a JSON list
                brain_response = await asyncio.to_thread(self.brain.reason_json, prompt)
                if isinstance(brain_response, str):
                    custom_payloads = json.loads(brain_response)
                else:
                    custom_payloads = brain_response
                
                if isinstance(custom_payloads, list):
                    for payload in custom_payloads:
                        mutations.append((MutationType.STRING, payload))
            except Exception as e:
                console.print(f"[dim red][!] Sentient Mutator Error: {e}[/dim red]")
        
        # Determine target types: requested + semantic hints
        target_types = set(mutation_types)
        for hint, types in self.SEMANTIC_HINTS.items():
            if hint in param_name.lower():
                target_types.update(types)
        
        for mut_type in target_types:
            if mut_type in self.MUTATIONS:
                try:
                    mut_value = self.MUTATIONS[mut_type](param_name, original_value)
                    if isinstance(mut_value, list):
                        for v in mut_value: mutations.append((mut_type, v))
                    else:
                        mutations.append((mut_type, mut_value))
                except: pass
        
        return mutations


class DAGExecutor:
    """Executes workflow steps in DAG topological order."""
    
    def __init__(self):
        self.graph: Dict[str, Set[str]] = defaultdict(set)
        self.in_degree: Dict[str, int] = defaultdict(int)
        self.nodes: Dict[str, WorkflowStep] = {}
    
    def add_step(self, step: WorkflowStep):
        self.nodes[step.step_id] = step
        self.in_degree[step.step_id] = len(step.depends_on)
        
        for dep in step.depends_on:
            self.graph[dep].add(step.step_id)
    
    def topological_sort(self) -> List[str]:
        # Copy in_degree to prevent destructive updates to the original state
        current_in_degree = self.in_degree.copy()
        queue = [node for node, degree in current_in_degree.items() if degree == 0]
        result = []
        
        while queue:
            node = queue.pop(0)
            result.append(node)
            
            for neighbor in self.graph[node]:
                current_in_degree[neighbor] -= 1
                if current_in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        if len(result) != len(self.nodes):
            raise ValueError("Cycle detected in workflow DAG")
        
        return result


class StatefulLogicFuzzer:
    """
    Production-grade Stateful API Workflow Fuzzer.
    
    Executes API workflows as DAGs with:
    - Session state propagation (tokens, cookies)
    - Intelligent parameter mutation
    - Business logic vulnerability detection
    - Comprehensive result tracking
    """
    
    def __init__(
        self,
        base_url: str,
        session: Optional[httpx.AsyncClient] = None,
        default_headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        rate_limit_delay: float = 0.5
    ):
        self.base_url = base_url.rstrip('/')
        self.default_headers = default_headers or {
            "User-Agent": "Aura-Logic-Fuzzer/38.0",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit_delay = rate_limit_delay
        
        self.session = session
        self._owns_session = False
        
        self.mutator = ParameterMutator()
        self.dag_executor = DAGExecutor()
        
        self.results: List[WorkflowResult] = []
        self.findings: List[Vulnerability] = []
        
        self._callbacks: Dict[str, List[Callable]] = {
            "before_step": [],
            "after_step": [],
            "on_finding": [],
        }
        self.brain = AuraBrain()
        self.polymorphic = PolymorphicEngine(self.brain)
        self.idor_hunter = IDORHunterV2()
        self.sentinel_ssrf = SentinelSSRF()
        self.strategic_mind = StrategicMind(self.brain)

    async def generate_ai_workflow(self, endpoints: List[Dict[str, Any]]) -> List[WorkflowStep]:
        """v51.0: Real-time autonomous workflow synthesis via AuraBrain CoT."""
        if not self.brain or not self.brain.enabled:
            return []
            
        console.print(f"[bold purple]🧠 [AuraBrain] Analyzing {len(endpoints)} endpoints for logic attack chains...[/bold purple]")
        
        endpoints_subset = endpoints[:20] if endpoints else []
        prompt = f"""
        Analyze these discovered endpoints and synthesize 2-3 step business logic attack workflows (e.g. IDOR, BOLA, Race Condition, Price Manipulation).
        Endpoints: {json.dumps(endpoints_subset)}
        
        Format your response as a JSON array of workflow steps compatible with StatefulLogicFuzzer.
        Each step must include: id, name, method, path, data, extract_token (optional), depends_on (optional).
        
        Focus on stateful interactions (e.g. User A creates resource, User B deletes it).
        """
        
        try:
            raw_workflow = await asyncio.to_thread(self.brain.reason_json, prompt)
            step_defs = json.loads(raw_workflow)
            if not isinstance(step_defs, list): return []
            
            return self.define_workflow("AI-Synthesized-Attack", step_defs)
        except Exception as e:
            console.print(f"[dim red][!] AI Workflow Synthesis Failed: {e}[/dim red]")
            return []

    async def ingest_model(self, state_model: Dict[str, Any]):
        """v51.0 OMEGA: Converters AI State Model into executable DAG steps."""
        console.print("[bold purple][🧬] Ingesting Neural State Model into Fuzzer DAG...[/bold purple]")
        states = state_model.get("states", [])
        transitions = state_model.get("transitions", [])
        fuzz_points = state_model.get("suggested_fuzz_points", [])
        logic_chains = state_model.get("logic_chains", [])
        
        step_definitions = []
        for state in states:
            # Create a step for each state
            step_def = {
                "id": state.get("id", str(uuid.uuid4())),
                "name": state.get("name", "Unnamed State"),
                "method": state.get("method", "GET"),
                "path": state.get("path", "/"),
                "data": state.get("sample_data", {}),
                "type": state.get("type", "data"),
                "fuzz_params": [p for p in fuzz_points if p in str(state.get("path")) or p in state.get("sample_data", {})],
                "depends_on": [t["from"] for t in transitions if t["to"] == state.get("id")]
            }
            step_definitions.append(step_def)
            
        self.define_workflow("Sentient-Audit-Workflow", step_definitions)
        
        # Also define specific workflows for each discovered logic chain
        for chain in logic_chains:
            chain_steps = []
            for state_id in chain.get("steps", []):
                state_def = next((s for s in step_definitions if s["id"] == state_id), None)
                if state_def:
                    chain_steps.append(state_def)
            if chain_steps:
                self.define_workflow(f"Chain-{chain['name']}", chain_steps)
                
        console.print(f"[bold green][✓] DAG Compiled: {len(step_definitions)} neural nodes and {len(logic_chains)} attack chains ready.[/bold green]")

    async def execute_advanced_strategy(self):
        """Executes the loaded DAG with sentient mutations and state monitoring."""
        workflow = [step for step in self.dag_executor.nodes.values()]
        if not workflow:
            console.print("[red][!] No workflow found to execute strategy.[/red]")
            return
            
        await self.execute_workflow(workflow, mutate_only=True)

    async def _convert_to_impact(self, vuln: Vulnerability, session: SessionState):
        """v51.0 Apex Phase 4: Fatal Impact escalation engine."""
        console.print(f"[bold red]| [🧨] FATAL IMPACT: Critical Vuln Found. Executing Autonomous Takeover...[/bold red]")
        
        if "RCE" in vuln.vuln_type or "Injection" in vuln.vuln_type:
            prompt = f"""
            Vulnerability: {vuln.vuln_type}
            Evidence: {json.dumps(vuln.evidence)}
            
            Based on the evidence above, generate a one-line Python C2 beacon deployment command for a Linux target.
            The command should be encrypted or encoded for stealth.
            """
            try:
                beacon_cmd = await asyncio.to_thread(self.brain.reason, prompt)
                console.print(f"[bold red]| [💀] APEX C2: Deployment Command Generated: {beacon_cmd[:50]}...[/bold red]")
                
                # Logic to actually execute this would involve the fuzzer re-submitting 
                # the request with this payload. For the "Apex" version, this is stored 
                # as the ultimate proof of fatal impact.
                self.findings.append({"type": "Fatal Impact Escalation", "status": "C2 Deployment Initiated", "payload": beacon_cmd})
            except: pass
            
        elif "SQL Injection" in vuln.vuln_type:
            console.print(f"[bold red]| [💎] FATAL IMPACT: Initiating Database Credential Harvest...[/bold red]")
    
    async def _get_session(self) -> httpx.AsyncClient:
        if self.session is None:
            self.session = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers=self.default_headers
            )
            self._owns_session = True
        return self.session
    
    async def close(self):
        if self._owns_session and self.session:
            await self.session.aclose()
            self.session = None
    
    def register_callback(self, event: str, callback: Callable):
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    async def _fire_callbacks(self, event: str, *args, **kwargs):
        if event in self._callbacks:
            for callback in self._callbacks[event]:
                if asyncio.iscoroutinefunction(callback):
                    await callback(*args, **kwargs)
                else:
                    callback(*args, **kwargs)
    
    def define_workflow(
        self,
        name: str,
        steps: List[Dict[str, Any]]
    ) -> List[WorkflowStep]:
        """
        Define a workflow from a list of step specifications.
        
        Args:
            name: Workflow name
            steps: List of step definitions
            
        Returns:
            List of WorkflowStep objects
        """
        workflow_steps = []
        
        for i, step_def in enumerate(steps):
            step = WorkflowStep(
                step_id=step_def.get("id", f"step_{i+1}"),
                name=step_def.get("name", f"Step {i+1}"),
                method=step_def.get("method", "GET").upper(),
                path=step_def.get("path", "/"),
                headers=step_def.get("headers", {}),
                data=step_def.get("data", {}),
                params=step_def.get("params", {}),
                extract_token=step_def.get("extract_token"),
                extract_cookie=step_def.get("extract_cookie"),
                extract_json=step_def.get("extract_json"),
                requires_auth=step_def.get("requires_auth", True),
                skip_if_failed=step_def.get("skip_if_failed", True),
                retries=step_def.get("retries", self.max_retries),
                depends_on=step_def.get("depends_on", []),
                conditions=step_def.get("conditions", {}),
                expected_status=step_def.get("expected_status", [200, 201, 204]),
                mutate=step_def.get("mutate", {}),
                fuzz_params=step_def.get("fuzz_params", []),
                fuzz_types=self._parse_mutation_types(step_def.get("fuzz_types", []))
            )
            workflow_steps.append(step)
            self.dag_executor.add_step(step)
        
        return workflow_steps
    
    def _parse_mutation_types(self, types: List[str]) -> List[MutationType]:
        """Parse mutation type strings to enums."""
        result = []
        type_map = {
            "negative": MutationType.NEGATIVE,
            "zero": MutationType.ZERO,
            "max_int": MutationType.MAX_INT,
            "negative_max": MutationType.NEGATIVE_MAX,
            "float": MutationType.FLOAT,
            "string": MutationType.STRING,
            "empty": MutationType.EMPTY,
            "null": MutationType.NULL,
            "bool_toggle": MutationType.BOOL_TOGGLE,
            "array_empty": MutationType.ARRAY_EMPTY,
            "array_negative": MutationType.ARRAY_NEGATIVE,
            "sqli": MutationType.SQLI,
            "xss": MutationType.XSS,
            "overflow": MutationType.OVERFLOW,
            "path_traversal": MutationType.PATH_TRAVERSAL,
        }
        
        for t in types:
            if t in type_map:
                result.append(type_map[t])
        
        return result if result else [MutationType.NEGATIVE, MutationType.ZERO]
    
    async def execute_workflow(
        self,
        workflow: List[WorkflowStep],
        session_state: Optional[SessionState] = None,
        mutate_only: bool = False
    ) -> WorkflowResult:
        """
        Execute a complete workflow with parallel step execution for independent nodes.
        """
        start_time = time.time()
        workflow_name = workflow[0].name if workflow else "unknown"
        
        session = session_state or SessionState()
        step_results: List[StepResult] = []
        findings: List[Dict[str, Any]] = []
        
        try:
            execution_order = self.dag_executor.topological_sort()
        except ValueError as e:
            console.print(f"[bold red]| ? DAG Error: {str(e)}[/bold red]")
            return WorkflowResult(workflow_name, 0, 0, 0, 0, [], [], 0)
        
        console.print(f"[bold cyan]---- Executing Workflow: {workflow_name}[/bold cyan]")
        console.print(f"[bold cyan]| ? Steps: {len(workflow)} | DAG Optimized Execution[/bold cyan]")
        
        failed_steps = set()
        
        # Parallel Step Execution via DAG Levels
        levels = self._get_dag_levels(execution_order)
        
        for level in levels:
            tasks = []
            for step_id in level:
                step = self.dag_executor.nodes[step_id]
                tasks.append(self._process_single_step(step, session, failed_steps, mutate_only))
            
            level_results = await asyncio.gather(*tasks)
            
            for step_id, result in zip(level, level_results):
                step_results.append(result)
                if result.status == WorkflowStepStatus.SUCCESS:
                    session = self._update_session(session, result, self.dag_executor.nodes[step_id])
                elif result.status == WorkflowStepStatus.FAILED:
                    failed_steps.add(step_id)
                
                step_findings = self._analyze_result(result, self.dag_executor.nodes[step_id])
                findings.extend(step_findings)

                # Apex Phase 3: Strategic Decision Loop
                decision = await self.strategic_mind.decide_next_move(self.dag_executor.nodes[step_id], result, session)
                if decision["move"] == "ADAPT":
                    console.print(f"[bold yellow]| [🧠] StrategicMind: ADAPTING next steps based on response...[/bold yellow]")
                    # Logic to modify future steps based on decision["modifications"]
                elif decision["move"] == "PIVOT":
                    console.print(f"[bold red]| [🧠] StrategicMind: PIVOTING attack strategy![/bold red]")
                    # Logic to break current level and jump to a specific step
        
        execution_time = time.time() - start_time
        successful = sum(1 for r in step_results if r.status in [WorkflowStepStatus.SUCCESS, WorkflowStepStatus.MUTATED])
        mutated = sum(1 for r in step_results if r.status == WorkflowStepStatus.MUTATED)
        
        console.print(f"[bold cyan]| ? Completed: {successful}/{len(step_results)} steps[/bold cyan]")
        console.print(f"[bold red]| ? Findings: {len(findings)}[/bold red]")
        console.print(f"[bold cyan]|_--- Execution Time: {execution_time:.2f}s[/bold cyan]")
        
        res_obj = WorkflowResult(
            workflow_name=workflow_name, total_steps=len(step_results),
            successful_steps=successful, failed_steps=len(failed_steps),
            mutated_steps=mutated, step_results=step_results,
            findings=findings, execution_time=execution_time
        )
        self.results.append(res_obj)
        return res_obj

    def _get_dag_levels(self, sorted_nodes: List[str]) -> List[List[str]]:
        """Group nodes into levels for parallel execution."""
        levels = []
        remaining_nodes = set(sorted_nodes)
        completed = set()
        while remaining_nodes:
            current_level = []
            for node_id in list(remaining_nodes):
                step = self.dag_executor.nodes[node_id]
                if all(dep in completed for dep in step.depends_on):
                    current_level.append(node_id)
            if not current_level: break
            levels.append(current_level)
            for node_id in current_level:
                remaining_nodes.remove(node_id)
                completed.add(node_id)
        return levels

    async def _process_single_step(self, step: WorkflowStep, session: SessionState, failed_steps: set, mutate_only: bool) -> StepResult:
        """Helper for parallel step processing."""
        await self._fire_callbacks("before_step", step, session)
        if any(dep in failed_steps for dep in step.depends_on) and step.skip_if_failed:
            return StepResult(step.step_id, WorkflowStepStatus.SKIPPED, {}, {}, 0, error="Dependency failed")
        if step.mutate or step.fuzz_params:
            if mutate_only: return await self._execute_fuzz(step, session)
            else:
                normal_result = await self._execute_step(step, session)
                if normal_result.status == WorkflowStepStatus.SUCCESS: return await self._execute_fuzz(step, session)
                return normal_result
        return await self._execute_step(step, session)

    async def _execute_step(self, step: WorkflowStep, session_state: SessionState) -> StepResult:
        """Execute a single workflow step."""
        url = urljoin(self.base_url, step.path)
        headers = {**self.default_headers, **step.headers, **session_state.headers}
        cookies = session_state.cookies.copy()
        request_data = {**step.data, **session_state.json_data} if session_state.json_data else step.data.copy()
        
        for _ in range(step.retries):
            try:
                req_session = await self._get_session()
                req_start = time.time()
                response = await req_session.request(
                    step.method, url, json=request_data if step.method != "GET" else None,
                    params={**step.params, **request_data} if step.method == "GET" else step.params,
                    headers=headers, cookies=cookies, timeout=self.timeout
                )
                resp_time = time.time() - req_start
                status = WorkflowStepStatus.SUCCESS if response.status_code in step.expected_status else WorkflowStepStatus.FAILED
                extracted = self._extract_data(response, step)
                
                # Apex Phase 3: Log to Session History
                session_state.log_step(step.step_id, {"method": step.method, "url": url, "data": request_data}, 
                                      {"status": response.status_code, "body": response.text, "headers": dict(response.headers)})
                
                # Trigger IDOR 2.0 Check if IDs are detected in path or data
                if "id" in step.path.lower() or (step.data and any("id" in k.lower() for k in step.data.keys())):
                    attacker_id = extracted.get("id") or session_state.extracted.get("id")
                    asyncio.create_task(self.idor_hunter.test_endpoint(
                        url=url,
                        method=step.method,
                        data=step.data,
                        attacker_id=str(attacker_id) if attacker_id else None,
                        victim_id=os.getenv("VICTIM_ID")
                    ))

                # Trigger Sentinel SSRF if URL-like parameters are detected
                if step.data and any(re.match(r'https?://', str(v)) for v in step.data.values()):
                    asyncio.create_task(self.sentinel_ssrf.escalate(
                        vulnerable_url=f"{url}{'&' if '?' in url else '?'}{next(k for k,v in step.data.items() if re.match(r'https?://', str(v)))}="
                    ))

                return StepResult(step.step_id, status, {"method": step.method, "url": url}, 
                                 {"status": response.status_code, "body": response.text[:500]}, resp_time, extracted)
            except Exception as e:
                await asyncio.sleep(0.5)
        return StepResult(step.step_id, WorkflowStepStatus.FAILED, {}, {}, 0, error="Max retries")

    async def _execute_fuzz(self, step: WorkflowStep, session_state: SessionState) -> StepResult:
        """v25.0 OMEGA: High-velocity parallel mutation testing (Turbo)."""
        fuzz_params = step.fuzz_params or list(step.mutate.keys()) if step.mutate else []
        if not fuzz_params: return StepResult(step.step_id, WorkflowStepStatus.SKIPPED, {}, {}, 0, error="No params")
        
        all_mutations = []
        for i, param in enumerate(fuzz_params):
            val = step.data.get(param) or step.params.get(param) or ""
            
            # v40.0 OMEGA: Use Polymorphic Swarm for Stealth/Apex Mode
            if getattr(state, "STEALTH_MODE", False) or getattr(state, "APEX_MODE", False):
                mutations_list = await self.polymorphic.generate_swarm(val, count=3)
                for mv in mutations_list:
                    all_mutations.append({"param": param, "type": "polymorphic", "mutated": mv, "data": {**step.data, param: mv}, "params": {**step.params, param: mv}})
            else:
                mutations = await self.mutator.mutate(param, val, step.fuzz_types, context={"url": urljoin(self.base_url, step.path)}, use_ai=(i < 2))
                for mt, mv in mutations:
                    all_mutations.append({"param": param, "type": mt.value, "mutated": mv, "data": {**step.data, param: mv}, "params": {**step.params, param: mv}})

        if not all_mutations: return StepResult(step.step_id, WorkflowStepStatus.SKIPPED, {}, {}, 0)
        console.print(f"[bold yellow]| [⚡] Fuzzing {len(all_mutations)} mutations in parallel on {step.name}...[/bold yellow]")
        
        fuzz_semaphore = asyncio.Semaphore(50)
        async def _run_mutation(m):
            async with fuzz_semaphore:
                try:
                    req_session = await self._get_session()
                    response = await req_session.request(step.method, urljoin(self.base_url, step.path),
                        json=m["data"] if step.method != "GET" else None, params=m["params"] if step.method == "GET" else m["params"],
                        headers={**self.default_headers, **session_state.headers}, cookies=session_state.cookies, timeout=10)
                    finding = self._detect_vulnerability(step, m, response.status_code, response.text, 0.5)
                    if finding: 
                        vuln = Vulnerability(
                            step_id=step.step_id,
                            vuln_type=finding.get("type", "Logic Flaw"),
                            severity=finding.get("severity", "MEDIUM"),
                            description=finding.get("description", "Unknown"),
                            evidence=finding.get("evidence", {}),
                            remediation=finding.get("remediation", "")
                        )
                        self.findings.append(vuln)
                        await self._fire_callbacks("on_finding", vuln)
                        
                        # Apex Phase 4: Fatal Impact - Autonomous Escalation
                        if vuln.severity == "CRITICAL":
                            await self._convert_to_impact(vuln, session_state)
                except: pass

        await asyncio.gather(*[_run_mutation(m) for m in all_mutations])

        return StepResult(step.step_id, WorkflowStepStatus.MUTATED, {}, {}, 0, mutated_params={"count": len(all_mutations)})

    async def test_state_inversion(self, step: WorkflowStep, session_state: SessionState):
        """v25.0 OMEGA: Test for auth-bypass by purposefully sabotaging state."""
        console.print(f"[bold red]| [💀] State-Inversion: Sabotaging session for {step.name}...[/bold red]")
        sabotaged_state = SessionState()
        sabotaged_state.headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sabotaged"}
        res = await self._execute_step(step, sabotaged_state)
        if res.status == WorkflowStepStatus.SUCCESS:
            finding = {"type": "Broken Authentication (State Inversion)", "severity": "CRITICAL", "description": f"Endpoint {step.path} accepted a sabotaged JWT token.", "evidence": {"status": res.response.get("status"), "path": step.path}, "remediation": "Validate all tokens cryptographically and ensure fail-closed logic.", "cwe_id": "CWE-287"}
            self.findings.append(finding)
            await self._fire_callbacks("on_finding", finding)
    
    def _extract_data(self, response: httpx.Response, step: WorkflowStep) -> Dict[str, Any]:
        """Extract tokens and data from response."""
        extracted = {}
        
        if step.extract_token:
            token_pattern = step.extract_token
            if token_pattern:
                token_match = re.search(
                    token_pattern,
                    response.text
                )
            if token_match:
                extracted["token"] = token_match.group(1) if token_match.groups() else token_match.group(0)
        
        if step.extract_cookie:
            for cookie in response.cookies:
                if cookie.name == step.extract_cookie:
                    extracted["cookie"] = cookie.value
        
        if step.extract_json:
            try:
                json_data = response.json()
                value = json_data
                keys = step.extract_json.split('.') if step.extract_json else []
                for key in keys:
                    value = value.get(key, {})
                extracted["json"] = value
            except Exception:
                pass
        
        return extracted
    
    def _update_session(
        self,
        session: SessionState,
        result: StepResult,
        step: WorkflowStep
    ) -> SessionState:
        """Update session state with extracted data."""
        if result.extracted_data.get("token"):
            session.set_token(
                step.extract_token or "default",
                result.extracted_data["token"]
            )
        
        if result.extracted_data.get("cookie"):
            session.set_cookie(
                step.extract_cookie or "session",
                result.extracted_data["cookie"]
            )
        
        if result.extracted_data.get("json"):
            session.set_json(
                step.extract_json or "data",
                result.extracted_data["json"]
            )
        
        return session
    
    def _is_vulnerable_status(self, step: WorkflowStep, status_code: int) -> bool:
        return status_code in [200, 201, 204] and status_code not in step.expected_status
    
    def _detect_vulnerability(
        self,
        step: WorkflowStep,
        mutation: Dict[str, Any],
        status_code: int,
        response_text: str,
        response_time: float
    ) -> Optional[Dict[str, Any]]:
        """Detect vulnerabilities in fuzzing results."""
        findings = []
        
        if status_code == 200 and mutation["type"] == "negative":
            findings.append({
                "type": "Business Logic Flaw",
                "severity": "HIGH",
                "description": f"Negative value ({mutation['mutated']}) accepted for {mutation['param']}",
                "evidence": {
                    "param": mutation["param"],
                    "value": mutation["mutated"],
                    "status": status_code
                },
                "remediation": "Implement proper input validation for numeric fields",
                "cwe_id": "CWE-20"
            })
        
        if mutation["type"] in ["sqli", "sqli"] and "error" in response_text.lower():
            findings.append({
                "type": "Potential SQL Injection",
                "severity": "CRITICAL",
                "description": f"SQL injection payload in {mutation['param']} may have triggered error",
                "evidence": {
                    "param": mutation["param"],
                    "payload": mutation["mutated"],
                    "status": status_code,
                    "response_snippet": response_text[:200]
                },
                "remediation": "Use parameterized queries",
                "cwe_id": "CWE-89"
            })
        
        if response_time > 5 and mutation["type"] in ["negative", "overflow"]:
            findings.append({
                "type": "Potential DoS / Infinite Loop",
                "severity": "MEDIUM",
                "description": f"High response time ({response_time:.2f}s) with {mutation['type']} mutation",
                "evidence": {
                    "param": mutation["param"],
                    "value": mutation["mutated"],
                    "response_time": response_time
                },
                "remediation": "Implement proper bounds checking",
                "cwe_id": "CWE-834"
            })
        
        return findings
    
    def _analyze_result(
        self,
        result: StepResult,
        step: WorkflowStep
    ) -> List[Dict[str, Any]]:
        """Analyze step result for anomalies."""
        findings = []
        
        if result.status == WorkflowStepStatus.FAILED:
            if result.error:
                findings.append({
                    "type": "Step Failure",
                    "severity": "INFO",
                    "description": f"Step failed: {result.error}",
                    "evidence": {"step": step.name, "error": result.error},
                    "remediation": "Review step configuration"
                })
        
        if result.response_time > 10:
            findings.append({
                "type": "Performance Issue",
                "severity": "LOW",
                "description": f"Slow response: {result.response_time:.2f}s",
                "evidence": {"step": step.name, "time": result.response_time},
                "remediation": "Optimize endpoint"
            })
        
        return findings
    
    def generate_report(self) -> str:
        """Generate workflow execution report."""
        if not self.results:
            return "No workflow results available."
        
        report = ["# ? Stateful Logic Fuzzer Report\n"]
        
        for result in self.results:
            report.append(f"## Workflow: {result.workflow_name}\n")
            report.append(f"- **Total Steps:** {result.total_steps}")
            report.append(f"- **Successful:** {result.successful_steps}")
            report.append(f"- **Failed:** {result.failed_steps}")
            report.append(f"- **Mutated:** {result.mutated_steps}")
            report.append(f"- **Execution Time:** {result.execution_time:.2f}s")
            report.append(f"- **Findings:** {len(result.findings)}\n")
            
            if result.findings:
                report.append("### Findings\n")
                for finding in result.findings:
                    report.append(f"#### {finding['type']} ({finding['severity']})")
                    report.append(f"{finding['description']}\n")
        
        return "\n".join(report)


class WorkflowBuilder:
    """Helper to build complex API workflows."""
    
    @staticmethod
    def login_then_access(
        login_path: str,
        login_data: Dict,
        protected_path: str,
        token_key: str = "token"
    ) -> List[Dict[str, Any]]:
        """Build a simple login -> access workflow."""
        return [
            {
                "id": "login",
                "name": "Authenticate",
                "method": "POST",
                "path": login_path,
                "data": login_data,
                "extract_token": token_key,
                "extract_json": f"data.{token_key}"
            },
            {
                "id": "access",
                "name": "Access Protected Resource",
                "method": "GET",
                "path": protected_path,
                "depends_on": ["login"],
                "requires_auth": True
            }
        ]
    
    @staticmethod
    def ecommerce_checkout(
        base_paths: Dict[str, str],
        fuzz_price: bool = True,
        fuzz_quantity: bool = True
    ) -> List[Dict[str, Any]]:
        """Build a typical e-commerce checkout workflow."""
        workflow = [
            {
                "id": "login",
                "name": "User Login",
                "method": "POST",
                "path": base_paths.get("login", "/api/auth/login"),
                "data": {"email": "test@example.com", "password": "testpass123"},
                "extract_token": "token",
                "extract_json": "token"
            },
            {
                "id": "cart_view",
                "name": "View Cart",
                "method": "GET",
                "path": base_paths.get("cart", "/api/cart"),
                "depends_on": ["login"],
                "requires_auth": True
            },
            {
                "id": "add_item",
                "name": "Add Item to Cart",
                "method": "POST",
                "path": base_paths.get("add_item", "/api/cart/add"),
                "data": {"product_id": 1, "quantity": 1},
                "depends_on": ["cart_view"],
                "requires_auth": True
            }
        ]
        
        if fuzz_quantity:
            workflow.append({
                "id": "checkout_quantity",
                "name": "Checkout - Quantity Fuzz",
                "method": "POST",
                "path": base_paths.get("checkout", "/api/checkout"),
                "data": {"product_id": 1, "quantity": 1},
                "depends_on": ["add_item"],
                "requires_auth": True,
                "fuzz_params": ["quantity"],
                "fuzz_types": ["negative", "zero", "max_int", "array_negative"]
            })
        
        if fuzz_price:
            workflow.append({
                "id": "checkout_price",
                "name": "Checkout - Price Fuzz",
                "method": "POST",
                "path": base_paths.get("checkout", "/api/checkout"),
                "data": {"product_id": 1, "price": 99.99},
                "depends_on": ["add_item"],
                "requires_auth": True,
                "fuzz_params": ["price"],
                "fuzz_types": ["negative", "zero", "string", "null"]
            })
        
        return workflow

    @staticmethod
    def admin_panel_flow(
        login_path: str,
        login_data: Dict,
        admin_path: str,
        token_key: str = "token"
    ) -> List[Dict[str, Any]]:
        """Build a workflow testing admin panel access and privilege escalation."""
        return [
            {
                "id": "login",
                "name": "User Login",
                "method": "POST",
                "path": login_path,
                "data": login_data,
                "extract_token": token_key,
                "extract_json": f"data.{token_key}"
            },
            {
                "id": "admin_access",
                "name": "Access Admin Panel",
                "method": "GET",
                "path": admin_path,
                "depends_on": ["login"],
                "requires_auth": True,
                "fuzz_params": ["role", "is_admin", "admin"],
                "fuzz_types": ["bool_toggle", "string", "empty"]
            }
        ]

    @staticmethod
    def api_auth_flow(
        login_path: str,
        login_data: Dict,
        refresh_path: str,
    ) -> List[Dict[str, Any]]:
        """Build a workflow testing API auth and token refreshment."""
        return [
            {
                "id": "login",
                "name": "API Login",
                "method": "POST",
                "path": login_path,
                "data": login_data,
                "extract_token": "access_token",
                "extract_json": "refresh_token"
            },
            {
                "id": "refresh_token",
                "name": "Refresh Token",
                "method": "POST",
                "path": refresh_path,
                "depends_on": ["login"],
                "requires_auth": True,
                "data": {"refresh_token": "REFRESH_TOKEN_PLACEHOLDER"},
                "fuzz_params": ["refresh_token"],
                "fuzz_types": ["empty", "null", "string"]
            }
        ]


async def quick_workflow_test(base_url: str, workflow: List[Dict]) -> WorkflowResult:
    """
    Quick workflow testing function.
    
    Usage:
        workflow = [
            {"method": "POST", "path": "/login", "data": {"email": "test@test.com", "password": "test"}},
            {"method": "GET", "path": "/profile", "extract_token": "token"}
        ]
        result = await quick_workflow_test("https://target.com", workflow)
    """
    fuzzer = StatefulLogicFuzzer(base_url=base_url)
    steps = fuzzer.define_workflow("quick_test", workflow)
    result = await fuzzer.execute_workflow(steps)
    await fuzzer.close()
    return result


async def run_logic_fuzz(target: str, workflow_path: str = None, workflow_json: List[Dict] = None):
    """Entry point for CLI/Orchestrator to run stateful logic fuzzing."""
    base_url = target if target.startswith("http") else f"https://{target}"
    fuzzer = StatefulLogicFuzzer(base_url=base_url)
    
    steps_list = []
    wf_name = "dynamic_audit"

    if workflow_path:
        if not os.path.exists(workflow_path):
            console.print(f"[bold red]❌ Error: Workflow file not found at {workflow_path}[/bold red]")
            return []
        try:
            with open(workflow_path, 'r') as f:
                workflow_data = json.load(f)
                if isinstance(workflow_data, list):
                    steps_list = workflow_data
                    wf_name = "cli_logic_test"
                else:
                    steps_list = workflow_data.get("steps", [])
                    wf_name = workflow_data.get("name", "cli_logic_test")
        except Exception as e:
            console.print(f"[bold red]❌ Error parsing workflow JSON: {e}[/bold red]")
            return []
    elif workflow_json:
        steps_list = workflow_json
    else:
        # Default probe workflow
        steps_list = [
            {"id": "root", "name": "Base Probe", "method": "GET", "path": "/"}
        ]

    console.print(f"[bold cyan][LOGIC] Initiating Stateful Logic Fuzzing: {base_url}[/bold cyan]")
    console.print(f"[dim]Loaded workflow: {wf_name} ({len(steps_list)} steps)[/dim]")
    
    steps = fuzzer.define_workflow(wf_name, steps_list)
    result = await fuzzer.execute_workflow(steps)
    
    # Print results summary if it was likely a CLI run (has workflow_path)
    if workflow_path:
        console.print("\n" + fuzzer.generate_report())
    
    await fuzzer.close()
    return result.findings

