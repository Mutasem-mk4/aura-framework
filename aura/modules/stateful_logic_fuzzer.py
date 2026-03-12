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

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.tree import Tree
import httpx

console = Console(force_terminal=True)


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
    
    def set_token(self, key: str, value: str):
        self.tokens[key] = value
        self.headers["Authorization"] = f"Bearer {value}"
    
    def set_cookie(self, key: str, value: str):
        self.cookies[key] = value
    
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


class ParameterMutator:
    """v38.0: OMEGA Sentient: Context-Aware Morphic Payload Engine."""
    
    def __init__(self, brain=None):
        from aura.core.brain import AuraBrain
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
    
    async def mutate(self, param_name: str, original_value: Any, mutation_types: List[MutationType], context: Dict[str, Any] = None) -> List[Tuple[MutationType, Any]]:
        """v38.0: Real-time dynamic payload generation via AuraBrain."""
        mutations = []
        
        if context and self.brain:
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
        queue = [node for node, degree in self.in_degree.items() if degree == 0]
        result = []
        
        while queue:
            node = queue.pop(0)
            result.append(node)
            
            for neighbor in self.graph[node]:
                self.in_degree[neighbor] -= 1
                if self.in_degree[neighbor] == 0:
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
        Execute a complete workflow.
        
        Args:
            workflow: List of workflow steps
            session_state: Initial session state
            mutate_only: If True, skip normal execution and only fuzz
            
        Returns:
            WorkflowResult with all findings
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
        console.print(f"[bold cyan]| ? Steps: {len(workflow)} | Execution Order: {execution_order}[/bold cyan]")
        
        failed_steps = set()
        
        for step_id in execution_order:
            step = self.dag_executor.nodes[step_id]
            
            await self._fire_callbacks("before_step", step, session)
            
            if step_id in failed_steps and step.skip_if_failed:
                result = StepResult(
                    step_id=step_id,
                    status=WorkflowStepStatus.SKIPPED,
                    request={},
                    response={},
                    response_time=0,
                    error="Previous step failed"
                )
                step_results.append(result)
                console.print(f"[dim]| ? Skipped: {step.name} (previous failure)[/dim]")
                continue
            
            if step.mutate or step.fuzz_params:
                if mutate_only:
                    result = await self._execute_fuzz(step, session)
                else:
                    normal_result = await self._execute_step(step, session)
                    step_results.append(normal_result)
                    
                    if normal_result.status == WorkflowStepStatus.SUCCESS:
                        result = await self._execute_fuzz(step, session)
                    else:
                        result = StepResult(
                            step_id=step_id,
                            status=WorkflowStepStatus.SKIPPED,
                            request={},
                            response={},
                            response_time=0,
                            error="Skipped fuzzing due to step failure"
                        )
            else:
                result = await self._execute_step(step, session)
            
            step_results.append(result)
            
            if result.status == WorkflowStepStatus.SUCCESS:
                session = self._update_session(session, result, step)
            elif result.status == WorkflowStepStatus.FAILED:
                failed_steps.add(step_id)
            
            step_findings = self._analyze_result(result, step)
            findings.extend(step_findings)
            
            await self._fire_callbacks("after_step", step, result, session)
            
            await asyncio.sleep(self.rate_limit_delay)
        
        execution_time = time.time() - start_time
        
        successful = sum(1 for r in step_results if r.status == WorkflowStepStatus.SUCCESS)
        mutated = sum(1 for r in step_results if r.status == WorkflowStepStatus.MUTATED)
        
        console.print(f"[bold cyan]| ? Completed: {successful}/{len(step_results)} steps[/bold cyan]")
        console.print(f"[bold red]| ? Findings: {len(findings)}[/bold red]")
        console.print(f"[bold cyan]|_--- Execution Time: {execution_time:.2f}s[/bold cyan]")
        
        result = WorkflowResult(
            workflow_name=workflow_name,
            total_steps=len(step_results),
            successful_steps=successful,
            failed_steps=len(failed_steps),
            mutated_steps=mutated,
            step_results=step_results,
            findings=findings,
            execution_time=execution_time
        )
        
        self.results.append(result)
        return result
    
    async def _execute_step(
        self,
        step: WorkflowStep,
        session_state: SessionState
    ) -> StepResult:
        """Execute a single workflow step."""
        url = urljoin(self.base_url, step.path)
        
        headers = {**self.default_headers, **step.headers}
        if session_state.headers:
            headers.update(session_state.headers)
        
        cookies = session_state.cookies.copy()
        
        request_data = step.data.copy()
        if session_state.json_data:
            for key, value in session_state.json_data.items():
                if key in request_data:
                    request_data[key] = value
        
        for _ in range(step.retries):
            try:
                req_session = await self._get_session()
                
                req_start = time.time()
                
                if step.method == "GET":
                    response = await req_session.get(
                        url,
                        params={**step.params, **request_data},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.timeout
                    )
                elif step.method == "POST":
                    response = await req_session.post(
                        url,
                        json=request_data if request_data else None,
                        params=step.params,
                        headers=headers,
                        cookies=cookies,
                        timeout=self.timeout
                    )
                elif step.method == "PUT":
                    response = await req_session.put(
                        url,
                        json=request_data,
                        params=step.params,
                        headers=headers,
                        cookies=cookies,
                        timeout=self.timeout
                    )
                elif step.method == "DELETE":
                    response = await req_session.delete(
                        url,
                        json=request_data,
                        params=step.params,
                        headers=headers,
                        cookies=cookies,
                        timeout=self.timeout
                    )
                elif step.method == "PATCH":
                    response = await req_session.patch(
                        url,
                        json=request_data,
                        params=step.params,
                        headers=headers,
                        cookies=cookies,
                        timeout=self.timeout
                    )
                else:
                    response = await req_session.request(
                        step.method,
                        url,
                        json=request_data,
                        params=step.params,
                        headers=headers,
                        cookies=cookies,
                        timeout=self.timeout
                    )
                
                resp_time = time.time() - req_start
                
                status = WorkflowStepStatus.SUCCESS if response.status_code in step.expected_status else WorkflowStepStatus.FAILED
                
                extracted = self._extract_data(response, step)
                
                return StepResult(
                    step_id=step.step_id,
                    status=status,
                    request={"method": step.method, "url": url, "data": request_data},
                    response={
                        "status": response.status_code,
                        "headers": dict(response.headers),
                        "body": response.text[:1000]
                    },
                    response_time=resp_time,
                    extracted_data=extracted
                )
                
            except asyncio.TimeoutError:
                await asyncio.sleep(1)
                continue
            except Exception as e:
                return StepResult(
                    step_id=step.step_id,
                    status=WorkflowStepStatus.FAILED,
                    request={"method": step.method, "url": url},
                    response={},
                    response_time=0,
                    error=str(e)
                )
        
        return StepResult(
            step_id=step.step_id,
            status=WorkflowStepStatus.FAILED,
            request={},
            response={},
            response_time=0,
            error="Max retries exceeded"
        )
    
    async def _execute_fuzz(
        self,
        step: WorkflowStep,
        session_state: SessionState
    ) -> StepResult:
        """v25.0 OMEGA: High-velocity parallel mutation testing."""
        fuzz_params = step.fuzz_params or list(step.mutate.keys())
        
        if not fuzz_params:
            return StepResult(
                step_id=step.step_id,
                status=WorkflowStepStatus.SKIPPED,
                request={},
                response={},
                response_time=0,
                error="No parameters to fuzz"
            )
        
        original_data = step.data.copy()
        original_params = step.params.copy()
        all_mutations = []
        
        for param in fuzz_params:
            original_value = original_data.get(param) or original_params.get(param) or ""
            
            # Prepare context for Sentient Mutation
            context = {
                "url": urljoin(self.base_url, step.path),
                "prev_response_summary": step.data.get("__prev_response") # If available
            }
            
            mutations = await self.mutator.mutate(param, original_value, step.fuzz_types, context=context)
            for mut_type, mut_value in mutations:
                all_mutations.append({
                    "param": param, "type": mut_type.value, "mutated": mut_value,
                    "data": {**original_data, param: mut_value},
                    "params": {**original_params, param: mut_value}
                })

        if not all_mutations:
            return StepResult(step.step_id, WorkflowStepStatus.SKIPPED, {}, {}, 0, error="No valid mutations")

        console.print(f"[bold yellow]| [⚡] Fuzzing {len(all_mutations)} mutations in parallel on {step.name}...[/bold yellow]")
        
        # Parallel Execution with Rate Limiting
        fuzz_semaphore = asyncio.Semaphore(10)
        
        async def _run_mutation(mutation):
            async with fuzz_semaphore:
                url = urljoin(self.base_url, step.path)
                headers = {**self.default_headers, **session_state.headers, **step.headers}
                try:
                    req_session = await self._get_session()
                    req_start = time.time()
                    response = await req_session.request(
                        step.method, url,
                        json=mutation["data"] if step.method != "GET" else None,
                        params=mutation["params"] if step.method == "GET" else None,
                        headers=headers, cookies=session_state.cookies, timeout=self.timeout
                    )
                    resp_time = time.time() - req_start
                    
                    finding = self._detect_vulnerability(step, mutation, response.status_code, response.text, resp_time)
                    if finding:
                        self.findings.append(finding)
                        await self._fire_callbacks("on_finding", finding)
                    
                    return StepResult(
                        step_id=step.step_id,
                        status=WorkflowStepStatus.MUTATED,
                        request={"method": step.method, "url": url, "mutation": mutation},
                        response={"status": response.status_code, "body": response.text[:500]},
                        response_time=resp_time,
                        mutated_params={mutation["param"]: mutation["mutated"]}
                    )
                except Exception: return None

        fuzz_results = await asyncio.gather(*[_run_mutation(m) for m in all_mutations])
        valid_results = [r for r in fuzz_results if r]
        
        # Prioritize results that triggered findings or non-expected status codes
        for r in valid_results:
            if r.response.get("status") not in step.expected_status:
                return r
        
        return valid_results[0] if valid_results else StepResult(step.step_id, WorkflowStepStatus.FAILED, {}, {}, 0, error="All fuzz attempts failed")

    async def test_state_inversion(self, step: WorkflowStep, session_state: SessionState):
        """v25.0 OMEGA: Test for auth-bypass by purposefully sabotaging state."""
        console.print(f"[bold red]| [💀] State-Inversion: Sabotaging session for {step.name}...[/bold red]")
        sabotaged_state = SessionState()
        # Common sabotage: Corrupted JWT
        sabotaged_state.headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sabotaged"}
        
        res = await self._execute_step(step, sabotaged_state)
        if res.status == WorkflowStepStatus.SUCCESS:
            finding = {
                "type": "Broken Authentication (State Inversion)",
                "severity": "CRITICAL",
                "description": f"Endpoint {step.path} accepted a sabotaged JWT token.",
                "evidence": {"status": res.response.get("status"), "path": step.path},
                "remediation": "Validate all tokens cryptographically and ensure fail-closed logic.",
                "cwe_id": "CWE-287"
            }
            self.findings.append(finding)
            await self._fire_callbacks("on_finding", finding)
    
    def _extract_data(self, response: httpx.Response, step: WorkflowStep) -> Dict[str, Any]:
        """Extract tokens and data from response."""
        extracted = {}
        
        if step.extract_token:
            token_match = re.search(
                step.extract_token,
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
                for key in step.extract_json.split('.'):
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
        
        return findings[0] if findings else None
    
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


if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) < 3:
            console.print("[bold red]Usage: python -m aura.modules.stateful_logic_fuzzer <base_url> <workflow_json>[/bold red]")
            sys.exit(1)
        
        base_url = sys.argv[1]
        
        with open(sys.argv[2], 'r') as f:
            workflow_def = json.load(f)
        
        fuzzer = StatefulLogicFuzzer(base_url=base_url)
        steps = fuzzer.define_workflow(workflow_def.get("name", "test"), workflow_def.get("steps", []))
        result = await fuzzer.execute_workflow(steps)
        
        console.print(f"\n[bold cyan]Report:[/bold cyan]\n{fuzzer.generate_report()}")
        
        await fuzzer.close()
    
    asyncio.run(main())
