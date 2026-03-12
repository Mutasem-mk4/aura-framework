import asyncio
import os
import shutil
import subprocess
import random
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich import box
from aura.ui.zenith_ui import ZenithUI
import time

console = Console()

class Web3Engine:
    """v33.0 Phase 33: Web3 Smart Contract Auditing Engine (Optimized)"""
    
    def __init__(self, workspace_dir="aura_workspace"):
        self.workspace_dir = Path(os.getcwd()) / workspace_dir
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        from aura.core.storage import AuraStorage
        self.db = AuraStorage()

    def _parse_target_url(self, target: str) -> tuple[str, str]:
        repo_url = target
        sub_path = ""
        if not target.startswith("http") and not target.endswith(".git") and not os.path.exists(target):
            if "/" in target and "github.com" not in target:
                repo_url = f"https://github.com/{target}.git"
        if "/tree/" in repo_url:
            parts = repo_url.split("/tree/")
            repo_url = parts[0]
            if not repo_url.endswith(".git"):
                repo_url += ".git"
            path_parts = parts[1].split("/", 1)
            if len(path_parts) > 1:
                sub_path = path_parts[1]
        return repo_url, sub_path

    async def clone_repository(self, repo_url: str) -> Path | None:
        try:
            parsed = urlparse(repo_url)
            timestamp = int(time.time())
            dir_name = parsed.path.strip("/").replace("/", "_").replace(".git", "") + f"_{timestamp}"
            repo_path = self.workspace_dir / dir_name
            if repo_path.exists():
                shutil.rmtree(repo_path, ignore_errors=True)
            console.print(f"[cyan]Cloning repository {repo_url}...[/cyan]")
            process = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", repo_url, str(repo_path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            if not (repo_path / ".git").exists():
                console.print(f"[bold red]❌ Failed to clone repository.[/bold red]")
                return None
            console.print(f"[bold green]✅ Repository cloned.[/bold green]")
            return repo_path
        except Exception as e:
            console.print(f"[bold red]❌ Error during cloning: {e}[/bold red]")
            return None

    async def analyze_smart_contracts(self, repo_path: Path):
        console.print(f"[cyan]Scanning {repo_path} for Smart Contracts...[/cyan]")
        contract_files = []
        for ext in ["*.sol", "*.rs"]:
            for path in repo_path.rglob(ext):
                if path.is_file():
                    contract_files.append(path)
        if not contract_files:
            console.print("[yellow]⚠️ No Smart Contracts found.[/yellow]")
            return
        console.print(f"[bold green]🔎 Found {len(contract_files)} files. Initiating Batch AI Audit...[/bold green]")
        await self._run_batch_audit(contract_files)

    async def _run_batch_audit(self, files: list[Path], batch_size: int = 5):
        """Phase 3: Contextual Batch Auditing with Sliding Window for Large Files."""
        target_name = files[0].parent.name if files else "SmartContract"
        
        system_prompt = (
            "You are an elite Web3 Smart Contract Auditor.\n"
            "Analyze the following BATCH of files (or file chunks) for Critical vulnerabilities:\n"
            "1. Stealing or loss of funds\n"
            "2. Stealing or misuse of identity\n"
            "3. Unauthorized transaction & Transaction manipulation\n"
            "4. Attacks on logic\n"
            "5. Reentrancy & Reordering\n"
            "If you find a valid High/Critical vulnerability, output a JSON object per file/chunk exactly like this:\n"
            "{\"file\": \"filename.sol\", \"type\": \"Vuln Type\", \"severity\": \"CRITICAL\", \"content\": \"...\"}\n"
            "If no severe vulnerabilities are found, output an empty JSON array []."
        )

        processed_files = []
        for f in files:
            content = f.read_text(encoding='utf-8')
            # Sliding Window Chunking: If file > 20k chars, split into 20k chunks with 5k overlap
            chunk_size = 20000
            overlap = 5000
            
            if len(content) <= chunk_size:
                processed_files.append((f.name, content))
            else:
                console.print(f"[dim]Chunking large file: {f.name} ({len(content)} chars)[/dim]")
                for start in range(0, len(content), chunk_size - overlap):
                    chunk = content[start:start + chunk_size]
                    chunk_name = f"{f.name} (Part {start//(chunk_size-overlap) + 1})"
                    processed_files.append((chunk_name, chunk))
                    if start + chunk_size >= len(content): break

        for i in range(0, len(processed_files), batch_size):
            batch = processed_files[i:i + batch_size]
            
            with ZenithUI.status(f"Auditing Batch {i//batch_size + 1} ({len(batch)} chunks/files)..."):
                combined_code = ""
                for name, code in batch:
                    combined_code += f"\n\n--- FILE/CHUNK: {name} ---\n{code}"

                full_prompt = f"{system_prompt}\n\nBatch Code:\n{combined_code}"
                prompt_file = Path(os.getcwd()) / f"batch_prompt_{int(time.time())}.txt"
                prompt_file.write_text(full_prompt, encoding="utf-8")

                try:
                    process = await asyncio.create_subprocess_exec(
                        "cmd.exe", "/c", f"type \"{prompt_file}\" | gemini --prompt \"\"",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await process.communicate()
                    
                    if process.returncode == 0:
                        output = stdout.decode('utf-8').strip()
                        if output and "[]" not in output and "{" in output:
                            ZenithUI.finding("Smart Contract Vulnerability", "CRITICAL", target_name)
                            self.db.add_finding(target_name, output, "Batch AI Web3 Audit", "CRITICAL")
                            
                            # Phase 4: PoC Synthesizer
                            poc_test_result = await self._generate_poc(output, combined_code)
                            if poc_test_result:
                                console.print(f"[bold green]✅ PoC Synthesizer: Exploit Confirmed by Foundry.[/bold green]")
                                self.db.add_finding(target_name, poc_test_result, "PoC Synthesizer (Foundry)", "CONFIRMED_VULNERABLE")
                        else:
                            console.print(f"[dim green]✅ Batch {i//batch_size + 1}: Secure[/dim green]")
                    else:
                        console.print(f"[yellow]⚠️ Batch {i//batch_size + 1} failed query.[/yellow]")
                finally:
                    if prompt_file.exists(): prompt_file.unlink()

        console.print("[bold green]🏁 Web3 Batch Audit Complete.[/bold green]")

    async def _generate_poc(self, finding_json: str, vulnerable_code: str) -> str | None:
        """Phase 4: Uses Gemini to write a Foundry Test PoC and executes it"""
        console.print("[cyan]🔬 Initializing PoC Synthesizer (Foundry)...[/cyan]")
        poc_prompt = (
            "You are an elite Exploit Developer. Given the following vulnerable Solidity code and the vulnerability description, "
            "write a standalone Foundry test (`contract ExploitTest is Test`) that exploits the vulnerability and results in a successful test execution "
            "(e.g., stealing funds, bypassing access). Output ONLY the raw Solidity test code, no markdown block quotes, no explanations. "
            f"Vulnerability Finding:\n{finding_json}\n\nVulnerable Code:\n{vulnerable_code}"
        )
        
        prompt_file = Path(os.getcwd()) / f"poc_prompt_{int(time.time())}.txt"
        prompt_file.write_text(poc_prompt, encoding="utf-8")
        
        try:
            # 1. Ask Gemini to generate the PoC
            process = await asyncio.create_subprocess_exec(
                "cmd.exe", "/c", f"type \"{prompt_file}\" | gemini --prompt \"\"",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                poc_code = stdout.decode('utf-8').strip()
                if poc_code:
                    # Clean up random markdown wrapping if Gemini didn't listen
                    if poc_code.startswith("```solidity"):
                        poc_code = poc_code.split("```solidity")[1].rsplit("```", 1)[0].strip()
                    elif poc_code.startswith("```"):
                        poc_code = poc_code.split("```")[1].rsplit("```", 1)[0].strip()

                    # 2. Setup Temporary Foundry Environment
                    poc_dir = self.workspace_dir / f"poc_env_{int(time.time())}"
                    poc_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Ensure it's a valid forge project
                    init_process = await asyncio.create_subprocess_exec(
                        "forge", "init", "--force", "--no-commit", str(poc_dir),
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    await init_process.communicate()

                    test_file = poc_dir / "test" / "Exploit.t.sol"
                    test_file.write_text(poc_code, encoding="utf-8")
                    
                    console.print(f"[cyan]⚔️ Executing synthesized PoC via forge test...[/cyan]")
                    # 3. Execute the PoC
                    test_process = await asyncio.create_subprocess_exec(
                        "forge", "test", "--match-path", "test/Exploit.t.sol",
                        cwd=str(poc_dir),
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    test_stdout, test_stderr = await test_process.communicate()
                    
                    output = test_stdout.decode('utf-8')
                    # Cleanup the temporary foundry env
                    shutil.rmtree(poc_dir, ignore_errors=True)

                    if "Test result: ok" in output or "[PASS]" in output:
                        return f"PoC Execution Successful:\n\nTest Output:\n{output}\n\nExploit Code:\n{poc_code}"
                    else:
                        console.print("[yellow]⚠️ PoC Synthesizer generated an invalid or failing exploit.[/yellow]")
                        return None
            return None
        except Exception as e:
            console.print(f"[red]❌ PoC Generator Error: {e}[/red]")
            return None
        finally:
            if prompt_file.exists(): prompt_file.unlink()

async def run_web3_audit(target: str):
    ZenithUI.banner("AURA OMNI — Web3 Engine", "Phase 33 Smart Contract Auditor")
    engine = Web3Engine()
    if os.path.isdir(target):
        repo_path = Path(target)
    else:
        repo_url, sub_path = engine._parse_target_url(target)
        cloned_path = await engine.clone_repository(repo_url)
        repo_path = cloned_path / sub_path if cloned_path and sub_path else cloned_path
    if not repo_path or not repo_path.exists():
        console.print("[bold red]Mission Aborted.[/bold red]")
        return
    await engine.analyze_smart_contracts(repo_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1: asyncio.run(run_web3_audit(sys.argv[1]))
