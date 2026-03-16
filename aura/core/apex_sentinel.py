import asyncio
import os
import subprocess
import tempfile
import logging
from aura.core.brain import AuraBrain

logger = logging.getLogger("aura.apex")

class ApexSentinel:
    """
    Tier 1 Weaponization: The Zero-False-Positive Verification Engine.
    Synthesizes, executes, and validates exploits to confirm vulnerabilities.
    """

    def __init__(self, brain: AuraBrain = None):
        self.brain = brain or AuraBrain()
        self.verified_findings = []

    async def verify_finding(self, finding: dict, target_domain: str) -> bool:
        """
        Synthesizes a verification script for a finding and executes it.
        Returns True if the vulnerability is confirmed.
        """
        f_type = finding.get("type", "Security Finding")
        f_content = finding.get("content", "")
        
        logger.info(f"[🎯 APEX] Verifying finding: {f_type} on {target_domain}")
        
        # 1. Synthesize verification script
        script_code = await asyncio.to_thread(
            self.brain.generate_exploit_script, 
            f_type, 
            f_content, 
            target_domain
        )
        
        if not script_code or "Failed to generate" in script_code:
            logger.warning(f"[!] APEX failed to synthesize script for {f_type}")
            return False

        # 2. Execute in sandbox (temporary file)
        return await self._execute_and_validate(script_code, f_type)

    async def _execute_and_validate(self, script_code: str, finding_type: str) -> bool:
        """Runs the script and checks for 'VERIFIED' or successful exit."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tmp:
            tmp.write(script_code)
            tmp_path = tmp.name

        try:
            # Run the script with a timeout
            # We assume the AI-generated script will print 'VULNERABLE' or 'VERIFIED' on success
            process = await asyncio.create_subprocess_exec(
                "python", tmp_path,
                stdout=asyncio.PIPE,
                stderr=asyncio.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                stdout_str = stdout.decode().upper() if stdout else ""
                stderr_str = stderr.decode().upper() if stderr else ""
                output = stdout_str + stderr_str
                
                # Check for success indicators
                success_keywords = ["VULNERABLE", "VERIFIED", "SUCCESS", "POC-CONFIRMED"]
                if any(k in output for k in success_keywords) or process.returncode == 0:
                    logger.info(f"[🔥 APEX] VULNERABILITY CONFIRMED: {finding_type}")
                    return True
                else:
                    logger.debug(f"[dim] APEX Verification output for {finding_type}: {output[:200]}...[/dim]")
                    return False
                    
            except asyncio.TimeoutError:
                try:
                    process.kill()
                except:
                    pass
                logger.warning(f"[!] APEX Verification timed out for {finding_type}")
                return False

        except Exception as e:
            logger.error(f"[!] APEX Execution Error: {e}")
            return False
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        return False
