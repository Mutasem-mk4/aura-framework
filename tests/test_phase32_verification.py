import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from aura.core.orchestrator import NeuralOrchestrator
from aura.core import state

async def test_phase32_integration():
    """Verifies that Phase 32 submission logic is triggered in NeuralOrchestrator."""
    
    # 1. Setup Orchestrator with Mocks
    # Mocking the database connection before initialization to avoid OperationalError
    with patch('sqlite3.connect') as mock_connect:
        orchestrator = NeuralOrchestrator()
        orchestrator.db = MagicMock()
        orchestrator.db.normalize_target.side_effect = lambda x: x
        orchestrator.profit_engine = MagicMock()
        orchestrator.submitter = MagicMock()
        orchestrator.submitter.submit = AsyncMock(return_value={"success": True, "id": "TEST-123"})
        
        # Mock OAST
        orchestrator.dast.oast = MagicMock()
        orchestrator.dast.oast.uuid = None
        
        # 2. Mock findings in DB
        mock_finding = {
            "type": "SQL Injection",
            "severity": "CRITICAL",
            "content": "Test SQLi finding",
            "impact_desc": "High impact",
            "confirmed": True
        }
        orchestrator.db.get_findings_by_target.return_value = [mock_finding]
        
        # 3. Enable Auto-Submit
        state.AUTO_SUBMIT = True
        
        # 4. Mock heavy/network methods
        patches = [
            patch.object(orchestrator, 'activate_sentient_mode', new_callable=AsyncMock),
            patch.object(orchestrator, '_oast_polling_loop', new_callable=AsyncMock),
            patch.object(orchestrator, '_memory_watchdog', new_callable=AsyncMock),
            patch.object(orchestrator.intel, 'query_shodan', return_value={}),
            patch.object(orchestrator.intel, 'query_virustotal', return_value={}),
            patch.object(orchestrator.intel, 'query_otx', return_value={}),
            patch.object(orchestrator.intel, 'query_securitytrails', return_value={}),
            patch.object(orchestrator.intel, 'query_censys', return_value={}),
            patch.object(orchestrator.intel, 'query_greynoise', return_value={}),
            patch.object(orchestrator.dorks_intel, 'run_dorks', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.cloud_recon, 'hunt', new_callable=AsyncMock),
            patch.object(orchestrator.oast, 'initialize', new_callable=AsyncMock),
            patch.object(orchestrator.session, 'get', new_callable=AsyncMock),
            patch.object(orchestrator.scanner, 'discover_subdomains', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.scanner, 'scan_ports', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.scanner, 'parse_sitemap_robots', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.scanner, 'recursive_spider', new_callable=AsyncMock, return_value=([], [])),
            patch.object(orchestrator.scanner, 'blind_siege', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.scanner, 'extract_js_css_links', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.scanner, 'force_fuzz', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.recon_pipeline, 'run', new_callable=AsyncMock, return_value={}),
            patch.object(orchestrator.takeover_hunter, 'run', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.nuclei_engine, 'scan', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.vision, 'capture_screenshot', new_callable=AsyncMock, return_value={}),
            patch.object(orchestrator.bounty, 'scan_for_secrets', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.reporter, 'finalize_mission', new_callable=AsyncMock, return_value=[]),
            patch.object(orchestrator.poc_engine, 'verify_all', new_callable=AsyncMock),
            patch.object(orchestrator, 'execute_exploit_chaining', new_callable=AsyncMock),
        ]
        
        for p in patches:
            p.start()
            
        try:
            domain = "test.com"
            orchestrator.scope.is_in_scope = MagicMock(return_value=True)
            
            # Run mission
            await orchestrator.execute_advanced_chain(domain)
            
            # 5. Verify Profit Engine was called
            orchestrator.profit_engine.generate_priority_report.assert_called()
            
            # 6. Verify Submitter was called due to state.AUTO_SUBMIT
            orchestrator.submitter.submit.assert_called()
            
            # 7. Verify success was logged to DB
            orchestrator.db.log_action.assert_any_call("AUTO_SUBMIT_SUCCESS", domain, "Report ID: TEST-123", None)
            
            print("\n[SUCCESS] Phase 32 Integration Verified.")
        finally:
            for p in patches:
                p.stop()

if __name__ == "__main__":
    asyncio.run(test_phase32_integration())
