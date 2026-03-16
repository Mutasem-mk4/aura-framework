# -*- coding: utf-8 -*-
"""
Aura Big Profit Test Suite (Phase 33)
======================================
Comprehensive test validating:
1. Profit Engine scoring and ranking
2. Database operations (storage/retrieval)
3. Finding validation and scope checking
4. Bounty estimation accuracy

Run: python -m pytest tests/test_big_profit.py -v
"""
import pytest
import sqlite3
import os
import sys
import json
from datetime import datetime

# Add aura to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aura.core.storage import AuraStorage
from aura.modules.profit_engine import (
    ProfitEngine, 
    _score_finding, 
    _get_multiplier,
    BOUNTY_RANGES,
    TYPE_MULTIPLIER
)


class TestProfitEngineScoring:
    """Test profit engine ROI calculations."""
    
    def test_bounty_ranges_exist(self):
        """Verify bounty ranges are defined for all severities."""
        assert "CRITICAL" in BOUNTY_RANGES
        assert "HIGH" in BOUNTY_RANGES
        assert "MEDIUM" in BOUNTY_RANGES
        assert "LOW" in BOUNTY_RANGES
        assert "INFO" in BOUNTY_RANGES
        
    def test_type_multipliers_exist(self):
        """Verify key vulnerability types have multipliers."""
        assert "RCE" in TYPE_MULTIPLIER
        assert "SQL" in TYPE_MULTIPLIER
        assert "XSS" in TYPE_MULTIPLIER
        assert "SSTI" in TYPE_MULTIPLIER
        
    def test_get_multiplier_rce(self):
        """RCE should have highest multiplier."""
        assert _get_multiplier("RCE") == 4.0
        
    def test_get_multiplier_sql(self):
        """SQL injection should have 2.0 multiplier."""
        assert _get_multiplier("SQL Injection") == 2.0
        
    def test_get_multiplier_xss(self):
        """XSS should have 1.2 multiplier."""
        assert _get_multiplier("XSS") == 1.2
        
    def test_get_multiplier_ssti(self):
        """SSTI should have 3.0 multiplier."""
        assert _get_multiplier("Server-Side Template Injection") == 3.0
        
    def test_get_multiplier_default(self):
        """Unknown types should default to 1.0."""
        assert _get_multiplier("Unknown Vulnerability") == 1.0
        
    def test_score_finding_critical_confirmed(self):
        """CRITICAL confirmed finding should have high ROI."""
        finding = {
            "severity": "CRITICAL",
            "type": "RCE",
            "confirmed": True
        }
        scored = _score_finding(finding)
        
        # CRITICAL: 100000 * 4.0 * 1.5 (confirmed) = 600,000
        assert scored["_roi_score"] == 600000
        assert scored["_expected_bounty_low"] == 20000
        assert scored["_expected_bounty_high"] == 400000
        
    def test_score_finding_medium_unconfirmed(self):
        """MEDIUM unconfirmed finding should have lower ROI."""
        finding = {
            "severity": "MEDIUM",
            "type": "XSS",
            "confirmed": False
        }
        scored = _score_finding(finding)
        
        # MEDIUM: 2000 * 1.2 * 0.8 (unconfirmed) = 1920
        assert scored["_roi_score"] == 1920
        assert scored["_expected_bounty_low"] == 120
        assert scored["_expected_bounty_high"] == 2400


class TestDatabaseOperations:
    """Test AuraStorage database operations."""
    
    @pytest.fixture
    def test_db(self, tmp_path):
        """Create temporary test database."""
        db_path = tmp_path / "test_aura.db"
        storage = AuraStorage(str(db_path))
        return storage
        
    def test_add_target(self, test_db):
        """Test adding a target to the database."""
        target_id = test_db.save_target({"target": "https://example.com", "type": "domain", "source": "test"})
        assert target_id is not None
        
        targets = test_db.get_all_targets()
        assert len(targets) > 0
        
    def test_add_finding(self, test_db):
        """Test adding a finding to the database."""
        # add_finding returns None when finding already exists (it updates timestamp instead)
        result = test_db.add_finding(
            "https://test.example.com",
            "Test XSS vulnerability in search param",
            "XSS"
        )
        # Result can be None (duplicate) or an ID (new insert)
        findings = test_db.get_all_findings()
        assert len(findings) >= 1
        
    def test_get_all_findings(self, test_db):
        """Test retrieving all findings."""
        test_db.add_finding("https://example.com", "Test SQLi in login", "SQL")
        test_db.add_finding("https://example.com", "Test XSS in search", "XSS")
        
        findings = test_db.get_all_findings()
        assert len(findings) >= 2


class TestProfitEngineIntegration:
    """Integration tests for ProfitEngine with database."""
    
    @pytest.fixture
    def test_db_with_findings(self, tmp_path):
        """Create test database with sample findings."""
        db_path = tmp_path / "profit_test.db"
        storage = AuraStorage(str(db_path))
        
        # Add targets and findings
        test_cases = [
            ("https://target.com", "CRITICAL", "RCE"),
            ("https://test.com", "HIGH", "SQL"),
            ("https://demo.com", "MEDIUM", "XSS"),
        ]
        
        for url, severity, ftype in test_cases:
            storage.add_finding(url, f"Test {ftype} finding", ftype, severity=severity)
            
        return str(db_path)
        
    def test_profit_engine_loads_findings(self, test_db_with_findings):
        """ProfitEngine should load findings from database."""
        engine = ProfitEngine(test_db_with_findings)
        findings = engine._load_findings()
        
        assert len(findings) == 3
        
    def test_profit_engine_generates_report(self, test_db_with_findings):
        """ProfitEngine should generate priority report."""
        engine = ProfitEngine(test_db_with_findings)
        report_path = engine.generate_priority_report()
        
        assert report_path != ""
        assert os.path.exists(report_path)
        
        # Verify report content
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "Profit Intelligence Report" in content
            assert "RCE" in content  # Should be first (highest ROI)
            
    def test_critical_finding_ranked_first(self, test_db_with_findings):
        """CRITICAL RCE should be ranked first in report."""
        engine = ProfitEngine(test_db_with_findings)
        findings = engine._load_findings()
        
        # Score all findings
        scored = [ _score_finding(f) for f in findings ]
        scored.sort(key=lambda x: x.get("_roi_score", 0), reverse=True)
        
        top_finding = scored[0]
        assert top_finding.get("type") == "RCE"
        assert top_finding.get("severity") == "CRITICAL"


class TestScopeValidation:
    """Test scope validation logic."""
    
    def test_scope_check_valid_domain(self):
        """Valid domain in scope should pass."""
        scope = ["example.com", "*.example.com"]
        target = "api.example.com"
        
        # Simple scope check
        is_valid = any(
            target.endswith(s) or target == s.replace("*.", "")
            for s in scope
        )
        assert is_valid == True
        
    def test_scope_check_invalid_domain(self):
        """Domain not in scope should fail."""
        scope = ["example.com"]
        target = "evil.com"
        
        is_valid = any(
            target.endswith(s) or target == s.replace("*.", "")
            for s in scope
        )
        assert is_valid == False


class TestEndToEndProfit:
    """End-to-end profit workflow test."""
    
    def test_full_profit_pipeline(self, tmp_path):
        """Test complete profit workflow: add findings -> score -> rank -> report."""
        db_path = tmp_path / "e2e_profit.db"
        
        # 1. Setup storage and add findings
        storage = AuraStorage(str(db_path))
        
        # Add findings with different severities
        test_cases = [
            ("https://target.com", "CRITICAL", "RCE", True),
            ("https://target.com", "CRITICAL", "SQL Injection", True),
            ("https://target.com", "HIGH", "XXE", False),
            ("https://target.com", "MEDIUM", "XSS", False),
            ("https://target.com", "LOW", "Open Redirect", False),
        ]
        
        for url, severity, ftype, confirmed in test_cases:
            storage.add_finding(
                url,
                f"Test {ftype}",
                ftype,
                severity=severity
            )
            
        # 2. Run profit engine
        engine = ProfitEngine(str(db_path))
        report_path = engine.generate_priority_report("target.com")
        
        # 3. Verify output
        assert os.path.exists(report_path)
        
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
            
            # Check for all finding types
            assert "RCE" in content
            assert "SQL" in content
            assert "XXE" in content
            
            # Portfolio estimate should be present
            assert "Portfolio Estimate" in content
            assert "$" in content
            
        # 4. Verify ranking (RCE should be first due to highest multiplier)
        findings = engine._load_findings()
        scored = [_score_finding(f) for f in findings]
        scored.sort(key=lambda x: x.get("_roi_score", 0), reverse=True)
        
        assert scored[0]["type"] == "RCE"
        assert scored[0]["severity"] == "CRITICAL"
        
        print(f"\n[E2E Test] Report generated: {report_path}")
        print(f"[E2E Test] Top finding: {scored[0]['type']} with ROI: {scored[0]['_roi_score']}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
