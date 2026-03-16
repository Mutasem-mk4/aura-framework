# AURA PROFESSIONAL FIX PLAN v1.0

## Test Results Summary

| Category | Result | Details |
|----------|--------|---------|
| **Environment** | ✅ PASS | Python 3.12.10, Windows |
| **Core Imports** | ✅ PASS | 10/10 modules load |
| **Database** | ✅ PASS | 6,936 findings, 13,678 targets |
| **API Keys** | ⚠️ PARTIAL | GEMINI set, Bounty platforms not configured |
| **Profit Engine** | ✅ PASS | Working correctly |
| **CLI Execution** | ❌ FAIL | Unicode/Windows console issues |

---

## ISSUES IDENTIFIED

### 1. CRITICAL: Windows Console Unicode Error
**Problem:** Rich library fails to print emojis/special chars on Windows cmd.exe
**Error:** `UnicodeEncodeError: 'charmap' codec can't encode character`
**Affected:** `aura_main.py`, `orchestrator.py`, `provisioner.py`, `zenith_ui.py`

### 2. HIGH: Missing Bug Bounty Platform Credentials
**Problem:** No Intigriti or HackerOne API keys configured
**Affected:** Auto-submission, bounty tracking
**Required:**
- `INTIGRITI_EMAIL`
- `INTIGRITI_PASSWORD`  
- `INTIGRITI_PROGRAM_ID`
- `H1_API_TOKEN`
- `H1_PROGRAM_HANDLE`

### 3. HIGH: Import Errors in aura_main.py
**Problem:** 
- `aura.modules.logic_fuzzer` - import not resolving
- `run_ast_audit` - function not found
**Affected:** CLI startup

### 4. MEDIUM: Type Hints / LSP Errors
**Problem:** Multiple type annotation issues in:
- `storage.py` - 10+ LSP errors
- `orchestrator.py` - 20+ LSP errors  
- `profit_engine.py` - 3 LSP errors

### 5. LOW: Pytest I/O Error on Windows
**Problem:** Closed file handle during test teardown
**Affected:** Test cleanup (non-critical)

---

## FIX PLAN

### PHASE 1: CRITICAL FIXES (Do First)

#### 1.1 Fix Windows Console Issue
**Options:**

**Option A - Run on WSL/Linux (Recommended):**
```bash
wsl -e bash -c "cd /path/to/aura && python aura_main.py arc.net"
```

**Option B - Fix Rich Console for Windows:**
Edit `aura_main.py` - already partially fixed but needs refinement:
```python
# Add at top of file BEFORE any rich imports:
import os
os.environ['TERM'] = 'dumb'
os.environ['NO_COLOR'] = '1'
```

**Option C - Use PowerShell instead of cmd.exe:**
```powershell
python aura_main.py arc.net
```

#### 1.2 Configure Bug Bounty Platform Credentials
Add to `.env`:
```bash
# Intigriti (recommended - faster response)
INTIGRITI_EMAIL=your@email.com
INTIGRITI_PASSWORD=yourpassword
INTIGRITI_PROGRAM_ID=bcny

# HackerOne (optional)
H1_API_TOKEN=your_token
H1_PROGRAM_HANDLE=bcny
```

---

### PHASE 2: HIGH PRIORITY FIXES

#### 2.1 Fix Import Errors
Check `aura_main.py` line 276 and 269:
- `logic_fuzzer` module may need to be created or imported correctly
- `run_ast_audit` function needs to be defined or removed

#### 2.2 Create logic_fuzzer Module
```python
# aura/modules/logic_fuzzer.py
def run_ast_audit(target):
    """Placeholder for AST audit functionality."""
    pass
```

---

### PHASE 3: MEDIUM PRIORITY FIXES

#### 3.1 Type Annotations (Optional but Recommended)
Fix LSP errors in:
- `aura/core/storage.py` - Add proper type hints
- `aura/core/orchestrator.py` - Add proper type hints
- `aura/modules/profit_engine.py` - Add proper type hints

---

## QUICK START (Bypass Issues)

To run Aura immediately while issues are fixed:

```bash
# 1. Use simpler command (bypasses --nexus --aggressive)
python aura_main.py arc.net

# 2. Or use CLI directly
python -m aura.cli arc.net

# 3. Or run in WSL
wsl python aura_main.py arc.net
```

---

## VERIFICATION CHECKLIST

After fixes, run:
```bash
# Core tests
python -m pytest tests/test_big_profit.py -v

# Full test suite  
python -m pytest tests/test_aura_professional.py -v

# Manual run
python aura_main.py arc.net --auto
```

Expected results:
- [ ] All tests pass
- [ ] No Unicode errors
- [ ] Database connects
- [ ] Profit engine generates report
- [ ] Credentials configured

---

## CURRENT STATUS

| Component | Status | Action Needed |
|-----------|--------|---------------|
| Profit Engine | ✅ Working | None |
| Database | ✅ 6,936 findings | None |
| GEMINI_API_KEY | ✅ Set | None |
| Intigriti/H1 | ❌ Missing | Add credentials |
| Windows Console | ❌ Broken | Use WSL or fix Rich |
| CLI | ⚠️ Partial | Fix imports |

---

*Generated: 2026-03-16*
*Test Suite: Aura Professional v1.0*
