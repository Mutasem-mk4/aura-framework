# AURA COMPLETE FIX PROMPT - Give this to Antigravity

---

## MISSION
Fix all remaining issues in the Aura bug bounty framework to make it fully functional on Windows and ready for bug hunting.

---

## CURRENT STATUS

### Working ✅
- Profit Engine: Working (18/18 tests pass)
- Database: Working (6,936 findings)
- Core imports: Working
- Windows console: Partially fixed (no crashes but some cleanup needed)

### Broken ❌

1. **Pytest I/O Error** - Closed file handle during test teardown on Windows
   - File: `tests/test_aura_professional.py`
   - Issue: `ValueError: I/O operation on closed file`
   - Error occurs in TestCLI and TestIntegration tests

2. **LSP Type Errors** - Multiple type annotation issues
   - `aura/core/storage.py`: 10+ LSP errors (None handling)
   - `aura/core/orchestrator.py`: 20+ LSP errors (type hints)
   - `aura/modules/profit_engine.py`: 3 LSP errors
   - `aura/modules/submitter_v2.py`: Path vs str issue

3. **Missing module exports** in `orchestrator.py`:
   - `StealthEngine.hunt_origin_ip` attribute doesn't exist
   - `state.SMART_BYPASS` not exported
   - `Never` from asyncio not handled correctly

---

## FIX TASKS

### Task 1: Fix Pytest I/O Errors
Fix the closed file handle errors in `tests/test_aura_professional.py`:

The tests `TestCLI.test_cli_import`, `TestIntegration.test_full_pipeline_imports`, and `TestIntegration.test_storage_integration` fail with:
```
ValueError: I/O operation on closed file
```

This happens during test teardown. The issue is likely from Rich console usage or subprocess cleanup. Either:
- Skip these tests on Windows, OR
- Fix the console cleanup in the test imports

### Task 2: Fix LSP Type Errors

#### aura/core/storage.py
Fix these LSP errors:
- Line 20: `Argument of type "str | None" cannot be assigned to parameter "url"`
- Line 263, 265, 282, 291: `Object of type "None" is not subscriptable`
- Line 328: `Expression of type "None" cannot be assigned to parameter of type "dict"`
- Line 454: `Expression of type "None" cannot be assigned to parameter of type "int"`
- Line 577: `Object of type "None" is not subscriptable`

Solution: Add proper None checks or use Optional type annotations.

#### aura/core/orchestrator.py
Fix these LSP errors:
- Lines 224, 208: None handling for list/str parameters
- Line 603: `hunt_origin_ip` attribute missing from StealthEngine
- Line 703: `Never` is not iterable
- Line 602: `SMART_BYPASS` not in `aura.core.state`
- Lines 565-566: Module spec handling
- Line 585: `Never` not awaitable
- Lines 1060, 1066, 1067: None handling for domain/IP parameters

Solutions:
- Add `hunt_origin_ip` attribute to StealthEngine class, OR remove usage
- Check what's in `aura/core/state.py` and fix the import
- Fix async handling for `Never` type

#### aura/modules/submitter_v2.py
- Line 111: Type "Path" not assignable to "str"
- Lines 112, 116: Cannot access .exists/.read_text on str
- Line 145: Cannot access .name on str

Solution: Fix type annotations or use pathlib correctly.

### Task 3: Fix orchestrator.py Attribute Errors

The orchestrator tries to access attributes that don't exist:
- `StealthEngine.hunt_origin_ip` - needs to be added or removed
- `state.SMART_BYPASS` - check what's in state.py and fix

---

## VERIFICATION

After fixes, run:
```bash
python -m pytest tests/test_aura_professional.py -v
python -m pytest tests/test_big_profit.py -v
python aura_main.py arc.net --auto
```

Expected: All tests pass, command runs without errors.

---

## NOTES

- Don't break existing functionality
- The profit engine tests (18 tests) currently pass - keep them passing
- The framework runs but has LSP/type issues - fix those
- Focus on making the code cleaner without breaking runtime behavior

---

*Give this prompt to Antigravity to complete all fixes.*
