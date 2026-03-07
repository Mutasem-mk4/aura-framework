"""
Aura v28.0 Phase Verification — The Siege Escalation
Tests that all three new Phase 28 engines import and initialize correctly.
"""
import asyncio

async def test_phase28():
    print("=" * 60)
    print("  🔥 Phase 28: The Siege Escalation — Verification")
    print("=" * 60)
    results = []

    # 1. Race Condition Hunter
    try:
        from aura.modules.race_condition_hunter import RaceConditionHunter
        hunter = RaceConditionHunter()
        candidates = hunter._filter_candidates([
            "https://example.com/api/coupon/apply",
            "https://example.com/about",
            "https://example.com/checkout/pay",
            "https://example.com/docs",
            "https://example.com/api/vote",
        ])
        assert len(candidates) == 3, f"Expected 3 candidates, got {len(candidates)}"
        print(f"  [✅] Race Condition Hunter: OK ({len(candidates)} candidates detected from 5 URLs)")
        results.append(True)
    except Exception as e:
        print(f"  [❌] Race Condition Hunter: FAILED — {e}")
        results.append(False)

    # 2. SSTI Engine
    try:
        from aura.modules.ssti_engine import SSTIEngine, SSTI_PROBES, SSTI_RCE_PROBES
        ssti = SSTIEngine()
        assert len(SSTI_PROBES) >= 10, "Not enough probes"
        assert "Jinja2" in SSTI_RCE_PROBES, "Missing Jinja2 RCE payloads"
        print(f"  [✅] SSTI Engine: OK ({len(SSTI_PROBES)} probes, {len(SSTI_RCE_PROBES)} engine RCE payloads)")
        results.append(True)
    except Exception as e:
        print(f"  [❌] SSTI Engine: FAILED — {e}")
        results.append(False)

    # 3. HTTP Request Smuggling Engine
    try:
        from aura.modules.smuggling_engine import SmugglingEngine
        smuggling = SmugglingEngine()
        assert hasattr(smuggling, '_probe_cl_te')
        assert hasattr(smuggling, '_probe_te_cl')
        assert hasattr(smuggling, '_probe_te_te')
        print(f"  [✅] HTTP Request Smuggling Engine: OK (CL.TE + TE.CL + TE.TE probes ready)")
        results.append(True)
    except Exception as e:
        print(f"  [❌] HTTP Request Smuggling Engine: FAILED — {e}")
        results.append(False)

    # 4. Orchestrator integration check
    try:
        from aura.core.orchestrator import RaceConditionHunter, SSTIEngine, SmugglingEngine
        print(f"  [✅] NeuralOrchestrator Integration: All 3 engines accessible from orchestrator")
        results.append(True)
    except Exception as e:
        print(f"  [❌] Orchestrator Integration: FAILED — {e}")
        results.append(False)

    print()
    passed = sum(results)
    total = len(results)
    print(f"  Result: {passed}/{total} checks passed")
    if passed == total:
        print("  🔥 Phase 28 [THE SIEGE ESCALATION]: FULLY OPERATIONAL")
    else:
        print("  ⚠️  Some checks failed — review above errors")

asyncio.run(test_phase28())
